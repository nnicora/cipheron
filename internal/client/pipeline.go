package client

// pipeline.go — up to pipelineDepth batches of one object or stream in flight at once, their answers taken in the
// order they were sent: the object's segments are written, checked and failed exactly as one batch after the other
// would have them, only sooner.
//
// Memory: what is in flight is at most pipelineDepth batches — each at most objectBatchBytes of payload (three
// quarters of cipheron's default batch.maxBytes: 768 KiB), held as the items, the request and the answer — so a
// stream holds about pipelineDepth × 3 × 768 KiB ≈ 7 MiB at the defaults, and never more than pipelineDepth batches
// whatever the object's size.

import (
	"context"
	"errors"
)

// pipelineDepth is how many batches of one object or stream are in flight at once.
const pipelineDepth = 3

// errRestart is a finish's answer that everything in flight is to be dropped and the jobs produced again from
// where next now stands (inBatches, after adopting cipheron's batch limits).
var errRestart = errors.New("cipheron: restart the pipeline")

// stage is one job in flight.
type stage[T any] struct {
	done     chan struct{}
	val      T
	err      error
	cancel   context.CancelFunc
	panicked *any
}

// pipelined runs jobs, up to pipelineDepth at once, in the order next produces them, and hands each one's outcome
// to finish in that order.
//
//   - next produces the next job (nil: there are no more) or an error (a read of the source failed): no job is
//     produced after it, the jobs in flight are finished in order, and the error is returned unless a finish failed
//     first — what the sequential loop returned in the same case.
//   - finish takes a job's value and error; an error ends the pipeline with it (the jobs still in flight are
//     cancelled, waited for and discarded), errRestart drops everything in flight and goes on producing.
//   - discard is given the value of every job dropped unfinished (a decryption's plaintexts are wiped there).
//
// A panic in a job is raised again here, on the caller's goroutine. Nothing is left running when it returns.
func pipelined[T any](ctx context.Context, next func() (func(context.Context) (T, error), error),
	finish func(T, error) error, discard func(T),
) error {
	var queue []*stage[T]
	drop := func() {
		for _, s := range queue {
			s.cancel()
		}
		for _, s := range queue {
			<-s.done
			if s.panicked == nil {
				discard(s.val)
			}
		}
		queue = queue[:0]
	}
	defer drop()
	var readErr error
	more := true
	for {
		for more && readErr == nil && len(queue) < pipelineDepth {
			run, err := next()
			if err != nil {
				readErr = err
				break
			}
			if run == nil {
				more = false
				break
			}
			sctx, cancel := context.WithCancel(ctx)
			s := &stage[T]{done: make(chan struct{}), cancel: cancel}
			go func() {
				defer close(s.done)
				defer func() {
					if p := recover(); p != nil {
						s.panicked = &p
					}
				}()
				s.val, s.err = run(sctx)
			}()
			queue = append(queue, s)
		}
		if len(queue) == 0 {
			return readErr
		}
		s := queue[0]
		queue = queue[1:]
		<-s.done
		s.cancel()
		if s.panicked != nil {
			panic(*s.panicked)
		}
		switch err := finish(s.val, s.err); {
		case errors.Is(err, errRestart):
			drop()
			more = true
		case err != nil:
			return err
		}
	}
}
