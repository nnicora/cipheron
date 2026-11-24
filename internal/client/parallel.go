package client

// parallel.go — a batch's per-item work on this side (sealing each item to cipheron, opening each plaintext cipheron
// sealed back) on a bounded pool, with the outcome of the sequential loop: the error of the FIRST failing item in
// index order, and every result at its own index.

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// maxItemWorkers is the most goroutines one batch's items run on (min with GOMAXPROCS).
const maxItemWorkers = 8

// eachItem runs f(i) for every i in [0, n) on at most min(GOMAXPROCS, maxItemWorkers) goroutines (the caller's one
// of them) and returns the error of the lowest index that failed — what the loop `for i { if err := f(i) … return
// err }` returns: an item after a failed one is not started (some already running beside it finish, their results
// are the caller's to discard). A panic in f is raised again on the caller's goroutine.
func eachItem(n int, f func(i int) error) error {
	workers := max(1, min(runtime.GOMAXPROCS(0), maxItemWorkers, n))
	if workers == 1 {
		for i := range n {
			if err := f(i); err != nil {
				return err
			}
		}
		return nil
	}
	errs := make([]error, n)
	var next atomic.Int64
	var bound atomic.Int64 // items after bound are not started: the lowest index that failed
	bound.Store(int64(n))
	var panicked atomic.Pointer[any]
	run := func() {
		defer func() {
			if p := recover(); p != nil {
				panicked.CompareAndSwap(nil, &p)
				bound.Store(-1)
			}
		}()
		for {
			i := int(next.Add(1) - 1)
			if i >= n || int64(i) > bound.Load() {
				return
			}
			if err := f(i); err != nil {
				errs[i] = err
				for b := bound.Load(); int64(i) < b && !bound.CompareAndSwap(b, int64(i)); b = bound.Load() {
				}
			}
		}
	}
	var wg sync.WaitGroup
	for range workers - 1 {
		wg.Go(run)
	}
	run()
	wg.Wait()
	if p := panicked.Load(); p != nil {
		panic(*p)
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
