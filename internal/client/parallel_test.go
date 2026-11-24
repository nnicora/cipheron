package client

// parallel_test.go — Wave D (deep review 2026-11-12, P13): a batch's items sealed and opened on a bounded pool, and
// an object's or a stream's batches pipelined, with the outcome of one after the other: the first error in index
// (or stream) order, every result in its place, what is not returned wiped, nothing left running.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/wire/transport"
)

func jitter() { time.Sleep(time.Duration(rand.IntN(300)) * time.Microsecond) }

func TestEachItemReturnsTheFirstErrorInIndexOrder(t *testing.T) {
	old := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(old)
	var mu sync.Mutex
	var started []int
	err := eachItem(100, func(i int) error {
		mu.Lock()
		started = append(started, i)
		mu.Unlock()
		switch i {
		case 10:
			time.Sleep(5 * time.Millisecond) // the lower index fails LAST
			return errors.New("item 10")
		case 12:
			return errors.New("item 12")
		}
		jitter()
		return nil
	})
	if err == nil || err.Error() != "item 10" {
		t.Fatalf("eachItem: %v; want the lowest index's error", err)
	}
	for _, i := range started {
		if i > 12+maxItemWorkers*8 {
			t.Fatalf("item %d started long after item 12 failed: %v", i, started)
		}
	}
	// Every item, in order, without failures; and sequentially with one processor.
	for _, procs := range []int{1, 8} {
		runtime.GOMAXPROCS(procs)
		out := make([]int, 50)
		if err := eachItem(50, func(i int) error { jitter(); out[i] = i + 1; return nil }); err != nil {
			t.Fatal(err)
		}
		for i, v := range out {
			if v != i+1 {
				t.Fatalf("GOMAXPROCS %d: item %d = %d", procs, i, v)
			}
		}
	}
}

func TestEachItemRaisesAPanicOnTheCaller(t *testing.T) {
	old := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(old)
	defer func() {
		if p := recover(); p != "boom" {
			t.Fatalf("recovered %v", p)
		}
	}()
	_ = eachItem(32, func(i int) error {
		if i == 20 {
			panic("boom")
		}
		return nil
	})
	t.Fatal("eachItem returned after a panic")
}

// TestPipelinedFinishesInOrder: jobs that complete out of order are finished in the order produced; a read error
// stops producing, the jobs before it are finished, then it is returned; a finish error ends at once, every job in
// flight discarded, nothing left running.
func TestPipelinedFinishesInOrder(t *testing.T) {
	ctx := context.Background()
	var inFlight, most atomic.Int64
	run := func(k int) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
			}
			select {
			case <-time.After(time.Duration(rand.IntN(2000)) * time.Microsecond):
			case <-ctx.Done():
				return -1, ctx.Err()
			}
			return k, nil
		}
	}
	// In order, at most pipelineDepth at once.
	k := 0
	var got []int
	err := pipelined(ctx, func() (func(context.Context) (int, error), error) {
		if k == 30 {
			return nil, nil //nolint:nilnil // pipelined's contract: a nil job is the end of the source
		}
		k++
		return run(k - 1), nil
	}, func(v int, err error) error {
		got = append(got, v)
		return err
	}, func(int) { t.Error("nothing is discarded") })
	if err != nil || len(got) != 30 || !slices.IsSorted(got) || most.Load() > pipelineDepth || most.Load() < 2 {
		t.Fatalf("err %v, finished %v, %d at once", err, got, most.Load())
	}
	// A read error at job 10: jobs 0..9 finished, then the error.
	k, got = 0, nil
	readErr := errors.New("read")
	err = pipelined(ctx, func() (func(context.Context) (int, error), error) {
		if k == 10 {
			return nil, readErr
		}
		k++
		return run(k - 1), nil
	}, func(v int, err error) error { got = append(got, v); return err }, func(int) { t.Error("nothing is discarded") })
	if !errors.Is(err, readErr) || len(got) != 10 || !slices.IsSorted(got) {
		t.Fatalf("a read error: %v, finished %v", err, got)
	}
	// A finish error at job 5: returned at once; jobs after it discarded, none finished.
	k, got = 0, nil
	var discarded atomic.Int64
	finishErr := errors.New("finish")
	err = pipelined(ctx, func() (func(context.Context) (int, error), error) {
		if k == 30 {
			return nil, nil //nolint:nilnil // pipelined's contract: a nil job is the end of the source
		}
		k++
		return run(k - 1), nil
	}, func(v int, err error) error {
		got = append(got, v)
		if v == 5 {
			return finishErr
		}
		return err
	}, func(int) { discarded.Add(1) })
	if !errors.Is(err, finishErr) || !slices.Equal(got, []int{0, 1, 2, 3, 4, 5}) || discarded.Load() > pipelineDepth-1 ||
		inFlight.Load() != 0 || k > 5+pipelineDepth {
		t.Fatalf("a finish error: %v, finished %v, %d discarded, %d running, %d produced", err, got, discarded.Load(),
			inFlight.Load(), k)
	}
}

// fakeSeal and fakeOpen stand for cipheron in the object and stream tests: a "ciphertext" is the item's associated
// data's length, the data XOR 0x5a, and the associated data — opened only with the same associated data.
func fakeSeal(it BatchItem) []byte {
	out := binary32(len(it.AssociatedData))
	out = append(out, it.AssociatedData...)
	for _, b := range it.Data {
		out = append(out, b^0x5a)
	}
	return out
}

func binary32(n int) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }

func fakeOpen(it BatchItem) ([]byte, error) {
	c := it.Data
	if len(c) < 4 {
		return nil, status.Error(codes.InvalidArgument, "malformed")
	}
	n := int(c[0])<<24 | int(c[1])<<16 | int(c[2])<<8 | int(c[3])
	if len(c) < 4+n || !bytes.Equal(c[4:4+n], it.AssociatedData) {
		return nil, status.Error(codes.InvalidArgument, "the associated data does not match")
	}
	out := make([]byte, 0, len(c)-4-n)
	for _, b := range c[4+n:] {
		out = append(out, b^0x5a)
	}
	return out, nil
}

// TestStreamsAndObjectsArePipelinedInOrder: an object encrypted and decrypted through batches that answer out of
// order (random delays) comes back whole, the same through the stream calls and the object calls, with up to
// pipelineDepth batches in flight; a segment that does not open fails at its own index with ErrSegmented, after
// exactly the segments before it were written; a refusal of the batch limits is adopted and the rest sent again
// in smaller batches.
func TestStreamsAndObjectsArePipelinedInOrder(t *testing.T) {
	ctx := context.Background()
	c := &Client{maxMessage: DefaultMaxMessageBytes}
	var inFlight, most, calls atomic.Int64
	slow := func() {
		n := inFlight.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		time.Sleep(time.Duration(rand.IntN(3000)) * time.Microsecond)
		inFlight.Add(-1)
	}
	enc := func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		calls.Add(1)
		slow()
		out := make([]BatchResult, len(items))
		for i, it := range items {
			out[i].Value = fakeSeal(it)
		}
		return out, nil
	}
	var corruptAt atomic.Int64
	corruptAt.Store(-1)
	dec := func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		calls.Add(1)
		slow()
		out := make([]BatchResult, len(items))
		for i, it := range items {
			out[i].Value, out[i].Err = fakeOpen(it)
		}
		return out, nil
	}
	plain := make([]byte, 3<<20+12345) // 3 MiB and a bit, in 16 KiB segments: about 200 segments, 5 batches
	for i := range plain {
		plain[i] = byte(i * 7)
	}
	co := callOptions{segment: 16 << 10, aad: []byte("row 1")}
	var obj bytes.Buffer
	n, err := c.encryptStream(ctx, &obj, bytes.NewReader(plain), int64(len(plain)), co, enc)
	if err != nil || n != int64(obj.Len()) {
		t.Fatalf("encryptStream: %d %v", n, err)
	}
	if most.Load() < 2 || most.Load() > pipelineDepth {
		t.Fatalf("%d batches in flight at once; want 2 to %d", most.Load(), pipelineDepth)
	}
	whole, err := c.encryptObject(ctx, plain, co, enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(whole) != obj.Len() {
		t.Fatalf("the object call and the stream call make objects of %d and %d bytes", len(whole), obj.Len())
	}
	var back bytes.Buffer
	if _, err := c.decryptStream(ctx, &back, bytes.NewReader(obj.Bytes()), co, dec); err != nil || !bytes.Equal(back.Bytes(), plain) {
		t.Fatalf("decryptStream: %v (%d bytes back)", err, back.Len())
	}
	if pt, err := c.decryptObject(ctx, whole, co, dec); err != nil || !bytes.Equal(pt, plain) {
		t.Fatalf("decryptObject: %v", err)
	}
	if pt, err := c.decryptObject(ctx, obj.Bytes(), co, dec); err != nil || !bytes.Equal(pt, plain) {
		t.Fatalf("decryptObject of the stream's object: %v", err)
	}

	// A segment tampered with: the error names it, and exactly the groups before its own were written (a group is
	// written only once every segment of it opened, as before).
	h, segs, err := transport.ParseSegmented(transport.Release(), whole)
	if err != nil {
		t.Fatal(err)
	}
	const bad = 137
	segs[bad] = slices.Clone(segs[bad])
	segs[bad][4] ^= 1 // its associated data
	tampered, err := transport.MarshalSegmented(transport.Release(), h, segs)
	if err != nil {
		t.Fatal(err)
	}
	back.Reset()
	_, err = c.decryptStream(ctx, &back, bytes.NewReader(tampered), co, dec)
	if !errors.Is(err, transport.ErrSegmented) || !bytes.Contains([]byte(err.Error()), fmt.Appendf(nil, "segment %d:", bad)) {
		t.Fatalf("a tampered segment: %v", err)
	}
	group := c.streamGroup(int(h.SegmentSize), len(co.aad))
	if want := bad / group * group * int(h.SegmentSize); back.Len() != want || !bytes.Equal(back.Bytes(), plain[:want]) {
		t.Fatalf("%d bytes written before the tampered segment %d; want %d (the groups of %d before its own)",
			back.Len(), bad, want, group)
	}
	if _, err := c.decryptObject(ctx, tampered, co, dec); !errors.Is(err, transport.ErrSegmented) {
		t.Fatalf("decryptObject of a tampered object: %v", err)
	}

	// A stream shorter than its size: the error once the segments before were written.
	obj.Reset()
	if _, err := c.encryptStream(ctx, &obj, bytes.NewReader(plain[:1<<20]), int64(len(plain)), co, enc); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a short stream: %v", err)
	}

	// The batch limits refused once (cipheron's limits are smaller than the client's defaults): adopted, every item
	// sent again in smaller batches, the result the same.
	var refused atomic.Bool
	limited := func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		if len(items) > 4 {
			refused.Store(true)
			st, _ := status.New(codes.InvalidArgument, "over the limits").WithDetails(&errdetails.ErrorInfo{
				Reason: transport.ReasonBatchLimit, Domain: transport.ErrorDomain,
				Metadata: map[string]string{"maxItems": "4", "maxBytes": "1048576"}})
			return nil, st.Err()
		}
		return enc(ctx, items)
	}
	small, err := c.encryptObject(ctx, plain, co, limited)
	if err != nil || !refused.Load() {
		t.Fatalf("under smaller limits: %v (refused %v)", err, refused.Load())
	}
	if pt, err := c.decryptObject(ctx, small, co, dec); err != nil || !bytes.Equal(pt, plain) {
		t.Fatalf("the object made under smaller limits: %v", err)
	}
	if inFlight.Load() != 0 {
		t.Fatalf("%d batches still running", inFlight.Load())
	}
}
