package cipheron

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// expiredCtx is a context whose deadline has passed and whose timer has not fired yet: Err is still nil. gRPC ends a
// call on a timer of its own at the same deadline, so its DEADLINE_EXCEEDED can be answered in exactly this state.
type expiredCtx struct{ context.Context }

func (expiredCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }
func (expiredCtx) Err() error                  { return nil }

// TestTheCallersDeadlineIsBareBeforeItsTimerFires: a call whose deadline passed is the caller's deadline whichever
// timer fired first — mapErr answers context.DeadlineExceeded, bare (Example_errors' "deadline: true"), not a
// deadline of gRPC's or the server's. A deadline still ahead keeps the server's answer.
func TestTheCallersDeadlineIsBareBeforeItsTimerFires(t *testing.T) {
	ctx := expiredCtx{context.Background()}
	for _, err := range []error{
		status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
		errors.New("connection error: context deadline exceeded"),
	} {
		if got := mapErr(ctx, err); got != context.DeadlineExceeded { //nolint:errorlint // bare: identity is the contract
			t.Errorf("%v: mapErr = %v (%T), want context.DeadlineExceeded, bare", err, got, got)
		}
	}

	ahead, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	got := mapErr(ahead, status.Error(codes.DeadlineExceeded, "the server's own deadline"))
	if got == context.DeadlineExceeded || !errors.Is(got, context.DeadlineExceeded) { //nolint:errorlint // identity is the point
		t.Errorf("a server's deadline with the caller's ahead: %v (%T), want it wrapped, not bare", got, got)
	}
}
