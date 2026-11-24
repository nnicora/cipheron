package cipheron

// wave3a_test.go — ops review 2026-11-13, wave 3a: a profile sealed on the replica that answered (unseal.partial).

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nnicora/cipheron/wire/transport"
)

// TestAProfileSealedIsRetryable: CIPHERON_PROFILE_SEALED is ErrProfileSealed — a kind of ErrUnavailable (retryable),
// neither ErrBusy nor ErrNoWriter — and RetryAfter reads its RetryInfo.
func TestAProfileSealedIsRetryable(t *testing.T) {
	ctx := context.Background()
	err := mapErr(ctx, withDetailsT(t, codes.Unavailable, "the profile is sealed on this replica",
		&errdetails.ErrorInfo{Reason: transport.ReasonProfileSealed, Domain: transport.ErrorDomain},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(5 * time.Second)}))
	if !errors.Is(err, ErrProfileSealed) || !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrBusy) ||
		errors.Is(err, ErrNoWriter) {
		t.Fatalf("a sealed profile: %v", err)
	}
	if d, ok := RetryAfter(err); !ok || d != 5*time.Second {
		t.Fatalf("RetryAfter: %v %v", d, ok)
	}
	if !errors.Is(ErrProfileSealed, ErrUnavailable) || errors.Is(ErrUnavailable, ErrProfileSealed) {
		t.Fatal("ErrProfileSealed is a kind of ErrUnavailable")
	}
}
