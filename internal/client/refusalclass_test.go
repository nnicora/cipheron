package client

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nnicora/cipheron/wire/transport"
)

// TestTheRetryDecisionsAreTheRefusalTable (owner decision S34): what WithRetry sends again and what is signed again
// after the start barrier are transport.Refusal's classes and rules — the conformance kit's errorClass table — so a
// reason in another ErrorInfo domain, or on another code than cipheron answers it with, is never retried or re-signed,
// and a RetryInfo alone makes nothing retryable.
func TestTheRetryDecisionsAreTheRefusalTable(t *testing.T) {
	c := &Client{}
	for _, tc := range []struct {
		name               string
		err                error
		transient, resigns bool
		wait               time.Duration
	}{
		{"busy", refusalErr(t, codes.ResourceExhausted, transport.ErrorDomain, transport.ReasonBusy, time.Second), true, false, time.Second},
		{"busy on permission", refusalErr(t, codes.PermissionDenied, transport.ErrorDomain, transport.ReasonBusy, time.Second), false, false, 0},
		{"retry info alone", refusalErr(t, codes.ResourceExhausted, "", "", time.Second), false, false, 0},
		{"starting", refusalErr(t, codes.Unavailable, transport.ErrorDomain, transport.ReasonStarting, 250*time.Millisecond), true, true,
			250 * time.Millisecond},
		{"starting of another domain", refusalErr(t, codes.Unavailable, "proxy.example", transport.ReasonStarting, time.Millisecond),
			false, false, 0},
		{"starting on invalid", refusalErr(t, codes.InvalidArgument, transport.ErrorDomain, transport.ReasonStarting, 0), false, false, 0},
		{"sealed", refusalErr(t, codes.Unavailable, transport.ErrorDomain, transport.ReasonProfileSealed, 5*time.Second), true, false,
			5 * time.Second},
		{"connection lost", refusalErr(t, codes.Unavailable, "", "", 0), true, false, 0},
		{"unknown reason", refusalErr(t, codes.Unavailable, transport.ErrorDomain, "CIPHERON_SOMETHING", 0), false, false, 0},
		{"not a status", errors.New("cipheron: something"), false, false, 0},
	} {
		wait, transient := c.transient(tc.err)
		_, resigns := startingWait(tc.err)
		if transient != tc.transient || resigns != tc.resigns || transient && wait != tc.wait {
			t.Errorf("%s: transient %v (%s), re-signed %v; want %v (%s), %v", tc.name, transient, wait, resigns, tc.transient,
				tc.wait, tc.resigns)
		}
	}
}

// refusalErr is a refusal of code with an ErrorInfo of domain and reason (none when both are empty) and a RetryInfo of
// delay (none when 0).
func refusalErr(t *testing.T, code codes.Code, domain, reason string, delay time.Duration) error {
	t.Helper()
	st := status.New(code, "refused")
	var err error
	if domain != "" || reason != "" {
		if st, err = st.WithDetails(&errdetails.ErrorInfo{Domain: domain, Reason: reason}); err != nil {
			t.Fatal(err)
		}
	}
	if delay > 0 {
		if st, err = st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(delay)}); err != nil {
			t.Fatal(err)
		}
	}
	return st.Err()
}
