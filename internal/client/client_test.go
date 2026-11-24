package client

// These are the pieces that need no server. trust_test.go and package cipheron's tests run the client against a
// fake cipheron (cipherontest); the round trips against the real one are the server's.

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/wire/transport"
)

// TestHTTPErrorsBecomeTheGatewaysStatus: over HTTP the client fails with the same gRPC status as over gRPC.
func TestHTTPErrorsBecomeTheGatewaysStatus(t *testing.T) {
	err := httpStatus(http.StatusForbidden, []byte(`{"code":7,"message":"permission denied","details":[]}`))
	if status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "permission denied" {
		t.Fatalf("gateway body: %v", err)
	}
	err = httpStatus(http.StatusBadRequest, []byte(`{"code":3,"message":"the ciphertext could not be decrypted"}`))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("INVALID_ARGUMENT over HTTP 400: %v", err)
	}
	// Busy: the gateway's RetryInfo detail survives, and a bare 429 gets one.
	for _, body := range []string{
		`{"code":8,"message":"busy","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1s"}]}`,
		"not json",
	} {
		st := status.Convert(httpStatus(http.StatusTooManyRequests, []byte(body)))
		if st.Code() != codes.ResourceExhausted || len(st.Details()) != 1 {
			t.Fatalf("HTTP 429 with %s: %v %v", body, st.Code(), st.Details())
		}
		if _, ok := st.Details()[0].(*errdetails.RetryInfo); !ok {
			t.Fatalf("HTTP 429 with %s: %T", body, st.Details()[0])
		}
	}
	// The machine-readable reason survives too: the ErrorInfo the gateway writes into its JSON status.
	ki := status.Convert(httpStatus(http.StatusBadRequest, []byte(`{"code":3,"message":"the key version of this ciphertext is not available",`+
		`"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"`+transport.ReasonKeyVersionUnavailable+
		`","domain":"`+transport.ErrorDomain+`"}]}`)))
	if ki.Code() != codes.InvalidArgument || len(ki.Details()) != 1 {
		t.Fatalf("an ErrorInfo over HTTP 400: %v %v", ki.Code(), ki.Details())
	}
	if ei, ok := ki.Details()[0].(*errdetails.ErrorInfo); !ok || ei.GetReason() != transport.ReasonKeyVersionUnavailable ||
		ei.GetDomain() != transport.ErrorDomain {
		t.Fatalf("an ErrorInfo over HTTP 400: %v", ki.Details()[0])
	}
	for httpCode, want := range map[int]codes.Code{
		http.StatusForbidden:             codes.PermissionDenied,
		http.StatusBadRequest:            codes.InvalidArgument,
		http.StatusRequestEntityTooLarge: codes.ResourceExhausted,
		http.StatusServiceUnavailable:    codes.Unavailable,
		http.StatusTeapot:                codes.Unknown,
	} {
		if got := status.Code(httpStatus(httpCode, []byte("not json"))); got != want {
			t.Errorf("HTTP %d without a body: %v, want %v", httpCode, got, want)
		}
	}
}

func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte("m"))
	if !Verify(pub, []byte("m"), sig) || Verify(pub, []byte("n"), sig) || Verify(pub[:31], []byte("m"), sig) {
		t.Fatal("Verify")
	}
}
