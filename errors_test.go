package cipheron

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nnicora/cipheron/internal/client"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestMapErr pins how a wire error becomes this package's: each status code to its sentinel, cipheron's
// message kept, the client's own sentinels kept as they are, an answer cipheron gave winning over a context
// that ended at the same moment, and a context that ended winning over everything else.
func withDetailsT(t *testing.T, code codes.Code, msg string, details ...protoadapt.MessageV1) error {
	t.Helper()
	st, err := status.New(code, msg).WithDetails(details...)
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

func TestMapErr(t *testing.T) {
	ctx := context.Background()
	for code, want := range map[codes.Code]error{
		codes.PermissionDenied: ErrPermissionDenied,
		codes.InvalidArgument:  ErrInvalidInput,
		// RESOURCE_EXHAUSTED that is neither cipheron's busy nor gRPC's size refusal: unavailable, not too large.
		codes.ResourceExhausted: ErrUnavailable,
		codes.Unavailable:       ErrUnavailable,
		codes.Unimplemented:     ErrUnsupported,
		codes.Internal:          ErrInternal,
		codes.DeadlineExceeded:  context.DeadlineExceeded,
		codes.Canceled:          context.Canceled,
	} {
		wire := status.Error(code, "the message")
		err := mapErr(ctx, wire)
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "the message") {
			t.Errorf("%v: %v, want %v carrying the message", code, err, want)
		}
		// The answer itself stays in the chain: its code, and the very error.
		if status.Code(err) != code || !errors.Is(err, wire) {
			t.Errorf("%v: the answer is not in the chain of %v (code %v)", code, err, status.Code(err))
		}
	}
	// gRPC's own refusal of a message over a limit — no details, its wording — is the one RESOURCE_EXHAUSTED that is
	// too large (the exact messages of the vendored grpc-go: rpc_util.go, stream.go, server.go).
	for _, msg := range []string{
		"grpc: received message larger than max (5000 vs. 4096)",
		"trying to send message larger than max (5000 vs. 4096)",
		"grpc: trying to send message larger than max (5000 vs. 4096)",
		"grpc: received message after decompression larger than max 4096",
		"grpc: message after decompression larger than max (5000 vs. 4096)",
		"grpc: message too large (5000000000 bytes)",
	} {
		if err := mapErr(ctx, status.Error(codes.ResourceExhausted, msg)); !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrUnavailable) {
			t.Errorf("%q: %v, want ErrTooLarge", msg, err)
		}
	}
	// With details it is not gRPC's (gRPC's has none), whatever the message says; and on another code the wording
	// means nothing.
	if err := mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "grpc: received message larger than max (5 vs. 4)",
		&errdetails.ErrorInfo{Reason: "OTHER", Domain: "other"})); errors.Is(err, ErrTooLarge) || !errors.Is(err, ErrUnavailable) {
		t.Errorf("a size wording with details: %v, want ErrUnavailable", err)
	}
	if err := mapErr(ctx, status.Error(codes.InvalidArgument, "grpc: received message larger than max (5 vs. 4)")); errors.Is(err, ErrTooLarge) {
		t.Errorf("the size wording on INVALID_ARGUMENT: %v", err)
	}
	// RESOURCE_EXHAUSTED with a RetryInfo, or with cipheron's busy reason, is cipheron at a limit: unavailable,
	// not too large.
	withDetails := func(code codes.Code, msg string, details ...protoadapt.MessageV1) error {
		st, err := status.New(code, msg).WithDetails(details...)
		if err != nil {
			t.Fatal(err)
		}
		return st.Err()
	}
	reason := func(r string) *errdetails.ErrorInfo {
		return &errdetails.ErrorInfo{Reason: r, Domain: transport.ErrorDomain}
	}
	for name, busy := range map[string]error{
		"RetryInfo":            withDetails(codes.ResourceExhausted, "busy", &errdetails.RetryInfo{RetryDelay: durationpb.New(time.Second)}),
		"the reason":           withDetails(codes.ResourceExhausted, "busy", reason(transport.ReasonBusy)),
		"the reason+RetryInfo": withDetails(codes.ResourceExhausted, "busy", reason(transport.ReasonBusy), &errdetails.RetryInfo{RetryDelay: durationpb.New(time.Second)}),
	} {
		if err := mapErr(ctx, busy); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTooLarge) {
			t.Errorf("busy (%s): %v, want ErrUnavailable", name, err)
		}
	}
	// INVALID_ARGUMENT with cipheron's key-version reason is not corruption: its own sentinel, not ErrInvalidInput,
	// whatever the message says (it is kept, for humans).
	for _, msg := range []string{"the key version of this ciphertext is not available", "the key version of this tenant key is not available",
		"reworded"} {
		err := mapErr(ctx, withDetails(codes.InvalidArgument, msg, reason(transport.ReasonKeyVersionUnavailable)))
		if !errors.Is(err, ErrKeyVersionUnavailable) || errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: %v, want ErrKeyVersionUnavailable", msg, err)
		}
	}
	// The message is never matched; a reason of another domain, or another reason, is not cipheron's.
	for name, err := range map[string]error{
		"the message alone":        status.Error(codes.InvalidArgument, "the key version of this ciphertext is not available"),
		"another ErrorInfo domain": withDetails(codes.InvalidArgument, "x", &errdetails.ErrorInfo{Reason: transport.ReasonKeyVersionUnavailable, Domain: "other"}),
		"another reason":           withDetails(codes.InvalidArgument, "x", reason(transport.ReasonBusy)),
		"not decrypted":            status.Error(codes.InvalidArgument, "the ciphertext could not be decrypted"),
	} {
		if err := mapErr(ctx, err); !errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrKeyVersionUnavailable) {
			t.Errorf("%s: %v, want ErrInvalidInput", name, err)
		}
	}
	// The key-version reason on another code is not the key-version refusal either — nor a size refusal: with
	// details it is not gRPC's own.
	if err := mapErr(ctx, withDetails(codes.ResourceExhausted, "x", reason(transport.ReasonKeyVersionUnavailable))); !errors.Is(err, ErrUnavailable) ||
		errors.Is(err, ErrKeyVersionUnavailable) || errors.Is(err, ErrTooLarge) || errors.Is(err, ErrBusy) {
		t.Errorf("the key-version reason on RESOURCE_EXHAUSTED: %v", err)
	}
	// What the library refuses itself before sending: not a ciphertext, a blob that is not the tenant's.
	for _, own := range []error{transport.ErrCiphertext, ErrTenantKey} {
		if err := mapErr(ctx, fmt.Errorf("the reason: %w", own)); !errors.Is(err, ErrInvalidInput) || !errors.Is(err, own) {
			t.Errorf("%v: %v, want ErrInvalidInput", own, err)
		}
	}
	if err := mapErr(ctx, status.Error(codes.Internal, "boom")); err == nil ||
		errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "boom") {
		t.Errorf("an internal error: %v", err)
	}
	plain := errors.New("not a status")
	if err := mapErr(ctx, plain); !errors.Is(err, plain) {
		t.Errorf("a non-status error lost its cause: %v", err)
	}
	if mapErr(ctx, nil) != nil {
		t.Error("no error became one")
	}
	for _, own := range []error{ErrServerIdentity, ErrServerKeyChanged, ErrBadResponse, ErrTooLarge, ErrTenancy, ErrClosed, ErrPinRequired} {
		wrapped := fmt.Errorf("%w: the reason", own)
		if err := mapErr(ctx, wrapped); err != wrapped { //nolint:errorlint // identity is the assertion
			t.Errorf("the client's own %v became %v", own, err)
		}
	}
	// An identity failure or a malformed answer whose cause names an input layout — a forged key statement in a key
	// fetch is ErrKeyStatement too — is the party's, never the caller's invalid input.
	for _, own := range []error{ErrServerIdentity, ErrServerKeyChanged, ErrPinRequired, ErrContextDigest, ErrBadResponse} {
		for _, input := range []error{ErrKeyStatement, ErrTenantKey, transport.ErrCiphertext, ErrAssociatedData, ErrSegmented,
			ErrJSONField} {
			wrapped := fmt.Errorf("%w: the answer: %w", own, input)
			if err := mapErr(ctx, wrapped); err != wrapped || errors.Is(err, ErrInvalidInput) { //nolint:errorlint // identity is the assertion
				t.Errorf("%v wrapping %v became %v", own, input, err)
			}
		}
	}

	done, cancel := context.WithCancel(ctx)
	cancel()
	// The status is looked at first: an answer is an answer, whatever the context did meanwhile.
	if err := mapErr(done, status.Error(codes.PermissionDenied, "x")); !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("a refusal that arrived as the context ended: %v", err)
	}
	if err := mapErr(done, status.Error(codes.Canceled, "x")); err != context.Canceled { //nolint:errorlint // identity is the assertion
		t.Errorf("a cancelled call: %v", err)
	}
	if err := mapErr(done, plain); err != context.Canceled { //nolint:errorlint // identity is the assertion
		t.Errorf("a cancelled call with a local error: %v", err)
	}
	if err := mapErr(done, fmt.Errorf("%w: uid", ErrServerIdentity)); !errors.Is(err, ErrServerIdentity) ||
		errors.Is(err, context.Canceled) {
		t.Errorf("an identity refusal became a context error: %v", err)
	}
}

// TestMapErrKeepsTheAnswer (finding A): an error made from an answer still carries the answer — its gRPC status
// with the details, and whatever the protocol client's error was (a refused certificate) — behind the package's
// value; the kinds hold together (busy and no-writer are unavailable, a refused certificate is permission
// denied); RetryAfter reads cipheron's delay; and the message every mapped value has always shown is unchanged.
func TestMapErrKeepsTheAnswer(t *testing.T) {
	ctx := context.Background()
	info := func(r string) *errdetails.ErrorInfo {
		return &errdetails.ErrorInfo{Reason: r, Domain: transport.ErrorDomain}
	}
	retry := func(d time.Duration) *errdetails.RetryInfo {
		return &errdetails.RetryInfo{RetryDelay: durationpb.New(d)}
	}

	// The kinds are kinds by themselves, not only on a mapped error.
	if !errors.Is(ErrBusy, ErrUnavailable) || !errors.Is(ErrNoWriter, ErrUnavailable) || errors.Is(ErrBusy, ErrNoWriter) ||
		errors.Is(ErrUnavailable, ErrBusy) {
		t.Fatal("ErrBusy and ErrNoWriter are kinds of ErrUnavailable, and not of each other")
	}
	if ErrCertificateRefused != client.ErrCertificateRefused || ErrUnknownSigningKey != client.ErrUnknownSigningKey || //nolint:errorlint // identity is the assertion
		ErrClosed != client.ErrClosed { //nolint:errorlint // identity is the assertion
		t.Fatal("the re-exported values are the protocol client's own")
	}

	// Busy: by cipheron's reason, with its delay.
	busy := mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "too many requests in flight", info(transport.ReasonBusy), retry(1500*time.Millisecond)))
	if !errors.Is(busy, ErrBusy) || !errors.Is(busy, ErrUnavailable) || errors.Is(busy, ErrTooLarge) || errors.Is(busy, ErrNoWriter) {
		t.Fatalf("busy: %v", busy)
	}
	if d, ok := RetryAfter(busy); !ok || d != 1500*time.Millisecond {
		t.Fatalf("RetryAfter(busy) = %v, %v; want 1.5s", d, ok)
	}
	if busy.Error() != "cipheron: unavailable: too many requests in flight" {
		t.Fatalf("the busy message changed: %q", busy)
	}
	st, ok := status.FromError(busy)
	if !ok || st.Code() != codes.ResourceExhausted || !hasReason(st, transport.ReasonBusy) {
		t.Fatalf("the busy status is not readable from the mapped error: %v %v", st, ok)
	}
	// A RetryInfo alone is busy too (an HTTP 429 without a readable body); a reason of another domain is not.
	if err := mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "x", retry(time.Second))); !errors.Is(err, ErrBusy) {
		t.Fatalf("RESOURCE_EXHAUSTED with a RetryInfo: %v", err)
	}
	if err := mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "x", &errdetails.ErrorInfo{Reason: transport.ReasonBusy, Domain: "other"})); errors.Is(err, ErrBusy) ||
		!errors.Is(err, ErrUnavailable) {
		t.Fatalf("the busy reason of another domain: %v", err)
	}
	// The busy reason on UNAVAILABLE is not ErrBusy (cipheron answers busy as RESOURCE_EXHAUSTED only).
	if err := mapErr(ctx, withDetailsT(t, codes.Unavailable, "x", info(transport.ReasonBusy))); errors.Is(err, ErrBusy) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the busy reason on UNAVAILABLE: %v", err)
	}

	// No writer.
	nw := mapErr(ctx, withDetailsT(t, codes.Unavailable, "no master key version writes now", info(transport.ReasonNoWriter)))
	if !errors.Is(nw, ErrNoWriter) || !errors.Is(nw, ErrUnavailable) || errors.Is(nw, ErrBusy) || status.Code(nw) != codes.Unavailable {
		t.Fatalf("no writer: %v", nw)
	}
	if _, ok := RetryAfter(nw); ok {
		t.Fatal("a no-writer answer carries no delay")
	}
	if nw.Error() != "cipheron: unavailable: no master key version writes now" {
		t.Fatalf("the no-writer message changed: %q", nw)
	}
	if err := mapErr(ctx, status.Error(codes.Unavailable, "shutting down")); errors.Is(err, ErrNoWriter) || errors.Is(err, ErrBusy) ||
		err.Error() != "cipheron: unavailable: shutting down" {
		t.Fatalf("a plain UNAVAILABLE: %v", err)
	}
	// The no-writer reason on RESOURCE_EXHAUSTED is neither.
	if err := mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "x", info(transport.ReasonNoWriter))); errors.Is(err, ErrNoWriter) {
		t.Fatalf("the no-writer reason on RESOURCE_EXHAUSTED: %v", err)
	}

	// The messages of the values that existed before are what they were: the value's text, then the answer's.
	for code, want := range map[codes.Code]string{
		codes.PermissionDenied: "cipheron: permission denied: m",
		codes.InvalidArgument:  "cipheron: invalid input: m",
		codes.Unavailable:      "cipheron: unavailable: m",
		codes.Unimplemented:    "cipheron: not supported by this cipheron: m",
		codes.Internal:         "cipheron: internal error: m",
		codes.Aborted:          "cipheron: m (Aborted)",
	} {
		if got := mapErr(ctx, status.Error(code, "m")).Error(); got != want {
			t.Errorf("%v: %q, want %q", code, got, want)
		}
	}
	if got := mapErr(ctx, status.Error(codes.ResourceExhausted, "grpc: received message larger than max (9 vs. 4)")).Error(); got != "cipheron: too large: grpc: received message larger than max (9 vs. 4)" {
		t.Errorf("the size refusal's message: %q", got)
	}
	if got := mapErr(ctx, withDetailsT(t, codes.InvalidArgument, "m", info(transport.ReasonKeyVersionUnavailable))).Error(); got != "cipheron: the key version is not available: m" {
		t.Errorf("the key-version message: %q", got)
	}
	// An answer of a code the package has no value for is none of the values, and still carries its status.
	other := mapErr(ctx, status.Error(codes.Aborted, "m"))
	for _, v := range []error{ErrPermissionDenied, ErrInvalidInput, ErrUnavailable, ErrTooLarge, ErrInternal, ErrUnsupported} {
		if errors.Is(other, v) {
			t.Errorf("ABORTED is %v", v)
		}
	}
	if status.Code(other) != codes.Aborted {
		t.Errorf("ABORTED lost its code: %v", status.Code(other))
	}
	// A deadline or a cancellation that is not this call's context: the context value, and the status.
	if err := mapErr(ctx, status.Error(codes.DeadlineExceeded, "m")); !errors.Is(err, context.DeadlineExceeded) ||
		status.Code(err) != codes.DeadlineExceeded || err.Error() != "cipheron: m: context deadline exceeded" {
		t.Errorf("a deadline of the server's: %v", err)
	}

	// RetryAfter: nothing for no error, a local error, an answer without one, or a delay that is not valid.
	for name, err := range map[string]error{
		"nil":             nil,
		"a local error":   errors.New("x"),
		"no RetryInfo":    mapErr(ctx, status.Error(codes.ResourceExhausted, "x")),
		"a nil delay":     mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "x", &errdetails.RetryInfo{})),
		"a negative":      mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "x", retry(-time.Second))),
		"an identity err": fmt.Errorf("%w: x", ErrServerIdentity),
	} {
		if d, ok := RetryAfter(err); ok || d != 0 {
			t.Errorf("RetryAfter(%s) = %v, %v", name, d, ok)
		}
	}
	if d, ok := RetryAfter(mapErr(ctx, withDetailsT(t, codes.ResourceExhausted, "x", retry(0)))); !ok || d != 0 {
		t.Errorf("a zero delay is a delay: %v %v", d, ok)
	}
	// It reads the protocol client's unmapped error as well (cipheron client does).
	if d, ok := RetryAfter(withDetailsT(t, codes.ResourceExhausted, "x", retry(2*time.Second))); !ok || d != 2*time.Second {
		t.Errorf("RetryAfter of an unmapped status: %v %v", d, ok)
	}
}

// TestMapErrUnknownSigningKey (finding B): ErrUnknownSigningKey is the Client's own decision and is returned as it
// is; with the fetch's error under it, the fetch's error is mapped too and both hold; a context that ended is the
// context's error, bare.
func TestMapErrUnknownSigningKey(t *testing.T) {
	ctx := context.Background()
	own := fmt.Errorf("%w (profile %q): not fetched again yet", ErrUnknownSigningKey, "d")
	if err := mapErr(ctx, own); err != own { //nolint:errorlint // identity is the assertion
		t.Fatalf("the client's own ErrUnknownSigningKey became %v", err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := mapErr(done, own); err != own { //nolint:errorlint // identity is the assertion
		t.Fatalf("a decision that cut nothing short became %v because the context had ended", err)
	}
	denied := fmt.Errorf("%w: the keys could not be fetched again: %w", ErrUnknownSigningKey, status.Error(codes.PermissionDenied, "permission denied"))
	if err := mapErr(ctx, denied); !errors.Is(err, ErrUnknownSigningKey) || !errors.Is(err, ErrPermissionDenied) ||
		status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a failed refresh: %v", err)
	}
	identity := fmt.Errorf("%w: the keys could not be fetched again: %w", ErrUnknownSigningKey, fmt.Errorf("%w: uid", ErrServerIdentity))
	if err := mapErr(ctx, identity); !errors.Is(err, ErrUnknownSigningKey) || !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("a refresh refused for the server's identity: %v", err)
	}
	cut := fmt.Errorf("%w: the keys could not be fetched again: %w", ErrUnknownSigningKey, context.Canceled)
	if err := mapErr(done, cut); err != context.Canceled { //nolint:errorlint // identity is the assertion
		t.Fatalf("a refresh cut short by the call's context: %v", err)
	}
}

// TestMapErrRoundTwo pins the values of round 2: ErrSigningKeyRevoked and ErrKeysStale are the protocol client's own
// and pass through, and so does ErrBadResponse (an answer holding what this protocol does not have); ErrUnsupported
// (UNIMPLEMENTED) is its own value; FAILED_PRECONDITION is no value; a ciphertext of a format this protocol does not
// have is the caller's input, ErrInvalidInput; ErrKeysStale over a failed fetch is the fetch's value too, and over
// the call's own context the context's error, bare.
func TestMapErrRoundTwo(t *testing.T) {
	ctx := context.Background()
	if ErrSigningKeyRevoked != client.ErrSigningKeyRevoked || ErrSigningKeyRevoked != transport.ErrSigningKeyRevoked || //nolint:errorlint // identity is the assertion
		ErrKeysStale != client.ErrKeysStale || ErrBadResponse != client.ErrBadResponse { //nolint:errorlint // identity is the assertion
		t.Fatal("the re-exported values are the protocol client's (and the transport's) own")
	}
	if ErrUnsupported.Error() != "cipheron: not supported by this cipheron" || errors.Is(ErrUnsupported, ErrBadResponse) {
		t.Fatalf("ErrUnsupported is a value of its own: %q", ErrUnsupported)
	}
	for _, own := range []error{ErrSigningKeyRevoked, ErrKeysStale, ErrBadResponse} {
		wrapped := fmt.Errorf("%w: the reason", own)
		if err := mapErr(ctx, wrapped); err != wrapped { //nolint:errorlint // identity is the assertion
			t.Errorf("the client's own %v became %v", own, err)
		}
	}
	// An answer in a format this protocol does not have, refused by the client: ErrBadResponse, never the caller's
	// input.
	answered := fmt.Errorf("%w: the ciphertext answered is in a format this protocol does not have (%v)", client.ErrBadResponse,
		transport.ErrCiphertextFormat) //nolint:errorlint // the client's own shape: the cause named, not wrapped
	if err := mapErr(ctx, answered); !errors.Is(err, ErrBadResponse) || errors.Is(err, ErrInvalidInput) {
		t.Errorf("an answer of an unknown ciphertext format: %v", err)
	}
	if err := mapErr(ctx, status.Error(codes.FailedPrecondition, "a redirect")); errors.Is(err, ErrInvalidInput) ||
		errors.Is(err, ErrUnsupported) || status.Code(err) != codes.FailedPrecondition {
		t.Errorf("FAILED_PRECONDITION: %v", err)
	}
	unimpl := mapErr(ctx, status.Error(codes.Unimplemented, "m"))
	if !errors.Is(unimpl, ErrUnsupported) || unimpl.Error() != "cipheron: not supported by this cipheron: m" {
		t.Errorf("UNIMPLEMENTED: %v", unimpl)
	}
	format := fmt.Errorf("the ciphertext given: %w", fmt.Errorf("%w (format 9)", transport.ErrCiphertextFormat))
	if err := mapErr(ctx, format); !errors.Is(err, ErrInvalidInput) || !errors.Is(err, transport.ErrCiphertext) {
		t.Errorf("a ciphertext of an unknown format given: %v", err)
	}
	stale := fmt.Errorf("%w (profile %q): %w", ErrKeysStale, "d", status.Error(codes.Unavailable, "down"))
	if err := mapErr(ctx, stale); !errors.Is(err, ErrKeysStale) || !errors.Is(err, ErrUnavailable) || status.Code(err) != codes.Unavailable {
		t.Errorf("a stale list whose refresh failed: %v", err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := mapErr(done, fmt.Errorf("%w: %w", ErrKeysStale, context.Canceled)); err != context.Canceled { //nolint:errorlint // identity is the assertion
		t.Errorf("a refresh cut short by the call's context: %v", err)
	}
}

// TestMapErrCertificateRefused (finding A): cipheron's refusal of the client's certificate is ErrCertificateRefused
// and ErrPermissionDenied, PERMISSION_DENIED by its code.
func TestMapErrCertificateRefused(t *testing.T) {
	refused := refusedForTestError{}
	err := mapErr(context.Background(), refused)
	if !errors.Is(err, ErrCertificateRefused) || !errors.Is(err, client.ErrCertificateRefused) || !errors.Is(err, ErrPermissionDenied) ||
		status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a refused certificate: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "cipheron: permission denied: ") {
		t.Fatalf("its message: %q", err)
	}
	// A call's refusal is not the certificate's.
	if err := mapErr(context.Background(), status.Error(codes.PermissionDenied, "permission denied")); errors.Is(err, ErrCertificateRefused) {
		t.Fatalf("a refused call is ErrCertificateRefused: %v", err)
	}
}

// refusedForTestError is the shape of the protocol client's refused-certificate error: a PERMISSION_DENIED status that
// is client.ErrCertificateRefused (the client's own type is not exported; network_test.go has the real one).
type refusedForTestError struct{}

func (refusedForTestError) Error() string        { return "cipheron refused this client's certificate" }
func (refusedForTestError) Is(target error) bool { return target == client.ErrCertificateRefused }
func (r refusedForTestError) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, r.Error())
}
