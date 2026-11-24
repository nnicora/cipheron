//go:build linux || darwin

package cipheron

// review5_test.go — the review's findings, end to end against the fake cipheron, over gRPC (the library's own
// transport) and over cipheron's HTTP API (the protocol client's other transport, behind the same mapping): what
// cipheron answers when it cannot serve becomes the value a service must treat differently, with the answer kept
// behind it (A); a size refusal is gRPC's own and nothing else (J); a closed Client says so (C); a nil Option is
// skipped (D).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// overBoth runs f with a Client of fake over gRPC and one over the HTTP API. mkClient returns a NEW Client each time.
func overBoth(t *testing.T, fake *cipherontest.Server, f func(t *testing.T, mkClient func() *Client)) {
	t.Helper()
	grpcSock, httpSock := fake.ServeSocket(t), fake.ServeHTTPSocket(t)
	t.Run("gRPC", func(t *testing.T) {
		f(t, func() *Client {
			c, err := New(grpcSock, WithAnyServer())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			return c
		})
	})
	t.Run("HTTP", func(t *testing.T) {
		f(t, func() *Client {
			c, err := New(httpSock, WithAnyServer(), WithTransport(TransportHTTP))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			return c
		})
	})
}

// TestWhatCipheronAnswersWhenItCannotServe (finding A): busy, no writer, internal, unimplemented, and a
// RESOURCE_EXHAUSTED that is none of cipheron's, each as the fake answers it with cipheron's code and details.
func TestWhatCipheronAnswersWhenItCannotServe(t *testing.T) {
	const shared, wrapped = "credentials", "documents"
	fake := cipherontest.New(t, shared, wrapped)
	fake.MakePerTenant(wrapped)
	overBoth(t, fake, func(t *testing.T, mkClient func() *Client) {
		t.Helper()

		defer fake.Fail(cipherontest.NoFault)
		defer fake.FailPublicKey(cipherontest.NoFault)
		c := mkClient()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ct, err := c.Encrypt(ctx, shared, []byte("made before"))
		if err != nil {
			t.Fatal(err)
		}
		tk, err := c.CreateTenantKey(ctx, wrapped, "t_acme")
		if err != nil {
			t.Fatal(err)
		}
		is := func(err error, all ...error) bool {
			for _, v := range all {
				if !errors.Is(err, v) {
					return false
				}
			}
			return true
		}
		none := func(err error, all ...error) bool {
			for _, v := range all {
				if errors.Is(err, v) {
					return false
				}
			}
			return true
		}

		// Busy: every call; the delay is cipheron's; the status and its reason are still there.
		fake.Fail(cipherontest.Busy)
		for name, call := range map[string]func() error{
			"Encrypt": func() error { _, err := c.Encrypt(ctx, shared, []byte("x")); return err },
			"Decrypt": func() error { _, err := c.Decrypt(ctx, shared, ct); return err },
			"Sign":    func() error { _, err := c.Sign(ctx, shared, []byte("x")); return err },
		} {
			err := call()
			if !is(err, ErrBusy, ErrUnavailable) || !none(err, ErrTooLarge, ErrNoWriter, ErrInternal, ErrPermissionDenied) {
				t.Fatalf("%s while busy: %v; want ErrBusy (and ErrUnavailable)", name, err)
			}
			if d, ok := RetryAfter(err); !ok || d != cipherontest.BusyRetryDelay {
				t.Fatalf("%s while busy: RetryAfter = %v, %v; want %v", name, d, ok, cipherontest.BusyRetryDelay)
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.ResourceExhausted || !hasReason(st, transport.ReasonBusy) {
				t.Fatalf("%s while busy: the answer is not in the error: %v", name, err)
			}
			if err.Error() != "cipheron: unavailable: "+cipherontest.BusyMessage {
				t.Fatalf("%s while busy: the message %q", name, err)
			}
		}

		// No writer: the writes; reads, and a wrapped profile's Encrypt (the tenant's own key), are served.
		fake.Fail(cipherontest.NoWriter)
		for name, call := range map[string]func() error{
			"Encrypt":         func() error { _, err := c.Encrypt(ctx, shared, []byte("x")); return err },
			"ReEncrypt":       func() error { _, err := c.ReEncrypt(ctx, shared, ct); return err },
			"CreateTenantKey": func() error { _, err := c.CreateTenantKey(ctx, wrapped, "t_globex"); return err },
			"RewrapTenantKey": func() error { _, err := c.RewrapTenantKey(ctx, wrapped, "t_acme", tk.Blob); return err },
		} {
			err := call()
			if !is(err, ErrNoWriter, ErrUnavailable) || !none(err, ErrBusy, ErrTooLarge, ErrInvalidInput) {
				t.Fatalf("%s with no writer: %v; want ErrNoWriter (and ErrUnavailable)", name, err)
			}
			if _, ok := RetryAfter(err); ok {
				t.Fatalf("%s with no writer: a delay", name)
			}
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("%s with no writer: code %v", name, status.Code(err))
			}
		}
		if pt, err := c.Decrypt(ctx, shared, ct); err != nil || string(pt) != "made before" {
			t.Fatalf("a read with no writer: %q, %v", pt, err)
		}
		if _, err := c.Sign(ctx, shared, []byte("x")); err != nil {
			t.Fatalf("Sign with no writer: %v", err)
		}
		if _, err := c.Tenant(wrapped, "t_acme", tk.Blob).Encrypt(ctx, []byte("x")); err != nil {
			t.Fatalf("a wrapped profile's Encrypt with no writer: %v", err)
		}

		// Internal.
		fake.Fail(cipherontest.Internal)
		_, err = c.Encrypt(ctx, shared, []byte("x"))
		if !is(err, ErrInternal) || !none(err, ErrUnavailable, ErrInvalidInput) || status.Code(err) != codes.Internal ||
			err.Error() != "cipheron: internal error: "+cipherontest.InternalMessage {
			t.Fatalf("an internal error: %v", err)
		}

		// A cipheron that does not have the call.
		fake.Fail(cipherontest.Unimplemented)
		_, err = c.ReEncrypt(ctx, shared, ct)
		if !is(err, ErrUnsupported) || !none(err, ErrUnavailable, ErrInternal) || status.Code(err) != codes.Unimplemented {
			t.Fatalf("a call cipheron does not have: %v", err)
		}

		// RESOURCE_EXHAUSTED from something that is not cipheron, about nothing's size: unavailable, never too large.
		fake.Fail(cipherontest.Overloaded)
		_, err = c.Encrypt(ctx, shared, []byte("x"))
		if !is(err, ErrUnavailable) || !none(err, ErrTooLarge, ErrBusy, ErrNoWriter) {
			t.Fatalf("RESOURCE_EXHAUSTED with no details and no size wording: %v; want ErrUnavailable only", err)
		}
		if _, ok := RetryAfter(err); ok {
			t.Fatal("an answer without a RetryInfo has a delay")
		}

		// Served again; and a Client's very first call (the fetch of the profile's keys) answered busy is busy too.
		fake.Fail(cipherontest.NoFault)
		if _, err := c.Encrypt(ctx, shared, []byte("x")); err != nil {
			t.Fatalf("after the fault: %v", err)
		}
		fake.FailPublicKey(cipherontest.Busy)
		_, err = mkClient().Encrypt(ctx, shared, []byte("x"))
		if !is(err, ErrBusy, ErrUnavailable) {
			t.Fatalf("the first call of a Client, cipheron busy: %v", err)
		}
		if d, ok := RetryAfter(err); !ok || d != cipherontest.BusyRetryDelay {
			t.Fatalf("its delay: %v %v", d, ok)
		}
	})
}

// TestSizeRefusalIsGRPCsOwn (finding J): a request over cipheron's limit (its maxRequestBytes: the gRPC server's
// MaxRecvMsgSize) is refused by gRPC itself — RESOURCE_EXHAUSTED, no details, gRPC's wording — and that, and only
// that, is ErrTooLarge. The wording is the vendored gRPC's: a gRPC that words its refusal otherwise fails here.
func TestSizeRefusalIsGRPCsOwn(t *testing.T) {
	const profile = "credentials"
	const limit = 8 << 10
	fake := cipherontest.New(t, profile)
	c, err := New(fake.ServeSocketMax(t, limit), WithAnyServer())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Encrypt(ctx, profile, make([]byte, limit/2)); err != nil {
		t.Fatalf("a request under the server's limit: %v", err)
	}
	_, err = c.Encrypt(ctx, profile, make([]byte, 8*limit))
	if !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrBusy) {
		t.Fatalf("a request over the server's limit: %v; want ErrTooLarge", err)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted || len(st.Proto().GetDetails()) != 0 || !strings.Contains(err.Error(), "larger than max") {
		t.Fatalf("gRPC's size refusal is not what isSizeRefusal reads: %v (details %d)", err, len(st.Proto().GetDetails()))
	}
	if _, ok := RetryAfter(err); ok {
		t.Fatal("a size refusal has no delay")
	}
	// The Client still works, and its own limit is refused before anything is sent — the same value.
	if _, err := c.Encrypt(ctx, profile, []byte("small")); err != nil {
		t.Fatalf("after a size refusal: %v", err)
	}
	small, err := New(fake.SocketPath(), WithAnyServer(), WithMaxMessageBytes(4<<10))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = small.Close() }()
	calls := fake.PublicKeyCalls()
	if _, err := small.Encrypt(ctx, profile, make([]byte, 8<<10)); !errors.Is(err, ErrTooLarge) || fake.PublicKeyCalls() != calls {
		t.Fatalf("the Client's own limit: %v (%d requests sent)", err, fake.PublicKeyCalls()-calls)
	}
}

// TestAClosedClient (finding C) and a nil Option (finding D), through the library.
func TestAClosedClient(t *testing.T) {
	const profile = "credentials"
	fake := cipherontest.New(t, profile)
	overBoth(t, fake, func(t *testing.T, mkClient func() *Client) {
		t.Helper()

		c := mkClient()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ct, err := c.Encrypt(ctx, profile, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("a second Close: %v", err)
		}
		calls := fake.PublicKeyCalls()
		for name, call := range map[string]func() error{
			"Encrypt":       func() error { _, err := c.Encrypt(ctx, profile, []byte("x")); return err },
			"Decrypt":       func() error { _, err := c.Decrypt(ctx, profile, ct); return err },
			"Keys":          func() error { _, err := c.Keys(ctx, profile); return err },
			"ContextDigest": func() error { _, err := c.ContextDigest(ctx, profile); return err },
			"Tenant.Sign":   func() error { _, err := c.Tenant(profile, "t_1", nil).Sign(ctx, []byte("x")); return err },
		} {
			err := call()
			if !errors.Is(err, ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, ErrUnavailable) {
				t.Fatalf("%s after Close: %v; want ErrClosed, and nothing else", name, err)
			}
		}
		if fake.PublicKeyCalls() != calls {
			t.Fatal("a call after Close reached cipheron")
		}
	})
	// A nil Option is skipped, wherever it stands.
	c, err := New(fake.SocketPath(), nil, WithAnyServer(), nil)
	if err != nil {
		t.Fatalf("New with nil options: %v", err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Encrypt(ctx, profile, []byte("x")); err != nil {
		t.Fatalf("a Client made with nil options: %v", err)
	}
	// New's own errors are configuration errors: none of the package's values.
	_, err = New(fake.SocketPath())
	if err == nil {
		t.Fatal("a socket without WithServerUID or WithAnyServer")
	}
	for _, v := range []error{ErrPermissionDenied, ErrInvalidInput, ErrUnavailable, ErrServerIdentity, ErrTooLarge, ErrClosed, ErrInternal} {
		if errors.Is(err, v) {
			t.Fatalf("New's configuration error is %v: %v", v, err)
		}
	}
}
