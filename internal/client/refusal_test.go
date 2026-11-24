//go:build linux || darwin

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/cipherontest"
)

const refusalServerID = "spiffe://prod.example.org/cipheron"

var errNotListed = errors.New("no profile lists the identity")

// refusingServer is a fake cipheron on mutual TLS whose VerifyConnection refuses every client while refuse is
// set — as cipheron refuses a SPIFFE ID no profile lists — and the client TLS configuration that reaches it.
func refusingServer(t *testing.T, refuse *atomic.Bool, configure func(*tls.Config)) (string, *tls.Config, *cipherontest.Server) {
	t.Helper()
	ca := cipherontest.NewCA(t, "ca")
	fake := cipherontest.New(t, "credentials")
	addr := fake.ServeTLSConfig(t, ca.Server(t, refusalServerID), ca, func(c *tls.Config) {
		c.VerifyConnection = func(tls.ConnectionState) error {
			if refuse.Load() {
				return errNotListed
			}
			return nil
		}
		if configure != nil {
			configure(c)
		}
	})
	return addr, cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/app", ca.Pool), fake
}

func requestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// publicOf is key's public half.
func publicOf(t *testing.T, key ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("an Ed25519 private key's public half: got %T", key.Public())
	}
	return pub
}

// isRefusal reports whether err is cipheron's refusal of this client's certificate: PERMISSION_DENIED, wrapping
// the alert, and ErrCertificateRefused.
func isRefusal(err error) bool {
	var r *refusedError
	return status.Code(err) == codes.PermissionDenied && errors.As(err, &r) && isCertificateRefusal(err) &&
		errors.Is(err, ErrCertificateRefused)
}

// TestCertificateRefusalFailsFastAndDoesNotStick: cipheron refusing the client's certificate in a TLS 1.3
// handshake fails the call at once with PERMISSION_DENIED — every call, sequential or concurrent, well before its
// deadline — and does not mark the Client: once the server admits the client, the next call is served, without
// waiting out the backoff the refusals grew.
func TestCertificateRefusalFailsFastAndDoesNotStick(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	addr, tc, fake := refusingServer(t, &refuse, nil)
	key := requestKey(t)
	fake.RequireRequestKey("credentials", publicOf(t, key))
	c, err := DialGRPC(addr, WithTLS(tc), WithRequestKey(key), WithServerSPIFFEID(refusalServerID),
		WithConnections(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Six refused calls in a row, each a fresh connection attempt: without cutting gRPC's backoff short, each
	// would wait a second or more for its attempt (about six in all).
	sequence := time.Now()
	for i := range 6 {
		start := time.Now()
		_, err := c.Encrypt(ctx, "credentials", []byte("x"))
		if !isRefusal(err) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("call %d: %v; want PERMISSION_DENIED wrapping the alert", i, err)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Fatalf("call %d took %v", i, took)
		}
	}
	if took := time.Since(sequence); took > 3*time.Second {
		t.Fatalf("six refused calls took %v: they waited out gRPC's backoff", took)
	}
	// Concurrent calls all fail, fast.
	var wg sync.WaitGroup
	errs := make([]error, 8)
	start := time.Now()
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = c.Encrypt(ctx, "credentials", []byte("x"))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if !isRefusal(err) {
			t.Fatalf("concurrent call %d: %v", i, err)
		}
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the concurrent calls took %v", took)
	}

	// The server now admits the client (its SPIFFE ID was listed): the next call is served, promptly.
	refuse.Store(false)
	start = time.Now()
	if _, err := c.Encrypt(ctx, "credentials", []byte("x")); err != nil {
		t.Fatalf("after the client was admitted: %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the first call after the client was admitted took %v: it waited out a backoff", took)
	}
}

// TestUnauthenticatedRefusalsStayTransient: a refusal alert the client cannot attribute to the server it
// verified does not fail a call fast — the call waits for a connection until its context ends, as for any
// transient failure: a TLS 1.2 server's alert (plaintext, before either Finished), and an alert written in
// plaintext into the TCP stream in place of the server's answer (what an on-path attacker could inject). Over
// HTTP, which does not wait, it is UNAVAILABLE, not PERMISSION_DENIED.
func TestUnauthenticatedRefusalsStayTransient(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	tls12, tc, _ := refusingServer(t, &refuse, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })
	injected := injectAlert(t)
	for name, addr := range map[string]string{"a TLS 1.2 server": tls12, "an injected plaintext alert": injected} {
		g, err := DialGRPC(addr, WithTLS(tc), WithRequestKey(requestKey(t)), WithServerSPIFFEID(refusalServerID))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_, err = g.Encrypt(ctx, "credentials", []byte("x"))
		cancel()
		_ = g.Close()
		if isRefusal(err) || status.Code(err) == codes.PermissionDenied || ctx.Err() == nil {
			t.Errorf("%s over gRPC: %v; want a call that waited until its context ended", name, err)
		}

		h, err := DialHTTP(addr, WithTLS(tc), WithRequestKey(requestKey(t)), WithServerSPIFFEID(refusalServerID))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		_, err = h.Encrypt(ctx, "credentials", []byte("x"))
		cancel()
		_ = h.Close()
		if isRefusal(err) || status.Code(err) != codes.Unavailable {
			t.Errorf("%s over HTTP: %v; want UNAVAILABLE", name, err)
		}
	}
}

// injectAlert is a TCP server that answers every ClientHello with a plaintext fatal bad_certificate alert
// record and closes. It returns the address.
func injectAlert(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, make([]byte, 5)); err != nil { // the ClientHello's record header
					return
				}
				// alert record, TLS 1.2 record version, length 2: fatal (2), bad_certificate (42).
				_, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, 42})
			}()
		}
	}()
	return l.Addr().String()
}

// TestIsCertificateRefusal: only an alert received from the peer that refuses the client's certificate.
func TestIsCertificateRefusal(t *testing.T) {
	for _, a := range certificateRefusals {
		if !isCertificateRefusal(&net.OpError{Op: "remote error", Err: a}) {
			t.Errorf("%v is a refusal", a)
		}
	}
	for name, err := range map[string]error{
		"handshake_failure":       &net.OpError{Op: "remote error", Err: tls.AlertError(40)},
		"internal_error":          &net.OpError{Op: "remote error", Err: tls.AlertError(80)},
		"our own bad_certificate": &net.OpError{Op: "local error", Err: tls.AlertError(42)},
		"a reset":                 &net.OpError{Op: "read", Err: errors.New("connection reset by peer")},
		"EOF":                     io.EOF,
	} {
		if isCertificateRefusal(err) {
			t.Errorf("%s is not a refusal", name)
		}
	}
	// Only a TLS 1.3 connection whose handshake completed is watched.
	var c net.Conn = &net.TCPConn{}
	if watchRefusals(c, tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true}, nil) != c ||
		watchRefusals(c, tls.ConnectionState{Version: tls.VersionTLS13}, nil) != c {
		t.Error("an unauthenticated connection is watched")
	}
	if _, ok := watchRefusals(c, tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}, nil).(*refusalConn); !ok {
		t.Error("an authenticated connection is not watched")
	}
}

// TestRefusalsEndWaitingCalls: a refusal ends the calls registered at that moment with itself as their cause,
// marks the last attempt, and is forgotten by the next attempt that is not one.
func TestRefusalsEndWaitingCalls(t *testing.T) {
	r := newRefusals()
	ctx, last, done := r.begin(context.Background())
	defer done()
	if last {
		t.Fatal("nothing was refused")
	}
	refusal := &refusedError{err: &net.OpError{Op: "remote error", Err: tls.AlertError(42)}}
	r.refused(refusal)
	<-ctx.Done()
	if err := outcome(ctx, status.Error(codes.Canceled, "context canceled")); !errors.Is(err, refusal) ||
		status.Code(err) != codes.PermissionDenied {
		t.Fatalf("outcome: %v", err)
	}
	later, last, done2 := r.begin(context.Background())
	if !last || later.Err() != nil {
		t.Fatal("a call after a refusal: the last attempt is refused, and the call is not ended by it")
	}
	done2()
	r.clear()
	if _, last, done3 := r.begin(context.Background()); last {
		t.Fatal("clear")
	} else {
		done3()
	}
	if len(r.waiting) != 0 {
		t.Fatalf("%d calls still registered", len(r.waiting))
	}
}
