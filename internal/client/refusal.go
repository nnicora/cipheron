package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A network client whose certificate cipheron refuses — its identity is one no profile lists, or is not in the scope of
// the trust bundle that verified it, or its chain does not verify, is revoked or has expired — is told so by a TLS
// alert: cipheron runs every one of those checks in the handshake's VerifyConnection, and crypto/tls answers a failed
// VerifyConnection with bad_certificate. Without this file the client would treat the closed connection as a server not
// up yet, and a call would wait for a connection until its context ended. With it, the call fails at once with
// PERMISSION_DENIED (package cipheron: ErrPermissionDenied), wrapping the alert.
//
// ONLY AN AUTHENTICATED ALERT COUNTS. A TLS alert is a record anyone on the path can write into the TCP stream
// when it is not protected, and an alert that ended a call at once would let an on-path party turn a
// connection it merely disturbs into a failure the application may not retry. Which alerts are protected:
//   - TLS 1.2: the server checks the client certificate before either side's Finished, and its alert travels in
//     plaintext — forgeable by anyone on the path;
//   - TLS 1.3, during the client's handshake: encrypted under handshake keys, which an active attacker who
//     answered the ClientHello itself shares — forgeable before the server proved its certificate;
//   - TLS 1.3, after the client's handshake completed: the server checks the client certificate after it sent
//     its Finished, so its alert reaches the client after the client verified the server's CertificateVerify
//     and Finished, encrypted under the server's application traffic key — a key derived from a transcript
//     the server's certificate signed. Only the server this client verified (WithServerSPIFFEID, or the
//     hostname against RootCAs) can produce it.
//
// So the client treats as definitive only a certificate-refusal alert read on a TLS 1.3 connection whose
// handshake completed (refusalConn is installed only there). Every other failure stays what it was — a gRPC call
// keeps waiting for a connection, an HTTP call fails UNAVAILABLE: a connection refused or reset, a timeout, a
// server that is not up yet, one that closes without an alert (cipheron's cap on open connections closes so), a
// TLS 1.2 alert, an alert during the handshake, an error of this process's own (a certificate file being
// rotated).
//
// AND IT ENDS CALLS, NOT THE CLIENT. A refusal does not mark the Client, or the connection, as refused for good.
// What it ends, exactly: EVERY call that is registered at that moment on the gRPC connection (one grpc.ClientConn of
// the pool, WithConnections) whose TLS connection read the alert — the calls waiting for that connection, which is
// the purpose, AND any call still running on an OLDER TLS connection of the same grpc.ClientConn: gRPC replaces a
// connection the server is draining (a GOAWAY: cipheron's maximum connection age, a shutdown) while the calls on
// the old one finish, and a refusal read on the replacement ends those too, although cipheron might still have
// answered them. They fail with PERMISSION_DENIED (ErrCertificateRefused); a call so ended may or may not have been
// served — as any call whose connection breaks. The registry is per grpc.ClientConn, not per TLS connection: gRPC
// does not tell a call which connection it is on, so the scope is not narrowed. Calls on the pool's other
// connections are not touched.
//
// A call made afterwards asks for a fresh connection attempt at once (it cuts gRPC's backoff short — until that
// one attempt has its outcome, not for as long as the call lives — so it does not wait out a backoff that grew
// while the identity was unlisted) and fails only if that attempt is refused in turn; a call over HTTP opens its
// own connection anyway. Listing the identity, or fixing the certificate, is picked up by the next call. Compared
// with today's exposure: an on-path attacker can already reset or drop every connection, which makes every call
// wait until its deadline; it cannot forge an authenticated alert, so this adds no failure it can cause — and
// even an alert it somehow could inject would cost the calls in flight on that connection, not the Client.
//
// One race remains, harmless: cipheron closes a refused connection as soon as it sent the alert, and when the
// client's first bytes are still unread there the close is a reset, which may reach the client before it reads
// the alert. That attempt is then a transient failure like any other, and the next one tells.

// certificateRefusals are the TLS alerts by which a server refuses the client's certificate (RFC 8446 §6.2,
// RFC 5246 §7.2.2): bad_certificate (what crypto/tls sends for a failed VerifyConnection — cipheron's every
// refusal), unsupported_certificate, certificate_revoked, certificate_expired, certificate_unknown, unknown_ca,
// access_denied, certificate_required.
var certificateRefusals = []tls.AlertError{42, 43, 44, 45, 46, 48, 49, 116}

// isCertificateRefusal reports whether err is a TLS alert from the peer that refuses this client's certificate.
// crypto/tls reports an alert it received as a *net.OpError whose Op is "remote error" and whose Err is its own
// unexported alert type, which prints as tls.AlertError does.
func isCertificateRefusal(err error) bool {
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return false
	}
	var ae tls.AlertError
	if errors.As(op.Err, &ae) {
		return slices.Contains(certificateRefusals, ae)
	}
	msg := op.Err.Error()
	return slices.ContainsFunc(certificateRefusals, func(a tls.AlertError) bool { return a.Error() == msg })
}

// ErrCertificateRefused: cipheron refused this client's certificate in the TLS handshake, on a connection whose
// server this client had authenticated (see the top of this file). The error is also a gRPC PERMISSION_DENIED
// status (status.Code reads it), so a caller that only tells refusals apart by code needs nothing more; one that
// wants to say WHAT was refused — the certificate, not a call (cipheron client does) — tests errors.Is with this.
var ErrCertificateRefused = errors.New("cipheron: this client's certificate was refused")

// refusedError is cipheron's refusal of this client's certificate, read on a connection whose server was
// authenticated (see the top of this file). It is a gRPC PERMISSION_DENIED status, wraps the alert, and is
// ErrCertificateRefused.
type refusedError struct{ err error }

// Is makes a refusedError ErrCertificateRefused.
func (e *refusedError) Is(target error) bool { return target == ErrCertificateRefused }

func (e *refusedError) Error() string {
	return "cipheron refused this client's certificate in the TLS handshake (" + e.err.Error() + "): no profile " +
		"lists its identity, its identity is not in the scope of the trust bundle that verified it, or its chain does " +
		"not verify against cipheron's trust bundles (cipheron's log has the reason)"
}

func (e *refusedError) Unwrap() error { return e.err }

// GRPCStatus is PERMISSION_DENIED, so status.Code, and package cipheron's mapping, read it as cipheron's refusal.
func (e *refusedError) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// authenticatedRefusalError is the read error of a refusalConn that is a certificate refusal: the alert, marked as
// read on an authenticated connection. It is deliberately NOT a gRPC status: gRPC fails a wait-for-ready call at
// once when the connection error it would wait past is a status, so a status here would fail every call that
// starts while the connection is in backoff — the Client marked as refused until the next attempt. The calls are
// ended through report instead, and over HTTP the call's error becomes a refusedError (httpRPC.call).
type authenticatedRefusalError struct{ err error }

func (e *authenticatedRefusalError) Error() string { return e.err.Error() }
func (e *authenticatedRefusalError) Unwrap() error { return e.err }

// refusalConn is a TLS 1.3 connection whose handshake completed (the server authenticated): a certificate
// refusal read on it is returned as an authenticatedRefusalError and reported, once, to report (nil: none) as a
// refusedError.
type refusalConn struct {
	net.Conn

	report func(error)
	once   sync.Once
}

func (c *refusalConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && isCertificateRefusal(err) {
		if c.report != nil {
			c.once.Do(func() { c.report(&refusedError{err: err}) })
		}
		return n, &authenticatedRefusalError{err: err}
	}
	return n, err
}

// watchRefusals wraps conn, an established TLS connection in state, so a certificate refusal read on it is
// reported — when the refusal is authenticated: the connection is TLS 1.3 and its handshake completed. Any other
// connection is returned as it is.
func watchRefusals(conn net.Conn, state tls.ConnectionState, report func(error)) net.Conn {
	if state.Version != tls.VersionTLS13 || !state.HandshakeComplete {
		return conn
	}
	return &refusalConn{Conn: conn, report: report}
}

// refusals is one gRPC connection's (one grpc.ClientConn's) record of cipheron refusing this client's
// certificate: whether its last connection attempt was refused, how many attempts have had an outcome, and the
// calls on it to end when an attempt is refused.
type refusals struct {
	mu       sync.Mutex
	last     bool   // the last attempt was refused
	outcomes uint64 // attempts that had an outcome: refused, failed otherwise, or a handshake completed
	seq      uint64
	waiting  map[uint64]context.CancelCauseFunc
}

func newRefusals() *refusals { return &refusals{waiting: map[uint64]context.CancelCauseFunc{}} }

// refused records a refusal and ends the calls registered at this moment — every one, whichever TLS connection
// of the grpc.ClientConn it is on (see the top of this file) — with it as their cause.
func (r *refusals) refused(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = true
	r.outcomes++
	for id, cancel := range r.waiting {
		cancel(err)
		delete(r.waiting, id)
	}
}

// clear records an attempt that was not refused: it failed otherwise, or its handshake completed.
func (r *refusals) clear() {
	r.mu.Lock()
	r.last = false
	r.outcomes++
	r.mu.Unlock()
}

// settled reports whether an attempt has had an outcome since the count since (beginAt's).
func (r *refusals) settled(since uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.outcomes != since
}

// begin registers a call: the context it runs with (ended by a refusal), whether the last attempt was refused
// — the caller then asks for a fresh attempt at once — and done, to call when the call ends.
func (r *refusals) begin(ctx context.Context) (context.Context, bool, func()) {
	cctx, last, _, done := r.beginAt(ctx)
	return cctx, last, done
}

// beginAt is begin, and the count of attempt outcomes at that moment (settled).
func (r *refusals) beginAt(ctx context.Context) (context.Context, bool, uint64, func()) {
	cctx, cancel := context.WithCancelCause(ctx)
	r.mu.Lock()
	last, since := r.last, r.outcomes
	r.seq++
	id := r.seq
	r.waiting[id] = cancel
	r.mu.Unlock()
	return cctx, last, since, func() {
		r.mu.Lock()
		delete(r.waiting, id)
		r.mu.Unlock()
		cancel(nil)
	}
}
