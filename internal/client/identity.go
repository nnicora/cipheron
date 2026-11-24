package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// identityError marks a connection the client refused because of who answered: the socket's process runs as
// another uid (WithServerUID), or the server's certificate or SPIFFE ID did not verify. It is what turns a call
// that would otherwise wait until its deadline into ErrServerIdentity.
type identityError struct{ err error }

func (e *identityError) Error() string { return e.err.Error() }
func (e *identityError) Unwrap() error { return e.err }

// isIdentityError reports whether err is a refusal of the server's identity: one of this package's, or
// crypto/tls's verification of the server's certificate (by hostname against RootCAs).
func isIdentityError(err error) bool {
	var ie *identityError
	var ce *tls.CertificateVerificationError
	return errors.As(err, &ie) || errors.As(err, &ce)
}

// identityState is what a Client knows of its last connection attempt: whether it was refused because of the
// server's identity. gRPC retries a connection that fails, and a call that waits for the connection to be ready
// (the default, so an application may start before cipheron has unsealed) would wait until its deadline and
// fail as a timeout. Instead:
//   - every connection attempt reports here: refused for identity (failed), or anything else (clear);
//   - a refusal ends every call that is waiting at that moment, with the refusal as its cause;
//   - while the last attempt was refused, a new call does not wait for a ready connection: it fails at once
//     with what gRPC knows (UNAVAILABLE), and the Client answers ErrServerIdentity (Client.finish).
//
// A call that is already on a live connection when another connection of the pool is refused is ended too: two
// connections to one address that reach different servers mean an impostor is on the path. Exactly: the state is
// ONE per Client, shared by every connection of its pool, so one identity refusal — of any connection attempt, of
// any connection — ends every gRPC call of the Client that is in flight at that moment, served or waiting, with
// ErrServerIdentity; a call so ended may or may not have been served. Nothing is remembered beyond the "last
// attempt" flag: the next attempt that is not an identity refusal clears it.
type identityState struct {
	mu      sync.Mutex
	err     error // the last attempt's identity refusal; nil when it was not one
	seq     uint64
	waiting map[uint64]context.CancelCauseFunc
}

func newIdentityState() *identityState {
	return &identityState{waiting: map[uint64]context.CancelCauseFunc{}}
}

// failed records an identity refusal and ends the calls that are waiting.
func (s *identityState) failed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
	cause := identityFailure(err)
	for id, cancel := range s.waiting {
		cancel(cause)
		delete(s.waiting, id)
	}
}

// clear records an attempt that was not refused for the server's identity.
func (s *identityState) clear() {
	s.mu.Lock()
	s.err = nil
	s.mu.Unlock()
}

// last is the last attempt's identity refusal, or nil.
func (s *identityState) last() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// begin registers a gRPC call: the context the call runs with (ended by an identity refusal), the call options
// (no waiting for a ready connection while the last attempt was refused), and done, to call when the call ends.
func (s *identityState) begin(ctx context.Context) (context.Context, []grpc.CallOption, func()) {
	cctx, cancel := context.WithCancelCause(ctx)
	s.mu.Lock()
	refused := s.err != nil
	s.seq++
	id := s.seq
	s.waiting[id] = cancel
	s.mu.Unlock()
	var opts []grpc.CallOption
	if refused {
		opts = []grpc.CallOption{grpc.WaitForReady(false)}
	}
	return cctx, opts, func() {
		s.mu.Lock()
		delete(s.waiting, id)
		s.mu.Unlock()
		cancel(nil)
	}
}

// outcome is the error of a call begun with begin: ErrServerIdentity when an identity refusal ended it, and
// cipheron's refusal of this client's certificate (a PERMISSION_DENIED refusedError, refusal.go) when that did.
//
// The error carries the call's request id (requestid.go: RequestIDOf), its text and status unchanged.
func outcome(cctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	cause := context.Cause(cctx)
	var r *refusedError
	if cause != nil && (errors.Is(cause, ErrServerIdentity) || errors.As(cause, &r)) {
		return withID(cause, outgoingRequestID(cctx))
	}
	return withID(err, outgoingRequestID(cctx))
}

// watchedCreds reports every TLS handshake's outcome to the identity state, and to the connection's refusals
// (nil: none) — on a TLS 1.3 connection whose handshake completed, cipheron's refusal of this client's
// certificate is read after the handshake, so the connection is wrapped to watch for it (refusal.go).
type watchedCreds struct {
	credentials.TransportCredentials

	id   *identityState
	deny *refusals
}

func (w watchedCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := w.TransportCredentials.ClientHandshake(ctx, authority, raw)
	switch {
	case err == nil:
		w.id.clear()
	case isIdentityError(err):
		w.id.failed(err)
	default:
		w.id.clear()
	}
	if w.deny != nil {
		w.deny.clear()
		if ti, ok := info.(credentials.TLSInfo); ok && err == nil {
			conn = watchRefusals(conn, ti.State, w.deny.refused)
		}
	}
	return conn, info, err
}

func (w watchedCreds) Clone() credentials.TransportCredentials {
	return watchedCreds{TransportCredentials: w.TransportCredentials.Clone(), id: w.id, deny: w.deny}
}
