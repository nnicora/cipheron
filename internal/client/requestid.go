package client

// requestid.go — every call names itself, and the operator can be told of the errors that only a client sees (ops
// review 2026-11-13, OB-11 and OB-12).
//
// THE REQUEST ID. Each call carries the gRPC metadata x-request-id (over HTTP the X-Request-Id header): the caller's own
// when its context already carries one in its OUTGOING gRPC metadata (metadata.AppendToOutgoingContext — gRPC's own
// mechanism, nothing new is put in a context), else 16 random bytes in hex. cipheron logs it on every refusal and
// failure line of the request and records it in the request's audit event, so RequestIDOf(err) — the id of the call
// that failed — is what to search the server's log and audit trail for. The error itself is unchanged: its text, its
// gRPC status and every errors.Is / errors.As answer are the same as without the id.
//
// THE OBSERVER. WithObserver(f) is told, at the end of a call, of an error of one of a fixed set of kinds — the
// integrity and drift errors cipheron's own metrics cannot see (ObserverKinds) —, of each retry WithRetry makes
// (KindRetry), and of an update of the pins directory that was not applied (KindPinsReload). An application exports
// them as it exports its own metrics (docs/client-library.md: a counter cipheron_client_errors_total{profile,kind}).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"unicode"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/wire/transport"
)

// maxRequestIDLen is the longest request id sent (cipheron accepts at most 128 printable bytes, and makes one of its
// own otherwise).
const maxRequestIDLen = 128

// withRequestID is ctx with a request id in its outgoing gRPC metadata — the one already there when it is printable
// and at most maxRequestIDLen bytes, else a new random one — and that id.
func withRequestID(ctx context.Context) (context.Context, string) {
	if id := outgoingRequestID(ctx); id != "" {
		return ctx, id
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	// Any value the caller put under the key and that is not usable is replaced, never sent beside the new one.
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(transport.RequestIDMetadataKey, id)
	return metadata.NewOutgoingContext(ctx, md), id
}

// outgoingRequestID is the usable request id of ctx's outgoing metadata ("" when there is none).
func outgoingRequestID(ctx context.Context) string {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return ""
	}
	v := md.Get(transport.RequestIDMetadataKey)
	if len(v) != 1 || v[0] == "" || len(v[0]) > maxRequestIDLen {
		return ""
	}
	for _, r := range v[0] {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return ""
		}
	}
	return v[0]
}

// idError is an error of the call whose request id is id: the error unchanged, with the id beside it.
type idError struct {
	err error
	id  string
}

func (e *idError) Error() string { return e.err.Error() }
func (e *idError) Unwrap() error { return e.err }

// idStatusError is idError for an error that carries a gRPC status: the status is the error's, so status.FromError,
// status.Code and the client's own reading of it answer as without the id.
type idStatusError struct{ idError }

func (e *idStatusError) GRPCStatus() *status.Status {
	st, _ := status.FromError(e.err)
	return st
}

// withID is err (nil stays nil) carrying the request id id ("" adds nothing; an error that already carries one keeps
// it).
func withID(err error, id string) error {
	if err == nil || id == "" || RequestIDOf(err) != "" {
		return err
	}
	if _, ok := status.FromError(err); ok {
		return &idStatusError{idError{err: err, id: id}}
	}
	return &idError{err: err, id: id}
}

// RequestIDOf is the request id of the call that failed with err — the id cipheron logged the failure under and
// recorded in its audit event — or "" when err carries none (it did not come from a call that was sent).
func RequestIDOf(err error) string {
	for err != nil {
		// The walk is this function's own, a level at a time, so the id nearest the top wins whichever of the two
		// carries it; errors.As per type would search the whole tree for one type before the other.
		switch e := err.(type) { //nolint:errorlint // walks the chain itself, one level at a time
		case *idError:
			return e.id
		case *idStatusError:
			return e.id
		}
		switch u := err.(type) { //nolint:errorlint // walks the chain itself, one level at a time
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				if id := RequestIDOf(x); id != "" {
					return id
				}
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

// The kinds the observer is told of (WithObserver): a fixed set, so a metric labelled by kind stays bounded.
const (
	KindContextDigest    = "context_digest"     // ErrContextDigest
	KindServerKeyChanged = "server_key_changed" // ErrServerKeyChanged
	KindServerIdentity   = "server_identity"    // ErrServerIdentity
	KindKeysStale        = "keys_stale"         // ErrKeysStale
	// KindRetry is a call sent again: by WithRetry after a transient refusal, or by any client after cipheron's start
	// barrier refusal (retry.go): told before each attempt after the first, with the call's profile. Not an error of
	// the call: the call may still succeed.
	KindRetry = "retry"
	// KindPinsReload is an update of the pins directory that was not applied (livepins.go): told once per distinct
	// failure with profile "" (the directory could not be read in full, or holds a pin the client refuses), and once
	// with the profile whose pin file disappeared (its pins are kept). The pins in force stay; it is told from the
	// client's own goroutine, not a call's.
	KindPinsReload = "pins_reload_failed"
)

// ObserverKinds are every kind, in a fixed order.
var ObserverKinds = []string{KindContextDigest, KindServerKeyChanged, KindServerIdentity, KindKeysStale, KindRetry,
	KindPinsReload}

// errorKind is the observer's kind of err, "" for an error it is not told of.
func errorKind(err error) string {
	for _, k := range []struct {
		err  error
		kind string
	}{{ErrContextDigest, KindContextDigest}, {ErrServerKeyChanged, KindServerKeyChanged}, {ErrServerIdentity, KindServerIdentity},
		{ErrKeysStale, KindKeysStale}} {
		if errors.Is(err, k.err) {
			return k.kind
		}
	}
	return ""
}

// WithObserver has f told, at the end of every call that failed with an integrity or drift error, the call's profile
// and the error's kind (ObserverKinds): errors only a client sees — a key context it does not pin, a changed
// identity, an impostor, a stale signing-key list. It is also told of each retry WithRetry
// makes (KindRetry, before the attempt) and of an update of the pins directory that was not applied (KindPinsReload,
// from the client's own goroutine). f runs on the calling goroutine — or the pins directory's — and may be called
// concurrently: keep it fast and safe for concurrent use (increment a counter). It is never told the error itself, a
// tenant or a payload. The profile is the one the application named in the call.
func WithObserver(f func(profile, kind string)) Option {
	return func(o *options) { o.observer = f }
}

// tell tells the observer, when there is one, of kind in profile.
func (c *Client) tell(profile, kind string) {
	if c.observer != nil {
		c.observer(profile, kind)
	}
}

// observe tells the observer of err when it is of a kind it watches.
func (c *Client) observe(profile string, err error) {
	if c.observer == nil || err == nil {
		return
	}
	if kind := errorKind(err); kind != "" {
		c.observer(profile, kind)
	}
}
