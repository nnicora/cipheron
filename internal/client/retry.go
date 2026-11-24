package client

// retry.go — WithRetry: the client sends an idempotent call again after a transient refusal (ops review 2026-11-13,
// item 23 / RT-5, owner decision D-V: opt-in).
//
// WHAT IS RETRIED. Only a refusal that says "not now, here": decided from the status code and cipheron's ErrorInfo
// reason (transport.Reason…), never from a message, by transport.Refusal's Classify (the conformance kit's errorClass
// table) —
//   - RESOURCE_EXHAUSTED with CIPHERON_BUSY (in-flight limits, no locked memory now). gRPC's own refusal of a message
//     over the size limit is RESOURCE_EXHAUSTED with no details: not retried (it would be refused again);
//   - UNAVAILABLE with CIPHERON_AUDIT_UNAVAILABLE, CIPHERON_PROFILE_SEALED, CIPHERON_NO_WRITER or CIPHERON_STARTING;
//   - UNAVAILABLE with no ErrorInfo: the transport lost the connection, or the replica is draining (GOAWAY) — unless
//     the connection's last attempt was refused for the server's identity (then it is ErrServerIdentity, never
//     retried).
//
// Nothing else is: ErrClosed, every error the client decides itself (ErrServerIdentity, ErrServerKeyChanged,
// ErrContextDigest, ErrPinRequired, ErrBadResponse, ErrKeysStale, ErrTenancy, ErrTenantKey,
// ErrTooLarge, ErrSigningKeyRevoked, ErrUnknownSigningKey, ...), PERMISSION_DENIED, INVALID_ARGUMENT,
// FAILED_PRECONDITION, UNIMPLEMENTED, INTERNAL, an UNAVAILABLE of a reason this client does not know, and the
// context's own end.
//
// WHICH OPERATIONS. Those whose second execution changes nothing (a fresh request each time; nothing on the server
// depends on how many were executed): PublicKey (the key fetch), Encrypt, Decrypt, ReEncrypt, Sign — the Client's and
// a Tenant's —, ReEncryptAcross (the cross-profile ReEncrypt: a second execution only makes another ciphertext of the
// target profile), and their batch forms, so the batches of the object, stream and JSON-field calls (EncryptObject,
// DecryptObject, ReEncryptObject, the three streams, the three JSON-field calls; each batch is retried on its own; a
// batch whose answer was taken, and its data written to the stream, is never sent again). NEVER CreateTenantKey, RewrapTenantKey or RewrapTenantKeyBatch: each execution makes a new key or blob, so a
// second one after a lost answer is a second effect (they are sent once). Verify sends nothing but the key fetch.
//
// HOW. At most MaxAttempts attempts in all. Each is a NEW request — a fresh request nonce, signed again (auth), sealed
// again — so cipheron's replay check never sees one twice; the next attempt goes on the pool's next connection
// (Client.pick takes them in turn, and skips a broken one), so with WithConnections > 1 or WithRoundRobin it reaches
// another connection, and another replica when there is one. Between attempts the client waits an exponential backoff
// (InitialBackoff, doubled, at most MaxBackoff) jittered to between half and all of it, and never less than the
// RetryInfo cipheron answered; a RetryInfo longer than MaxBackoff, or a wait that would pass the call's deadline,
// ends the retries and the call answers the last refusal. Close ends a wait at once.
//
// A SEALED PROFILE FAILS FAST BY DEFAULT. cipheron's answer for a profile sealed on the replica (CIPHERON_PROFILE_SEALED,
// unseal.partial) carries a RetryInfo of 5 seconds, longer than DefaultMaxBackoff (2 seconds): under the default
// policy it is not retried, and the call answers it at once. A caller that would rather wait for the unseal sets
// MaxBackoff above 5 seconds (up to MaxRetryBackoff) and gives the call a deadline that holds the wait. cipheron's
// other RetryInfo hints (CIPHERON_BUSY, CIPHERON_AUDIT_UNAVAILABLE) are 1 second, within the default.
//
// THE REQUEST ID. One per call: every attempt carries the same x-request-id (the caller's own, or one drawn once for
// the call), so the operator finds every attempt of a call under one id in cipheron's log and audit trail, and
// RequestIDOf(err) names it. The attempts are told apart there by their request nonces.
//
// THE OBSERVER. WithObserver is told KindRetry, with the call's profile (ReEncryptAcross: its source profile), before
// each attempt after the first.
//
// A REQUEST SIGNED BEFORE CIPHERON STARTED IS SENT ONCE MORE, WITH OR WITHOUT WithRetry, WHATEVER THE OPERATION
// (afterStart). A cipheron process serves nothing signed before its own start (its start barrier, against a
// request captured and replayed to a process that started after it): it answers UNAVAILABLE with
// CIPHERON_STARTING and a RetryInfo of how far the request's timestamp is before its start, having done nothing
// and recorded nothing. The client signs the call again (a fresh timestamp and nonce) and sends it once more, after
// that RetryInfo when it is at most MaxStartingWait and fits the call's deadline — CreateTenantKey, RewrapTenantKey
// and RewrapTenantKeyBatch too, since nothing ran. A second such refusal (a clock that lags cipheron's by more than
// MaxStartingWait) is the call's answer, or, under WithRetry, a transient refusal like the others.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/wire/transport"
)

// RetryPolicy is WithRetry's policy. A zero field takes its default.
type RetryPolicy struct {
	// MaxAttempts is how many attempts a call makes at most, the first included: 2 to MaxRetryAttempts
	// (DefaultRetryAttempts when 0).
	MaxAttempts int
	// InitialBackoff is the wait before the second attempt, before jitter: from MinRetryBackoff to MaxBackoff
	// (DefaultInitialBackoff when 0). Each later wait doubles it, up to MaxBackoff.
	InitialBackoff time.Duration
	// MaxBackoff is the longest wait between two attempts, and the longest RetryInfo honoured: a refusal that asks for
	// a longer wait is answered, not retried. From InitialBackoff to MaxRetryBackoff (DefaultMaxBackoff when 0). The
	// default does not wait out a sealed profile's 5-second hint: above 5 seconds, it does.
	MaxBackoff time.Duration
}

// WithRetry's bounds and defaults.
const (
	DefaultRetryAttempts  = 3
	MaxRetryAttempts      = 10
	DefaultInitialBackoff = 100 * time.Millisecond
	DefaultMaxBackoff     = 2 * time.Second
	MinRetryBackoff       = time.Millisecond
	MaxRetryBackoff       = 30 * time.Second
)

// WithRetry makes the client send an idempotent call again after a TRANSIENT refusal — cipheron busy, its audit
// trail unavailable, the profile sealed or without a writer on that replica, the connection lost or the replica
// draining — at most policy.MaxAttempts times in all, each attempt a fresh request (fresh nonce, signed again),
// waiting a jittered exponential backoff and at least the RetryInfo cipheron answered, never past the call's deadline.
// CreateTenantKey, RewrapTenantKey and RewrapTenantKeyBatch are never sent again. Off unless given; retry.go of this
// package lists exactly what is retried and what is not. Given again with another policy, the client is refused.
func WithRetry(policy RetryPolicy) Option {
	return func(o *options) {
		p, err := policy.normalized()
		switch {
		case err != nil:
			o.errs = append(o.errs, err)
		case o.retry != nil && *o.retry != p:
			o.errs = append(o.errs, errors.New("cipheron: WithRetry is given twice, with different policies; pass one"))
		default:
			o.retry = &p
		}
	}
}

// normalized is p with its defaults, or why it is refused.
func (p RetryPolicy) normalized() (RetryPolicy, error) {
	if p.MaxAttempts == 0 {
		p.MaxAttempts = DefaultRetryAttempts
	}
	if p.MaxBackoff == 0 {
		p.MaxBackoff = max(DefaultMaxBackoff, p.InitialBackoff)
	}
	if p.InitialBackoff == 0 {
		p.InitialBackoff = min(DefaultInitialBackoff, p.MaxBackoff)
	}
	switch {
	case p.MaxAttempts < 2 || p.MaxAttempts > MaxRetryAttempts:
		return p, fmt.Errorf("cipheron: WithRetry: MaxAttempts %d: from 2 to %d (the first attempt included)",
			p.MaxAttempts, MaxRetryAttempts)
	case p.MaxBackoff < MinRetryBackoff || p.MaxBackoff > MaxRetryBackoff:
		return p, fmt.Errorf("cipheron: WithRetry: MaxBackoff %s: from %s to %s", p.MaxBackoff, MinRetryBackoff, MaxRetryBackoff)
	case p.InitialBackoff < MinRetryBackoff || p.InitialBackoff > p.MaxBackoff:
		return p, fmt.Errorf("cipheron: WithRetry: InitialBackoff %s: from %s to MaxBackoff (%s)", p.InitialBackoff,
			MinRetryBackoff, p.MaxBackoff)
	}
	return p, nil
}

// MaxStartingWait is the longest RetryInfo of a CIPHERON_STARTING refusal the client waits out before it sends the
// call once more by itself (afterStart): longer, and the refusal is the call's answer.
const MaxStartingWait = time.Second

// afterStart runs attempt — one complete, fresh request — and, when cipheron refused it as signed before its
// process started (CIPHERON_STARTING), runs it once more after that refusal's RetryInfo (retry.go): nothing ran on
// the server, so a second attempt is safe for every operation. Both attempts carry the same request id. profile is the
// call's, for the observer.
func afterStart[T any](ctx context.Context, c *Client, profile string, attempt func(context.Context) (T, error)) (T, error) {
	ctx, _ = withRequestID(ctx) // one request id for both attempts
	out, err := attempt(ctx)
	wait, ok := startingWait(err)
	if !ok || wait > MaxStartingWait || c.closed.Load() {
		return out, err
	}
	if dl, has := ctx.Deadline(); has && time.Until(dl) <= wait {
		return out, err // the second attempt could not finish before the call's deadline
	}
	c.tell(profile, KindRetry)
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return out, err
		case <-c.done:
			t.Stop()
			return out, err
		case <-t.C:
		}
	}
	return attempt(ctx)
}

// startingWait reports whether err is cipheron's start barrier refusal (UNAVAILABLE with CIPHERON_STARTING:
// transport.ClassStarting), and the RetryInfo delay it carries (0: none).
func startingWait(err error) (time.Duration, bool) {
	r, delay, ok := refusalOf(err)
	if !ok {
		return 0, false
	}
	class, _ := r.Classify()
	return delay, class == transport.ClassStarting
}

// refusalOf reads err's gRPC status as transport.Refusal — its code and its last google.rpc.ErrorInfo — and the delay
// of its RetryInfo (0: none, or one that is not a valid duration); false when err carries no status.
func refusalOf(err error) (transport.Refusal, time.Duration, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return transport.Refusal{}, 0, false
	}
	r := transport.Refusal{Code: uint32(st.Code())} //nolint:gosec // a gRPC code is a small non-negative number
	var delay time.Duration
	for _, d := range st.Details() {
		switch d := d.(type) {
		case *errdetails.ErrorInfo:
			r.HasErrorInfo, r.ErrorDomain, r.Reason = true, d.GetDomain(), d.GetReason()
		case *errdetails.RetryInfo:
			if rd := d.GetRetryDelay(); rd != nil && rd.CheckValid() == nil {
				delay = max(rd.AsDuration(), 0)
			}
		}
	}
	return r, delay, true
}

// retryCall runs attempt — one complete, fresh request each time — and, under WithRetry, runs it again after a
// transient refusal (transient), as the policy says. Without WithRetry it runs it once, or twice after a start
// barrier refusal (afterStart). Every attempt carries the same request id. profile is the call's, for the observer.
func retryCall[T any](ctx context.Context, c *Client, profile string, attempt func(context.Context) (T, error)) (T, error) {
	p := c.retry
	if p == nil {
		return afterStart(ctx, c, profile, attempt)
	}
	ctx, _ = withRequestID(ctx) // one request id for every attempt of the call
	backoff := p.InitialBackoff
	for n := 1; ; n++ {
		out, err := afterStart(ctx, c, profile, attempt)
		if err == nil || n >= p.MaxAttempts || c.closed.Load() {
			return out, err
		}
		hint, ok := c.transient(err)
		if !ok || hint > p.MaxBackoff {
			return out, err
		}
		wait := max(backoff/2+rand.N(backoff/2+1), hint) //nolint:gosec // jitter, not a secret
		if dl, has := ctx.Deadline(); has && time.Until(dl) <= wait {
			return out, err // the next attempt could not finish before the call's deadline
		}
		c.tell(profile, KindRetry)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return out, err
		case <-c.done:
			t.Stop()
			return out, err
		case <-t.C:
		}
		backoff = min(2*backoff, p.MaxBackoff)
	}
}

// transient reports whether err is a refusal WithRetry sends a call again for (retry.go), and the RetryInfo delay it
// carries (0: none).
func (c *Client) transient(err error) (time.Duration, bool) {
	for _, own := range []error{ErrClosed, ErrServerIdentity, ErrServerKeyChanged, ErrContextDigest, ErrPinRequired,
		ErrBadResponse, ErrKeysStale, ErrTenancy, ErrTenantKey, ErrTooLarge, ErrSigningKeyRevoked,
		ErrUnknownSigningKey, ErrInvalidKeyList, ErrAssociatedData, transport.ErrCiphertext, context.Canceled,
		context.DeadlineExceeded} {
		if errors.Is(err, own) {
			return 0, false
		}
	}
	r, delay, ok := refusalOf(err)
	if !ok {
		return 0, false
	}
	class, rule := r.Classify()
	switch {
	case rule == transport.RetryNever:
		return 0, false
	case class == transport.ClassUnavailable:
		// The transport's loss of the connection, or a draining replica — unless the last connection attempt was
		// refused for the server's identity (finish answers that as ErrServerIdentity).
		return delay, c.id == nil || c.id.last() == nil
	}
	return delay, true
}
