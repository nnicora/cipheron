//go:build linux || darwin

package client

// retry_test.go — ops review 2026-11-13 item 23 / D-V: WithRetry.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nnicora/cipheron/cipherontest"
	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// flaky stands between the client and its connections: it answers queued faults in place of the server's answers.
// With forward set, the request reaches the server first (it executes it) and only its answer is replaced: an answer
// lost after the execution.
type flaky struct {
	mu      sync.Mutex
	faults  []error
	forward bool
	nonces  [][]byte
	ids     []string
	calls   map[string]int
}

type flakyRPC struct {
	rpc

	f *flaky
}

// install puts f between c and every connection of c's pool.
func (f *flaky) install(c *Client) {
	f.calls = map[string]int{}
	for i, r := range c.rpcs {
		c.rpcs[i] = &flakyRPC{rpc: r, f: f}
	}
}

// fault records the attempt and returns the next queued fault (nil: serve).
func (f *flaky) fault(ctx context.Context, op string, nonce []byte) (error, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[op]++
	f.nonces = append(f.nonces, bytes.Clone(nonce))
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		f.ids = append(f.ids, strings.Join(md.Get(transport.RequestIDMetadataKey), ","))
	} else {
		f.ids = append(f.ids, "")
	}
	if len(f.faults) == 0 {
		return nil, false
	}
	err := f.faults[0]
	f.faults = f.faults[1:]
	return err, f.forward
}

func (f *flaky) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func flakyCall[Req interface{ GetRequestNonce() []byte }, Resp any](ctx context.Context, f *flaky, op string, r Req,
	call func(context.Context, Req) (Resp, error)) (Resp, error) {
	err, forward := f.fault(ctx, op, r.GetRequestNonce())
	if err == nil {
		return call(ctx, r)
	}
	var zero Resp
	if forward {
		_, _ = call(ctx, r)
	}
	return zero, err
}

func (r *flakyRPC) PublicKey(ctx context.Context, q *cipheronv1.PublicKeyRequest) (*cipheronv1.PublicKeyResponse, error) {
	return flakyCall(ctx, r.f, "PublicKey", q, r.rpc.PublicKey)
}
func (r *flakyRPC) Encrypt(ctx context.Context, q *cipheronv1.EncryptRequest) (*cipheronv1.EncryptResponse, error) {
	return flakyCall(ctx, r.f, "Encrypt", q, r.rpc.Encrypt)
}
func (r *flakyRPC) Decrypt(ctx context.Context, q *cipheronv1.DecryptRequest) (*cipheronv1.DecryptResponse, error) {
	return flakyCall(ctx, r.f, "Decrypt", q, r.rpc.Decrypt)
}
func (r *flakyRPC) Sign(ctx context.Context, q *cipheronv1.SignRequest) (*cipheronv1.SignResponse, error) {
	return flakyCall(ctx, r.f, "Sign", q, r.rpc.Sign)
}
func (r *flakyRPC) ReEncrypt(ctx context.Context, q *cipheronv1.ReEncryptRequest) (*cipheronv1.ReEncryptResponse, error) {
	return flakyCall(ctx, r.f, "ReEncrypt", q, r.rpc.ReEncrypt)
}
func (r *flakyRPC) CreateTenantKey(ctx context.Context, q *cipheronv1.CreateTenantKeyRequest) (*cipheronv1.CreateTenantKeyResponse, error) {
	return flakyCall(ctx, r.f, "CreateTenantKey", q, r.rpc.CreateTenantKey)
}
func (r *flakyRPC) RewrapTenantKey(ctx context.Context, q *cipheronv1.RewrapTenantKeyRequest) (*cipheronv1.RewrapTenantKeyResponse, error) {
	return flakyCall(ctx, r.f, "RewrapTenantKey", q, r.rpc.RewrapTenantKey)
}
func (r *flakyRPC) EncryptBatch(ctx context.Context, q *cipheronv1.EncryptBatchRequest) (*cipheronv1.EncryptBatchResponse, error) {
	return flakyCall(ctx, r.f, "EncryptBatch", q, r.rpc.EncryptBatch)
}
func (r *flakyRPC) DecryptBatch(ctx context.Context, q *cipheronv1.DecryptBatchRequest) (*cipheronv1.DecryptBatchResponse, error) {
	return flakyCall(ctx, r.f, "DecryptBatch", q, r.rpc.DecryptBatch)
}
func (r *flakyRPC) RewrapTenantKeyBatch(ctx context.Context, q *cipheronv1.RewrapTenantKeyBatchRequest) (*cipheronv1.RewrapTenantKeyBatchResponse, error) {
	return flakyCall(ctx, r.f, "RewrapTenantKeyBatch", q, r.rpc.RewrapTenantKeyBatch)
}

// refusal is a status with cipheron's ErrorInfo reason (none when "") and a RetryInfo of delay (none when < 0).
func refusal(code codes.Code, reason string, delay time.Duration) error {
	st := status.New(code, "refused")
	var details []protoadapt.MessageV1
	if reason != "" {
		details = append(details, &errdetails.ErrorInfo{Reason: reason, Domain: transport.ErrorDomain})
	}
	if delay >= 0 {
		details = append(details, &errdetails.RetryInfo{RetryDelay: durationpb.New(delay)})
	}
	if len(details) > 0 {
		var err error
		if st, err = st.WithDetails(details...); err != nil {
			panic(err)
		}
	}
	return st.Err()
}

// fastRetry is a policy whose waits are short.
var fastRetry = RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: 500 * time.Millisecond}

// retryFake is a fake requiring a request key of its own for "docs", and a client of it with opts and that key.
func retryFake(t *testing.T, perTenant bool, opts ...Option) (*cipherontest.Server, *Client, *flaky, *observed) {
	t.Helper()
	fake := cipherontest.New(t, "docs")
	if perTenant {
		fake.MakePerTenant("docs")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake.RequireRequestKey("docs", pub)
	var obs observed
	c := dialFake(t, fake, false, append([]Option{WithRequestKey(priv), WithObserver(obs.f),
		WithProfileFingerprint("docs", fake.Fingerprint("docs"))}, opts...)...)
	f := &flaky{}
	f.install(c)
	return fake, c, f, &obs
}

// TestRetryIsOffByDefault: without WithRetry a transient refusal is the call's answer, after one attempt.
func TestRetryIsOffByDefault(t *testing.T) {
	ctx := ctxT(t)
	_, c, f, obs := retryFake(t, false)
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	f.faults = []error{refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("%v; want the busy refusal", err)
	}
	if n := f.count("Encrypt"); n != 1 || obs.count("docs/"+KindRetry) != 0 {
		t.Fatalf("%d attempts, %v; want 1 and no retry", n, obs.got)
	}
}

// TestRetryRetriesTheTransientRefusals: each listed refusal is retried — a fresh request each time (the fake, which
// checks every request's signature and refuses a nonce seen twice, executed the first attempt too), under one request
// id — and the observer is told KindRetry.
func TestRetryRetriesTheTransientRefusals(t *testing.T) {
	for name, fault := range map[string]error{
		"busy":              refusal(codes.ResourceExhausted, transport.ReasonBusy, 0),
		"audit unavailable": refusal(codes.Unavailable, transport.ReasonAuditUnavailable, 0),
		"profile sealed":    refusal(codes.Unavailable, transport.ReasonProfileSealed, time.Millisecond),
		"no writer":         refusal(codes.Unavailable, transport.ReasonNoWriter, -1),
		"starting":          refusal(codes.Unavailable, transport.ReasonStarting, 0), // afterStart, then the policy
		"transport loss":    status.Error(codes.Unavailable, "connection reset"),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := ctxT(t)
			fake, c, f, obs := retryFake(t, false, WithRetry(fastRetry))
			if _, err := c.Keys(ctx, "docs"); err != nil {
				t.Fatal(err)
			}
			v0, _, refused0 := fake.Auth()
			f.forward = true
			f.faults = []error{fault, fault}
			ct, err := c.Encrypt(ctx, "docs", []byte("p"))
			if err != nil {
				t.Fatalf("after two transient refusals: %v", err)
			}
			if pt, err := c.Decrypt(ctx, "docs", ct); err != nil || string(pt) != "p" {
				t.Fatalf("decrypt: %q %v", pt, err)
			}
			if n := f.count("Encrypt"); n != 3 {
				t.Fatalf("%d attempts; want 3", n)
			}
			verified, _, refused := fake.Auth()
			if verified-v0 != 4 || refused != refused0 { // three Encrypts and the Decrypt
				t.Fatalf("the server verified %d requests and refused %d: every attempt must be a fresh, signed request",
					verified-v0, refused-refused0)
			}
			f.mu.Lock()
			nonces, ids := f.nonces[1:4], f.ids[1:4] // after the Keys fetch
			f.mu.Unlock()
			if bytes.Equal(nonces[0], nonces[1]) || bytes.Equal(nonces[1], nonces[2]) || bytes.Equal(nonces[0], nonces[2]) {
				t.Fatal("an attempt reused a nonce")
			}
			if ids[0] == "" || ids[0] != ids[1] || ids[1] != ids[2] {
				t.Fatalf("request ids %q: one per call, the same on every attempt", ids)
			}
			if n := obs.count("docs/" + KindRetry); n != 2 {
				t.Fatalf("the observer was told %d retries; want 2", n)
			}
		})
	}
}

// TestRetryReEncryptAcross: the cross-profile ReEncrypt is retried as ReEncrypt is — each attempt a fresh request,
// signed again for both profiles (the fake, which checks both signatures and refuses a nonce seen twice, executed every
// attempt), under one request id — and the observer is told KindRetry for the source profile. Without WithRetry it is
// sent once and the refusal is its answer.
func TestRetryReEncryptAcross(t *testing.T) {
	for _, tc := range []struct {
		name  string
		retry bool
	}{{"off", false}, {"on", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ctxT(t)
			fake := cipherontest.New(t, "docs", "files")
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			fake.RequireRequestKey("docs", pub)
			fake.RequireRequestKey("files", pub)
			var obs observed
			opts := []Option{WithRequestKey(priv), WithObserver(obs.f),
				WithProfileFingerprint("docs", fake.Fingerprint("docs")),
				WithProfileFingerprint("files", fake.Fingerprint("files"))}
			if tc.retry {
				opts = append(opts, WithRetry(fastRetry))
			}
			c := dialFake(t, fake, false, opts...)
			f := &flaky{}
			f.install(c)
			ct, err := c.Encrypt(ctx, "docs", []byte("p"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Keys(ctx, "files"); err != nil {
				t.Fatal(err)
			}
			_, _, refused0 := fake.Auth()
			f.mu.Lock()
			before := len(f.nonces)
			f.mu.Unlock()
			f.forward = true
			busy := refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)
			f.faults = []error{busy, busy}
			moved, err := c.ReEncryptAcross(ctx, ReEncryptAcrossScope{Profile: "docs"}, ReEncryptAcrossScope{Profile: "files"}, ct)
			if !tc.retry {
				if status.Code(err) != codes.ResourceExhausted || f.count("ReEncrypt") != 1 || obs.count("docs/"+KindRetry) != 0 {
					t.Fatalf("without WithRetry: %v, %d attempts, %v; want the busy refusal after one attempt",
						err, f.count("ReEncrypt"), obs.got)
				}
				return
			}
			if err != nil {
				t.Fatalf("after two transient refusals: %v", err)
			}
			if pt, err := c.Decrypt(ctx, "files", moved); err != nil || string(pt) != "p" {
				t.Fatalf("the moved ciphertext in files: %q %v", pt, err)
			}
			if n := f.count("ReEncrypt"); n != 3 {
				t.Fatalf("%d attempts; want 3", n)
			}
			if _, _, refused := fake.Auth(); refused != refused0 {
				t.Fatalf("the server refused %d requests: every attempt must be a fresh request, signed for both profiles",
					refused-refused0)
			}
			f.mu.Lock()
			nonces, ids := f.nonces[before:before+3], f.ids[before:before+3]
			f.mu.Unlock()
			if bytes.Equal(nonces[0], nonces[1]) || bytes.Equal(nonces[1], nonces[2]) || bytes.Equal(nonces[0], nonces[2]) {
				t.Fatal("an attempt reused a nonce")
			}
			if ids[0] == "" || ids[0] != ids[1] || ids[1] != ids[2] {
				t.Fatalf("request ids %q: one per call, the same on every attempt", ids)
			}
			if n, m := obs.count("docs/"+KindRetry), obs.count("files/"+KindRetry); n != 2 || m != 0 {
				t.Fatalf("the observer was told %d retries for docs and %d for files; want 2 and 0", n, m)
			}
		})
	}
}

// TestRetryLeavesEverythingElse: what is not a listed transient refusal is answered after one attempt.
func TestRetryLeavesEverythingElse(t *testing.T) {
	for name, fault := range map[string]error{
		"permission":          status.Error(codes.PermissionDenied, "permission denied"),
		"invalid argument":    status.Error(codes.InvalidArgument, "could not be decrypted"),
		"key version":         refusal(codes.InvalidArgument, transport.ReasonKeyVersionUnavailable, -1),
		"failed precondition": status.Error(codes.FailedPrecondition, "a precondition"),
		"message too large":   status.Error(codes.ResourceExhausted, "grpc: received message larger than max"),
		"an unknown reason":   refusal(codes.Unavailable, "CIPHERON_SOMETHING_NEW", 0),
		"internal":            status.Error(codes.Internal, "internal error"),
		"unimplemented":       status.Error(codes.Unimplemented, "unknown method"),
		"deadline":            status.Error(codes.DeadlineExceeded, "deadline"),
		"retry info too far":  refusal(codes.ResourceExhausted, transport.ReasonBusy, time.Minute),
		"closed":              ErrClosed,
		"identity":            identityFailure(errors.New("x")),
		"context digest":      ErrContextDigest,
		"busy, but identity":  identityFailure(refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := ctxT(t)
			_, c, f, obs := retryFake(t, false, WithRetry(fastRetry))
			if _, err := c.Keys(ctx, "docs"); err != nil {
				t.Fatal(err)
			}
			f.faults = []error{fault, fault, fault}
			if _, err := c.Encrypt(ctx, "docs", []byte("p")); err == nil {
				t.Fatal("served")
			}
			if n := f.count("Encrypt"); n != 1 || obs.count("docs/"+KindRetry) != 0 {
				t.Fatalf("%d attempts; want 1", n)
			}
		})
	}
}

// TestRetryHonoursRetryInfoAndTheDeadline: the wait is at least the RetryInfo; a wait the call's deadline cannot
// hold is not made.
func TestRetryHonoursRetryInfoAndTheDeadline(t *testing.T) {
	ctx := ctxT(t)
	_, c, f, _ := retryFake(t, false, WithRetry(fastRetry))
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	f.faults = []error{refusal(codes.ResourceExhausted, transport.ReasonBusy, 150*time.Millisecond)}
	start := time.Now()
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 150*time.Millisecond {
		t.Fatalf("retried after %s; RetryInfo said 150ms", waited)
	}

	f.faults = []error{refusal(codes.ResourceExhausted, transport.ReasonBusy, 300*time.Millisecond)}
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err := c.Encrypt(short, "docs", []byte("p"))
	if status.Code(err) != codes.ResourceExhausted || time.Since(start) > 90*time.Millisecond {
		t.Fatalf("%v after %s; want the busy refusal at once (the deadline cannot hold the wait)", err, time.Since(start))
	}
	if n := f.count("Encrypt"); n != 3 {
		t.Fatalf("%d Encrypt attempts in all; want 3 (2, then 1)", n)
	}
	// The attempts are bounded: a refusal that lasts is answered after MaxAttempts.
	busy := refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)
	f.faults = []error{busy, busy, busy, busy, busy}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("%v; want the busy refusal", err)
	}
	if n := f.count("Encrypt"); n != 6 {
		t.Fatalf("%d attempts in all; want 6 (3 more)", n)
	}
	f.mu.Lock()
	ids := f.ids[len(f.ids)-3:]
	f.mu.Unlock()
	if ids[0] == "" || ids[0] != ids[1] || ids[1] != ids[2] {
		t.Fatalf("request ids %q: the call's one id on every attempt", ids)
	}
}

// TestRetryNeverResendsWhatMints: CreateTenantKey, RewrapTenantKey and RewrapTenantKeyBatch are sent once, whatever
// the refusal.
func TestRetryNeverResendsWhatMints(t *testing.T) {
	ctx := ctxT(t)
	_, c, f, _ := retryFake(t, true, WithRetry(fastRetry))
	tk, err := c.CreateTenantKey(ctx, "docs", "t1")
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []error{refusal(codes.ResourceExhausted, transport.ReasonBusy, 0),
		status.Error(codes.Unavailable, "connection reset"), refusal(codes.Unavailable, transport.ReasonNoWriter, -1)} {
		f.faults = []error{fault, fault}
		before := f.count("CreateTenantKey")
		if _, err := c.CreateTenantKey(ctx, "docs", "t2"); err == nil || f.count("CreateTenantKey") != before+1 {
			t.Fatalf("CreateTenantKey: %v, %d attempts", err, f.count("CreateTenantKey")-before)
		}
		f.faults = []error{fault, fault}
		before = f.count("RewrapTenantKey")
		if _, err := c.RewrapTenantKey(ctx, "docs", "t1", tk.Blob); err == nil || f.count("RewrapTenantKey") != before+1 {
			t.Fatalf("RewrapTenantKey: %v, %d attempts", err, f.count("RewrapTenantKey")-before)
		}
		f.faults = []error{fault, fault}
		before = f.count("RewrapTenantKeyBatch")
		_, err := c.RewrapTenantKeyBatch(ctx, "docs", []TenantKeyRef{{Tenant: "t1", Blob: tk.Blob}})
		if err == nil || f.count("RewrapTenantKeyBatch") != before+1 {
			t.Fatalf("RewrapTenantKeyBatch: %v, %d attempts", err, f.count("RewrapTenantKeyBatch")-before)
		}
		f.faults = nil
	}
	// A tenant's Encrypt is idempotent: retried.
	f.faults = []error{refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)}
	if _, err := c.Tenant("docs", "t1", tk.Blob).Encrypt(ctx, []byte("p")); err != nil {
		t.Fatalf("a tenant's Encrypt: %v", err)
	}
}

// TestRetryPerBatch: a batch, and an object's batches, are retried each on its own; the object reads back whole.
func TestRetryPerBatch(t *testing.T) {
	ctx := ctxT(t)
	_, c, f, _ := retryFake(t, false, WithRetry(fastRetry))
	busy := refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)
	f.faults = []error{busy}
	if _, err := c.EncryptBatch(ctx, "docs", []BatchItem{{Data: []byte("a")}, {Data: []byte("b")}}); err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("x"), 3*transport.MinSegmentSize+7)
	f.faults = []error{busy}
	obj, err := c.EncryptObject(ctx, "docs", plain, WithSegmentSize(transport.MinSegmentSize))
	if err != nil {
		t.Fatal(err)
	}
	f.faults = []error{status.Error(codes.Unavailable, "connection reset")}
	got, err := c.DecryptObject(ctx, "docs", obj)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("decrypt object: %v", err)
	}
}

// TestRetryKeyFetch: the key fetch is retried, each attempt with a nonce of its own (keys_signature verifies over the
// last one).
func TestRetryKeyFetch(t *testing.T) {
	ctx := ctxT(t)
	_, c, f, _ := retryFake(t, false, WithRetry(fastRetry))
	f.forward = true
	f.faults = []error{refusal(codes.Unavailable, transport.ReasonProfileSealed, time.Millisecond)}
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("PublicKey"); n != 2 {
		t.Fatalf("%d fetches; want 2", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Equal(f.nonces[0], f.nonces[1]) {
		t.Fatal("the second fetch reused the first's nonce")
	}
}

// TestCloseEndsARetryWait: Close ends a wait between attempts at once.
func TestCloseEndsARetryWait(t *testing.T) {
	ctx := ctxT(t)
	_, c, f, _ := retryFake(t, false, WithRetry(RetryPolicy{MaxAttempts: 3, InitialBackoff: 20 * time.Second,
		MaxBackoff: 20 * time.Second}))
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	f.faults = []error{refusal(codes.ResourceExhausted, transport.ReasonBusy, 0)}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = c.Close()
	}()
	start := time.Now()
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}

// TestWithRetryRefuses: the policy's bounds, and two policies.
func TestWithRetryRefuses(t *testing.T) {
	for name, opt := range map[string]Option{
		"one attempt":         WithRetry(RetryPolicy{MaxAttempts: 1}),
		"too many attempts":   WithRetry(RetryPolicy{MaxAttempts: MaxRetryAttempts + 1}),
		"backoff over max":    WithRetry(RetryPolicy{InitialBackoff: time.Second, MaxBackoff: time.Millisecond}),
		"max backoff too far": WithRetry(RetryPolicy{MaxBackoff: time.Hour}),
		"negative":            WithRetry(RetryPolicy{InitialBackoff: -time.Second}),
		"two policies": func(o *options) {
			WithRetry(RetryPolicy{})(o)
			WithRetry(RetryPolicy{MaxAttempts: 5})(o)
		},
	} {
		var o options
		opt(&o)
		if len(o.errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	var o options
	WithRetry(RetryPolicy{})(&o)
	WithRetry(RetryPolicy{MaxAttempts: DefaultRetryAttempts})(&o)
	if len(o.errs) != 0 || *o.retry != (RetryPolicy{MaxAttempts: DefaultRetryAttempts, InitialBackoff: DefaultInitialBackoff,
		MaxBackoff: DefaultMaxBackoff}) {
		t.Fatalf("defaults: %+v %v", o.retry, o.errs)
	}
}

// TestRetryAgainstTheServersOwnBusy: the fake's own busy answer (RetryInfo of a second, as cipheron's) is retried no
// sooner than it says, and the call's error carries its one request id.
func TestRetryAgainstTheServersOwnBusy(t *testing.T) {
	ctx := ctxT(t)
	fake, c, _, obs := retryFake(t, false, WithRetry(RetryPolicy{MaxAttempts: 2, MaxBackoff: 2 * time.Second}))
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.Fail(cipherontest.Busy)
	start := time.Now()
	_, err := c.Encrypt(ctx, "docs", []byte("p"))
	if status.Code(err) != codes.ResourceExhausted || RequestIDOf(err) == "" {
		t.Fatalf("%v (request id %q); want the busy refusal with the call's id", err, RequestIDOf(err))
	}
	if waited := time.Since(start); waited < cipherontest.BusyRetryDelay {
		t.Fatalf("retried after %s; the RetryInfo said %s", waited, cipherontest.BusyRetryDelay)
	}
	if n := obs.count("docs/" + KindRetry); n != 1 {
		t.Fatalf("%d retries; want 1", n)
	}
	fake.Fail(cipherontest.NoFault)
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
}
