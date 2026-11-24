//go:build linux || darwin

package client

// startretry_test.go — owner decision S28: a call cipheron refused as signed before its process started
// (CIPHERON_STARTING) is signed again and sent once more, with or without WithRetry, whatever the operation.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nnicora/cipheron/wire/transport"
)

// TestAStartRefusalIsSignedAgainAndSentOnceMore: the fake restarted as a process whose start is 40 ms ahead of the
// client's clock (a caller whose clock lags). Every operation's first attempt is refused with CIPHERON_STARTING and a
// RetryInfo; the client waits it, signs the call again (another nonce, the same request id) and sends it once more
// — CreateTenantKey, RewrapTenantKey and RewrapTenantKeyBatch too, though nothing else ever resends them: the refusal
// says nothing ran. The observer is told KindRetry.
func TestAStartRefusalIsSignedAgainAndSentOnceMore(t *testing.T) {
	ctx := ctxT(t)
	fake, c, f, obs := retryFake(t, true) // no WithRetry
	tk, err := c.CreateTenantKey(ctx, "docs", "t1")
	if err != nil {
		t.Fatal(err)
	}
	calls := []struct {
		op   string
		call func() error
	}{
		{"CreateTenantKey", func() error { _, err := c.CreateTenantKey(ctx, "docs", "t2"); return err }},
		{"RewrapTenantKey", func() error { _, err := c.RewrapTenantKey(ctx, "docs", "t1", tk.Blob); return err }},
		{"RewrapTenantKeyBatch", func() error {
			_, err := c.RewrapTenantKeyBatch(ctx, "docs", []TenantKeyRef{{Tenant: "t1", Blob: tk.Blob}})
			return err
		}},
		{"Encrypt", func() error { _, err := c.Tenant("docs", "t1", tk.Blob).Encrypt(ctx, []byte("p")); return err }},
	}
	for _, tc := range calls {
		fake.Restart(time.Now().Add(40 * time.Millisecond))
		before, retries := f.count(tc.op), obs.count("docs/"+KindRetry)
		v0, _, refused0 := fake.Auth()
		f.mu.Lock()
		n0 := len(f.nonces)
		f.mu.Unlock()
		t0 := time.Now()
		if err := tc.call(); err != nil {
			t.Fatalf("%s after a start refusal: %v", tc.op, err)
		}
		if n := f.count(tc.op) - before; n != 2 {
			t.Fatalf("%s: %d attempts; want 2", tc.op, n)
		}
		if el := time.Since(t0); el < 35*time.Millisecond {
			t.Fatalf("%s: sent again after %v; want the RetryInfo (about 40ms) waited", tc.op, el)
		}
		if verified, _, refused := fake.Auth(); verified-v0 != 1 || refused != refused0 {
			t.Fatalf("%s: %d verified, %d refused; want one execution (the start refusal is neither)", tc.op,
				verified-v0, refused-refused0)
		}
		f.mu.Lock()
		nonces, ids := f.nonces[n0:], f.ids[n0:]
		f.mu.Unlock()
		if len(nonces) != 2 || bytes.Equal(nonces[0], nonces[1]) {
			t.Fatalf("%s: the second attempt reused the nonce", tc.op)
		}
		if ids[0] == "" || ids[0] != ids[1] {
			t.Fatalf("%s: request ids %q; want the call's one id on both attempts", tc.op, ids)
		}
		if n := obs.count("docs/"+KindRetry) - retries; n != 1 {
			t.Fatalf("%s: the observer was told %d retries; want 1", tc.op, n)
		}
	}
}

// TestAStartRefusalIsSentOnceMoreOnly: without WithRetry a second start refusal is the call's answer (two attempts);
// a RetryInfo beyond MaxStartingWait is answered at once (one attempt, no wait); and every other UNAVAILABLE is not
// sent again.
func TestAStartRefusalIsSentOnceMoreOnly(t *testing.T) {
	ctx := ctxT(t)
	fake, c, f, _ := retryFake(t, false)
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	starting := refusal(codes.Unavailable, transport.ReasonStarting, time.Millisecond)
	f.faults = []error{starting, starting, starting}
	before := f.count("Encrypt")
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); status.Code(err) != codes.Unavailable {
		t.Fatalf("two start refusals: %v; want the second one answered", err)
	}
	if n := f.count("Encrypt") - before; n != 2 {
		t.Fatalf("two start refusals: %d attempts; want 2", n)
	}
	f.faults = nil

	fake.Restart(time.Now().Add(5 * time.Second))
	before = f.count("Encrypt")
	t0 := time.Now()
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); status.Code(err) != codes.Unavailable {
		t.Fatalf("a start refusal 5s ahead: %v; want it answered", err)
	}
	if n := f.count("Encrypt") - before; n != 1 || time.Since(t0) > time.Second {
		t.Fatalf("a start refusal beyond MaxStartingWait: %d attempts after %v; want 1, at once", n, time.Since(t0))
	}
	fake.Restart(time.Now().Add(-time.Second))

	for _, other := range []error{refusal(codes.Unavailable, transport.ReasonNoWriter, -1),
		refusal(codes.Unavailable, "CIPHERON_SOMETHING_ELSE", time.Millisecond)} {
		f.faults = []error{other}
		before = f.count("Encrypt")
		if _, err := c.Encrypt(ctx, "docs", []byte("p")); err == nil || f.count("Encrypt")-before != 1 {
			t.Fatalf("%v: %d attempts; want 1", other, f.count("Encrypt")-before)
		}
	}
}

// TestAStartRefusalIsNotSentAgainOutsideItsBounds: a start refusal whose RetryInfo does not fit in the call's
// deadline is the call's answer at once — one attempt, no retry told, no wait — and an ErrorInfo of reason
// CIPHERON_STARTING under a domain other than cipheron's (transport.ErrorDomain) is not cipheron's start refusal: it
// is not sent again.
func TestAStartRefusalIsNotSentAgainOutsideItsBounds(t *testing.T) {
	_, c, f, obs := retryFake(t, false)
	if _, err := c.Keys(ctxT(t), "docs"); err != nil {
		t.Fatal(err)
	}
	starting := refusal(codes.Unavailable, transport.ReasonStarting, 500*time.Millisecond)
	f.faults = []error{starting, starting}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	before, retries := f.count("Encrypt"), obs.count("docs/"+KindRetry)
	t0 := time.Now()
	_, err := c.Encrypt(ctx, "docs", []byte("p"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("a start refusal beyond the deadline: %v; want it answered", err)
	}
	if n, told, el := f.count("Encrypt")-before, obs.count("docs/"+KindRetry)-retries, time.Since(t0); n != 1 ||
		told != 0 || el >= 100*time.Millisecond {
		t.Fatalf("a start refusal beyond the deadline: %d attempts, %d retries told, answered after %v; want 1, 0, at once",
			n, told, el)
	}
	f.faults = nil

	foreign, err := status.New(codes.Unavailable, "refused").WithDetails(
		&errdetails.ErrorInfo{Reason: transport.ReasonStarting, Domain: "example.com"},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	f.faults = []error{foreign.Err(), foreign.Err()}
	before = f.count("Encrypt")
	if _, err := c.Encrypt(ctxT(t), "docs", []byte("p")); err == nil || f.count("Encrypt")-before != 1 {
		t.Fatalf("CIPHERON_STARTING under another ErrorInfo domain: %v after %d attempts; want refused after 1", err,
			f.count("Encrypt")-before)
	}
}
