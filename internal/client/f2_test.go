package client

// f2_test.go — the re-review fixes of the client (F2): the keys' maximum age on the monotonic clock, the fresh stamp
// only after the list is stored, Sign answers judged on a list no older than the maximum age, VerifyWithKeys refusing
// a list that is not one profile's, and the skew retry only under another version (never for CreateTenantKey or
// RewrapTenantKey).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/cipherontest"
	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// staleList makes the profile's list older than any maximum age: verified at the zero time.
func staleList(c *Client, profile string) {
	c.freshnessOf(profile).verified.Store(new(time.Time))
}

// stateIn is keyID's state in the profile's cached list ("" when it is not there).
func stateIn(c *Client, profile string, keyID []byte) transport.SigningKeyState {
	if keys, ok := c.cachedKeys(profile); ok {
		if k, ok := keys.SigningKey(keyID); ok {
			return k.State
		}
	}
	return ""
}

// TestTheMaxAgeIsMeasuredOnTheMonotonicClock (F2-1): the fresh stamp is a time.Now() reading (it carries the
// monotonic clock), and the age is measured on the Client's clock: a clock that reads earlier than the stamp — a
// wall clock stepped back, which only a clock without the monotonic reading could show — is no age a decision may
// rest on: the list is fetched again (fail closed), never treated as fresh.
func TestTheMaxAgeIsMeasuredOnTheMonotonicClock(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false, WithKeysMaxAge(MinKeysMaxAge))
	old := signedBy(t, c, "docs", []byte("old"))
	if v := c.freshnessOf("docs").verified.Load(); v == nil || !strings.Contains(v.String(), "m=") {
		t.Fatalf("the fresh stamp carries no monotonic reading: %v", v)
	}

	var mu sync.Mutex
	clock := time.Now()
	c.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}
	step := func(d time.Duration) {
		mu.Lock()
		clock = clock.Add(d)
		mu.Unlock()
	}
	fake.RotateSigning("docs")
	if _, err := c.Keys(ctx, "docs"); err != nil { // stamped at clock
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", old.KeyID)
	calls := fake.PublicKeyCalls()
	step(time.Second) // within the maximum age: the cached list decides (the revocation is not seen yet)
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); !ok || err != nil || fake.PublicKeyCalls() != calls {
		t.Fatalf("within the maximum age: %v, %v (%d PublicKey calls)", ok, err, fake.PublicKeyCalls()-calls)
	}
	step(-6 * time.Hour) // the clock steps back six hours
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("after a step back: %v, %v; want the list fetched again and ErrSigningKeyRevoked", ok, err)
	}
	if n := fake.PublicKeyCalls() - calls; n != 1 {
		t.Fatalf("after a step back: %d PublicKey calls, want 1 (the refresh)", n)
	}

	// The same clock read back before a failure stamp: a failed refresh does not hold for longer than it should.
	staleList(c, "docs")
	fake.FailPublicKey(cipherontest.Internal)
	if _, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); !errors.Is(err, ErrKeysStale) {
		t.Fatalf("a failing refresh: %v, want ErrKeysStale", err)
	}
	fake.FailPublicKey(cipherontest.NoFault)
	step(-time.Hour) // earlier than the failure: not "a failure less than a few seconds old"
	staleList(c, "docs")
	if _, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("a step back after a failure: %v, want the list fetched again", err)
	}
}

// TestTheFreshStampFollowsTheStore (F2-2): fetchKeys stamps the list fresh only after the merged list is stored.
// Deterministic: the clock reading that becomes the stamp is taken when the cache already holds the answer's
// revocation. Concurrent (run under -race): Verifies racing the refresh of a stale list that learns a revocation
// never answer (true, nil) under the revoked key.
func TestTheFreshStampFollowsTheStore(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	old := signedBy(t, c, "docs", []byte("old"))
	fake.RotateSigning("docs")
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", old.KeyID)

	var mu sync.Mutex
	revokedAt := map[time.Time]bool{} // every clock reading → whether the cache held the revocation when it was taken
	base, n := time.Now(), 0
	c.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		now := base.Add(time.Duration(n) * time.Millisecond)
		revokedAt[now] = stateIn(c, "docs", old.KeyID) == transport.SigningKeyRevoked
		return now
	}
	staleList(c, "docs")
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("the refreshed list: %v, %v; want ErrSigningKeyRevoked", ok, err)
	}
	stamp := c.freshnessOf("docs").verified.Load()
	mu.Lock()
	held, ok := revokedAt[*stamp]
	mu.Unlock()
	if !ok || !held {
		t.Fatalf("the list was stamped fresh (reading found: %v) before the list with the revocation was stored", ok)
	}

	for round := range 10 {
		fake.UnrevokeSigning("docs", old.KeyID)
		r := dialFake(t, fake, false)
		if _, err := r.Keys(ctx, "docs"); err != nil {
			t.Fatal(err)
		}
		fake.RevokeSigning("docs", old.KeyID)
		staleList(r, "docs")
		var wg sync.WaitGroup
		var accepted atomic.Int64
		for range 8 {
			wg.Go(func() {
				if ok, err := r.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); ok && err == nil {
					accepted.Add(1)
				}
			})
		}
		wg.Wait()
		if a := accepted.Load(); a != 0 {
			t.Fatalf("round %d: %d Verifies racing the refresh accepted a revoked key", round, a)
		}
		_ = r.Close()
	}
}

// TestASignAnswerIsJudgedOnAFreshList (F2-3): a replica that still signs with a key revoked since this Client's list
// was fetched. Within the maximum age the cached list decides (a verify-only key is accepted: the documented limit);
// past it the list is fetched again first and the answer refused (ErrSigningKeyRevoked); a list that cannot be
// fetched again is ErrKeysStale, and no signature is returned.
func TestASignAnswerIsJudgedOnAFreshList(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	old := signedBy(t, c, "docs", []byte("old"))
	fake.RotateSigning("docs")
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", old.KeyID)
	fake.SetMode(cipherontest.SignRevoked)
	defer fake.SetMode(cipherontest.Honest)

	if s, err := c.Sign(ctx, "docs", []byte("d")); err != nil || !transport.SameKeyID(s.KeyID, old.KeyID) {
		t.Fatalf("within the maximum age, the cached list (old verify-only): %v (key %x)", err, s.KeyID)
	}
	calls := fake.PublicKeyCalls()
	staleList(c, "docs")
	if s, err := c.Sign(ctx, "docs", []byte("d")); !errors.Is(err, ErrSigningKeyRevoked) || s.Bytes != nil {
		t.Fatalf("past the maximum age: %v; want the list fetched again and ErrSigningKeyRevoked", err)
	}
	if n := fake.PublicKeyCalls() - calls; n != 1 {
		t.Fatalf("past the maximum age: %d PublicKey calls, want 1", n)
	}

	// Another Client, whose list does not know the revocation, with cipheron unable to answer PublicKey.
	fake.SetMode(cipherontest.Honest)
	fake.UnrevokeSigning("docs", old.KeyID)
	other := dialFake(t, fake, false)
	if _, err := other.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", old.KeyID)
	fake.SetMode(cipherontest.SignRevoked)
	staleList(other, "docs")
	fake.FailPublicKey(cipherontest.Internal)
	defer fake.FailPublicKey(cipherontest.NoFault)
	if s, err := other.Sign(ctx, "docs", []byte("d")); !errors.Is(err, ErrKeysStale) || s.Bytes != nil {
		t.Fatalf("a stale list that cannot be fetched again: %v; want ErrKeysStale and no signature", err)
	}
}

// TestVerifyWithKeysRefusesAListThatIsNotOneProfiles (F2-4): a key id listed twice (an older list joined with a newer
// one, in either order) or an id that is not its key's is ErrInvalidKeyList, whatever key id is asked about —
// never (true, nil) under a key one of the lists revokes.
func TestVerifyWithKeysRefusesAListThatIsNotOneProfiles(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	old := signedBy(t, c, "docs", []byte("old"))
	fake.RotateSigning("docs")
	before, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", old.KeyID)
	after, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyWithKeys(before.SigningKeys, []byte("old"), old.Bytes, old.KeyID); !ok || err != nil {
		t.Fatalf("the older list alone: %v, %v", ok, err)
	}
	if ok, err := VerifyWithKeys(after.SigningKeys, []byte("old"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("the newer list alone: %v, %v", ok, err)
	}
	joined := map[string][]transport.SigningKey{
		"old ++ new": append(cloneKeys(before.SigningKeys), cloneKeys(after.SigningKeys)...),
		"new ++ old": append(cloneKeys(after.SigningKeys), cloneKeys(before.SigningKeys)...),
	}
	active, _ := after.Active()
	for name, keys := range joined {
		for _, id := range [][]byte{old.KeyID, active.KeyID, make([]byte, transport.SigningKeyIDLen)} {
			if ok, err := VerifyWithKeys(keys, []byte("old"), old.Bytes, id); ok || !errors.Is(err, ErrInvalidKeyList) {
				t.Errorf("%s, key %x: %v, %v; want ErrInvalidKeyList", name, id, ok, err)
			}
			if ok, err := VerifyTenantWithKeys(keys, "docs", "t_1", []byte("old"), old.Bytes, id); ok || !errors.Is(err, ErrInvalidKeyList) {
				t.Errorf("%s (tenant), key %x: %v, %v; want ErrInvalidKeyList", name, id, ok, err)
			}
		}
	}
	mislabelled := cloneKeys(before.SigningKeys)
	for i := range mislabelled {
		if transport.SameKeyID(mislabelled[i].KeyID, active.KeyID) {
			mislabelled[i].PublicKey = cloneKeys(before.SigningKeys)[(i+1)%len(mislabelled)].PublicKey
		}
	}
	if ok, err := VerifyWithKeys(mislabelled, []byte("old"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrInvalidKeyList) {
		t.Fatalf("a key under another key's id: %v, %v; want ErrInvalidKeyList", ok, err)
	}
}

// forgeTap wraps a Client's transport: it counts the operations that reached cipheron and, while forge is set,
// answers an operation cipheron EXECUTED with a forged refusal in place of its answer (a party in the path that holds
// the connection).
type forgeTap struct {
	rpc

	n *forgeCounts
}

type forgeCounts struct {
	forge                                atomic.Bool
	encrypts, decrypts, creates, rewraps atomic.Int64
}

// forgedRefusal is the refusal forgeTap answers: FAILED_PRECONDITION, which no operation is sent again for.
func forgedRefusal() error {
	return status.Error(codes.FailedPrecondition, "a refusal forged after cipheron executed the request")
}

func (s forgeTap) Encrypt(ctx context.Context, r *cipheronv1.EncryptRequest) (*cipheronv1.EncryptResponse, error) {
	resp, err := s.rpc.Encrypt(ctx, r)
	s.n.encrypts.Add(1)
	if err == nil && s.n.forge.Load() {
		return nil, forgedRefusal()
	}
	return resp, err
}

func (s forgeTap) Decrypt(ctx context.Context, r *cipheronv1.DecryptRequest) (*cipheronv1.DecryptResponse, error) {
	resp, err := s.rpc.Decrypt(ctx, r)
	s.n.decrypts.Add(1)
	if err == nil && s.n.forge.Load() {
		return nil, forgedRefusal()
	}
	return resp, err
}

func (s forgeTap) CreateTenantKey(ctx context.Context, r *cipheronv1.CreateTenantKeyRequest) (*cipheronv1.CreateTenantKeyResponse, error) {
	resp, err := s.rpc.CreateTenantKey(ctx, r)
	s.n.creates.Add(1)
	if err == nil && s.n.forge.Load() {
		return nil, forgedRefusal()
	}
	return resp, err
}

func (s forgeTap) RewrapTenantKey(ctx context.Context, r *cipheronv1.RewrapTenantKeyRequest) (*cipheronv1.RewrapTenantKeyResponse, error) {
	resp, err := s.rpc.RewrapTenantKey(ctx, r)
	s.n.rewraps.Add(1)
	if err == nil && s.n.forge.Load() {
		return nil, forgedRefusal()
	}
	return resp, err
}

// tap installs a forgeTap on every connection of c.
func tap(c *Client) *forgeCounts {
	n := new(forgeCounts)
	for i := range c.rpcs {
		c.rpcs[i] = forgeTap{rpc: c.rpcs[i], n: n}
	}
	return n
}

// TestAForgedRefusalIsNeverSentAgain (F2-5): a refusal a party in the path forges after cipheron EXECUTED an
// Encrypt or a Decrypt is answered to the caller as it is — with the status in the chain — and the request executed
// once: the client never sends it again by itself, and fetches nothing for it.
func TestAForgedRefusalIsNeverSentAgain(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	n := tap(c)
	ct, err := c.Encrypt(ctx, "docs", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	n.encrypts.Store(0)
	calls := fake.PublicKeyCalls()
	n.forge.Store(true)
	defer n.forge.Store(false)
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Encrypt, a forged refusal: %v, want it answered", err)
	}
	if _, err := c.Decrypt(ctx, "docs", ct); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Decrypt, a forged refusal: %v, want it answered", err)
	}
	if e, d := n.encrypts.Load(), n.decrypts.Load(); e != 1 || d != 1 {
		t.Fatalf("a forged refusal: %d Encrypt and %d Decrypt executions, want 1 each", e, d)
	}
	if got := fake.PublicKeyCalls() - calls; got != 0 {
		t.Fatalf("a forged refusal: %d PublicKey calls, want none", got)
	}
}

// TestTenantKeyCallsAreNeverRetried (F2-5): CreateTenantKey and RewrapTenantKey are never sent again by the client
// after a refusal forged once cipheron executed them: one execution each, the refusal answered, and the caller's own
// retry served.
func TestTenantKeyCallsAreNeverRetried(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	c := dialFake(t, fake, false)
	n := tap(c)
	blob, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	n.creates.Store(0)
	n.forge.Store(true)
	if _, err := c.CreateTenantKey(ctx, "docs", "t_3"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CreateTenantKey, a forged refusal: %v", err)
	}
	if _, err := c.RewrapTenantKey(ctx, "docs", "t_1", blob.Blob); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RewrapTenantKey, a forged refusal: %v", err)
	}
	n.forge.Store(false)
	if cr, rw := n.creates.Load(), n.rewraps.Load(); cr != 1 || rw != 1 {
		t.Fatalf("a forged refusal: %d CreateTenantKey and %d RewrapTenantKey executions, want 1 each", cr, rw)
	}
	if _, err := c.CreateTenantKey(ctx, "docs", "t_3"); err != nil {
		t.Fatalf("the caller's own retry: %v", err)
	}
}
