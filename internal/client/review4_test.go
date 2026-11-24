package client

// review4_test.go — PublicKey answers are fresh (R4: a recorded older answer, replayed, is refused — it rolls back
// neither the active signing key nor the context digest, and a fresh client does not adopt it), and Verify's re-fetch
// throttle counts attempts, not successes (R6).

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// keysServer answers PublicKey as cipheron does — keys_signature over the request's nonce — from its current state,
// or replays a recorded answer.
type keysServer struct {
	rpc

	profile  string
	id       transport.Identity
	respPriv ed25519.PrivateKey
	keys     []transport.SigningKey
	digest   string
	replay   *cipheronv1.PublicKeyResponse // when set, answered whatever the request
	calls    atomic.Int64
	fail     atomic.Bool
}

func (s *keysServer) answer(nonce []byte) *cipheronv1.PublicKeyResponse {
	tenancy := cipheronv1.Tenancy_TENANCY_PER_TENANT_DERIVED
	if s.id.Tenancy == transport.TenancyShared {
		tenancy = cipheronv1.Tenancy_TENANCY_SHARED
	}
	tr, err := transport.SigningKeysTranscript(transport.Release(), s.profile, s.id.Tenancy, s.digest, nonce, s.keys)
	if err != nil {
		panic(err)
	}
	resp := &cipheronv1.PublicKeyResponse{HpkePublicKey: s.id.HPKE, ResponsePublicKey: s.id.Response,
		Tenancy: tenancy, ContextDigest: s.digest, KeysSignature: ed25519.Sign(s.respPriv, tr),
		HpkeSuite:            &cipheronv1.HpkeSuite{KemId: uint32(transport.KEMID), KdfId: uint32(transport.KDFID), AeadId: uint32(transport.AEADID)},
		ResponseKeyAlgorithm: cipheronv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519}
	for _, k := range s.keys {
		resp.SigningKeys = append(resp.SigningKeys, &cipheronv1.SigningKey{KeyId: k.KeyID,
			State: cipheronv1.SigningKeyState(k.State.Code()), PublicKey: k.PublicKey,
			Algorithm: cipheronv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519})
	}
	// The key statement of the same state, signed without the nonce.
	st := transport.KeyStatement{Profile: s.profile, IssuedAtMS: time.Now().UnixMilli(), ContextDigest: s.digest,
		Identity: s.id, SigningKeys: s.keys}
	raw, err := transport.MarshalKeyStatement(transport.Release(), &st)
	if err != nil {
		panic(err)
	}
	resp.KeyStatement, resp.KeyStatementSignature = raw, ed25519.Sign(s.respPriv, raw)
	return resp
}

func (s *keysServer) PublicKey(_ context.Context, r *cipheronv1.PublicKeyRequest) (*cipheronv1.PublicKeyResponse, error) {
	s.calls.Add(1)
	if s.fail.Load() {
		return nil, context.DeadlineExceeded
	}
	if len(r.GetRequestNonce()) != transport.NonceLen {
		return nil, errors.New("the client sent no fresh nonce")
	}
	if s.replay != nil {
		return s.replay, nil
	}
	return s.answer(r.GetRequestNonce()), nil
}

func (s *keysServer) Close() error { return nil }

func newKeysServer(t *testing.T, profile string) (*keysServer, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	respPub, respPriv, _ := ed25519.GenerateKey(rand.Reader)
	s1, _, _ := ed25519.GenerateKey(rand.Reader)
	s2, _, _ := ed25519.GenerateKey(rand.Reader)
	s := &keysServer{profile: profile, respPriv: respPriv,
		id: transport.Identity{Tenancy: transport.TenancyPerTenantDerived, HPKE: hk.PublicKey().Bytes(), Response: respPub}}
	s.set(t, s1, []ed25519.PublicKey{s1, s2})
	return s, s1, s2
}

// set makes active the server's active key and keys its list (the digest follows).
func (s *keysServer) set(t *testing.T, active ed25519.PublicKey, keys []ed25519.PublicKey) {
	t.Helper()
	s.keys = nil
	for _, p := range keys {
		st := transport.SigningKeyVerifyOnly
		if p.Equal(active) {
			st = transport.SigningKeyActive
		}
		s.keys = append(s.keys, transport.SigningKey{KeyID: transport.SigningKeyID(p), State: st, PublicKey: p})
	}
	transport.SortSigningKeys(s.keys)
	d, err := transport.ContextDigest(transport.KeyContext{Profile: s.profile, Tenancy: s.id.Tenancy,
		MasterVersions:    []transport.MasterVersionCheck{{ID: "v1", KCV: make([]byte, transport.KeyCheckValueLen)}},
		KeysetFingerprint: transport.Fingerprint(s.profile, s.id), SigningKeys: s.keys})
	if err != nil {
		t.Fatal(err)
	}
	s.digest = d
}

// TestAReplayedKeyListIsRefused (R4): an answer recorded before signing.active moved, replayed by a party in the
// path, verifies no longer — it was signed over another request's nonce: the client keeps its
// active key and digest (the call fails as not cipheron's), and a fresh pinned client does not adopt it.
func TestAReplayedKeyListIsRefused(t *testing.T) {
	const profile = "credentials"
	s, s1, s2 := newKeysServer(t, profile)
	fp := transport.Fingerprint(profile, s.id)
	old := s.answer(make([]byte, transport.NonceLen)) // recorded last month, for a request of its own
	s.set(t, s2, []ed25519.PublicKey{s1, s2})
	c := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20, pins: map[string]string{profile: fp}})
	ctx := context.Background()
	k, err := c.Keys(ctx, profile)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := k.Active(); !a.PublicKey.Equal(s2) || k.ContextDigest != s.digest {
		t.Fatal("not the current answer")
	}
	s.replay = old
	if _, err := c.Keys(ctx, profile); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("a replayed answer: %v", err)
	}
	cur, ok := c.cachedKeys(profile)
	if !ok {
		t.Fatal("the profile's keys are not cached")
	}
	if cur.ContextDigest != s.digest || func() bool { a, _ := cur.Active(); return !a.PublicKey.Equal(s2) }() {
		t.Fatal("the replayed answer rolled the cache back")
	}
	c2 := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20, pins: map[string]string{profile: fp}})
	if _, err := c2.Keys(ctx, profile); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("a fresh pinned client given the old answer: %v", err)
	}
	if _, ok := c2.keys.Load(profile); ok {
		t.Fatal("a fresh client adopted a replayed answer")
	}
	s.replay = nil
	if k, err := c2.Keys(ctx, profile); err != nil || k.ContextDigest != s.digest {
		t.Fatalf("the genuine answer after the replay: %v", err)
	}
}

// TestVerifyRefetchIsThrottledByAttempt (R6): a Verify naming an unknown key id fetches the keys at most once per
// minVerifyRefresh — whether the fetch succeeds or fails: while PublicKey fails, 50 forged Verifies make one call.
func TestVerifyRefetchIsThrottledByAttempt(t *testing.T) {
	const profile = "credentials"
	s, _, _ := newKeysServer(t, profile)
	s.id.Tenancy = transport.TenancyShared
	s.set(t, s.keysPub(0), []ed25519.PublicKey{s.keysPub(0)})
	c := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20})
	ctx := context.Background()
	if _, err := c.Keys(ctx, profile); err != nil {
		t.Fatal(err)
	}
	unknown := make([]byte, transport.SigningKeyIDLen)
	before := s.calls.Load()
	for range 50 {
		// Not (false, nil): nothing was verified, and the answer says so.
		if ok, err := c.Verify(ctx, profile, []byte("d"), make([]byte, 64), unknown); ok || !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("an unknown key id right after a fetch: %v, %v; want ErrUnknownSigningKey", ok, err)
		}
	}
	if n := s.calls.Load() - before; n != 0 {
		t.Fatalf("after a successful fetch: %d PublicKey calls", n)
	}
	v, _ := c.fetched.Load(profile)
	stamp, ok := v.(*atomic.Pointer[time.Time])
	if !ok {
		t.Fatalf("the profile's fetch stamp: got %T", v)
	}
	stamp.Store(new(time.Time)) // the last fetch long ago
	s.fail.Store(true)
	before = s.calls.Load()
	var withCause int
	for range 50 {
		ok, err := c.Verify(ctx, profile, []byte("d"), make([]byte, 64), unknown)
		if ok || !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("while PublicKey fails: %v, %v; want ErrUnknownSigningKey", ok, err)
		}
		if errors.Is(err, context.DeadlineExceeded) { // the one Verify that fetched carries the fetch's error
			withCause++
		}
	}
	if n := s.calls.Load() - before; n != 1 || withCause != 1 {
		t.Fatalf("while PublicKey fails: %d PublicKey calls, %d errors carrying the fetch's error, for 50 forged Verifies; want 1 and 1", n, withCause)
	}
}

// keysPub is the public key of the server's i-th listed key.
func (s *keysServer) keysPub(i int) ed25519.PublicKey { return s.keys[i].PublicKey }
