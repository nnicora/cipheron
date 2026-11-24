package client

// protocol_test.go — the protocol's hardening, the client's side: signing-key revocation (Verify, Sign answers,
// monotonic, the maximum key age), the refusal of an answer holding what this protocol does not have (a signing-key
// state, a tenancy, a ciphertext format, a tenant key blob version) on gRPC and on HTTP — a PublicKey answer
// authenticated before it is read, so that a value changed in the path is an identity failure the observer counts —,
// and tenant key blob version 1.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/cipherontest"
	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// dialFake is a client of fake over gRPC (its socket) or HTTP (the gateway on a socket of its own).
func dialFake(t *testing.T, fake *cipherontest.Server, overHTTP bool, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithServerUID(uint32(os.Getuid()))}, opts...)
	var c *Client
	var err error
	if overHTTP {
		c, err = DialHTTP(fake.ServeHTTPSocket(t), opts...)
	} else {
		c, err = DialGRPC(fake.ServeSocket(t), opts...)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// transports runs f over gRPC and over HTTP.
func transports(t *testing.T, f func(t *testing.T, overHTTP bool)) {
	t.Helper()
	for _, overHTTP := range []bool{false, true} {
		name := "gRPC"
		if overHTTP {
			name = "HTTP"
		}
		t.Run(name, func(t *testing.T) { f(t, overHTTP) })
	}
}

// signedBy signs data with the profile's current active key on c, and returns the signature.
func signedBy(t *testing.T, c *Client, profile string, data []byte) Signature {
	t.Helper()
	s, err := c.Sign(ctxT(t), profile, data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAnUnknownStateIsRefused: a PublicKey answer listing a signing key in a state this protocol does not have (a
// number past revoked), the number signed by the profile's response key, is refused whole — ErrBadResponse, not
// ErrServerIdentity, on gRPC and on HTTP, where cipheron writes enum numbers: an authenticated answer holding what this
// client does not have, a defect the observer is not told of. Nothing is cached, and no key of it is ever verified
// under or accepted for a Sign answer. A Client that cached the profile's list earlier keeps it, never adopting the
// answer.
func TestAnUnknownStateIsRefused(t *testing.T) {
	transports(t, func(t *testing.T, overHTTP bool) {
		t.Helper()
		ctx := ctxT(t)
		fake := cipherontest.New(t, "docs")
		signer := dialFake(t, fake, false)
		old := signedBy(t, signer, "docs", []byte("old"))
		fake.RotateSigning("docs")
		cur := signedBy(t, signer, "docs", []byte("new"))
		obs := &observed{}
		cached := dialFake(t, fake, overHTTP, WithObserver(obs.f))
		before, err := cached.Keys(ctx, "docs")
		if err != nil {
			t.Fatal(err)
		}
		fake.SignSigningKeyUnknown("docs", old.KeyID, 7)

		c := dialFake(t, fake, overHTTP, WithObserver(obs.f))
		if _, err := c.Keys(ctx, "docs"); !errors.Is(err, ErrBadResponse) || errors.Is(err, ErrServerIdentity) {
			t.Fatalf("a signed list with a state this protocol does not have: %v, want ErrBadResponse", err)
		}
		if _, ok := c.keys.Load("docs"); ok {
			t.Fatal("a list with an unknown state was cached")
		}
		for name, s := range map[string]Signature{"the key in the unknown state": old, "the active key": cur} {
			if ok, err := c.Verify(ctx, "docs", []byte(name), s.Bytes, s.KeyID); ok || !errors.Is(err, ErrBadResponse) {
				t.Fatalf("Verify under %s: %v, %v; want ErrBadResponse", name, ok, err)
			}
		}
		if _, err := c.Sign(ctx, "docs", []byte("d")); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("Sign: %v, want ErrBadResponse", err)
		}
		// The client that cached the list before keeps it: the refused answer is not adopted.
		if _, err := cached.Keys(ctx, "docs"); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("a cached profile, the answer fetched again: %v, want ErrBadResponse", err)
		}
		if k, ok := cached.cachedKeys("docs"); !ok || !sameKeys(k.SigningKeys, before.SigningKeys) {
			t.Fatal("the refused list was adopted")
		}
		if n := obs.count("docs/" + KindServerIdentity); n != 0 {
			t.Fatalf("a signed answer the client does not have was told to the observer as an identity failure %d times", n)
		}
	})
}

// TestATamperedStateIsAnIdentityFailure: the same answer with the unknown state number written AFTER keys_signature
// was made (the key's real state signed, the number changed in the path, cipherontest.MarkSigningKeyUnknown) is not
// cipheron's answer: keys_signature is checked over the answer as received, before anything in it is read, so the
// refusal is ErrServerIdentity — not ErrBadResponse —, and every call that met it is told to the observer
// (server_identity). Nothing is cached, the cached client keeps its list, and nothing verifies.
func TestATamperedStateIsAnIdentityFailure(t *testing.T) {
	transports(t, func(t *testing.T, overHTTP bool) {
		t.Helper()
		ctx := ctxT(t)
		fake := cipherontest.New(t, "docs")
		signer := dialFake(t, fake, false)
		old := signedBy(t, signer, "docs", []byte("old"))
		fake.RotateSigning("docs")
		cur := signedBy(t, signer, "docs", []byte("new"))
		obs := &observed{}
		cached := dialFake(t, fake, overHTTP, WithObserver(obs.f))
		before, err := cached.Keys(ctx, "docs")
		if err != nil {
			t.Fatal(err)
		}
		fake.MarkSigningKeyUnknown("docs", old.KeyID, 7)

		c := dialFake(t, fake, overHTTP, WithObserver(obs.f))
		calls := 0
		identity := func(what string, err error) {
			t.Helper()
			calls++
			if !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrBadResponse) || !errors.Is(err, transport.ErrAuth) {
				t.Fatalf("%s: %v, want ErrServerIdentity (keys_signature does not verify)", what, err)
			}
		}
		_, err = c.Keys(ctx, "docs")
		identity("a list whose state was changed after it was signed", err)
		if _, ok := c.keys.Load("docs"); ok {
			t.Fatal("a tampered list was cached")
		}
		for name, s := range map[string]Signature{"the key in the changed state": old, "the active key": cur} {
			ok, err := c.Verify(ctx, "docs", []byte(name), s.Bytes, s.KeyID)
			if ok {
				t.Fatalf("Verify under %s: verified", name)
			}
			identity("Verify under "+name, err)
		}
		_, err = c.Sign(ctx, "docs", []byte("d"))
		identity("Sign", err)
		_, err = cached.Keys(ctx, "docs")
		identity("a cached profile, the answer fetched again", err)
		if k, ok := cached.cachedKeys("docs"); !ok || !sameKeys(k.SigningKeys, before.SigningKeys) {
			t.Fatal("the tampered list was adopted")
		}
		if n := obs.count("docs/" + KindServerIdentity); n != calls {
			t.Fatalf("the observer was told of %d identity failures; %d calls met one", n, calls)
		}
	})
}

// TestAnUnknownTenancyIsRefused: a tenancy number this protocol does not have names no tenancy the client could put
// into the fingerprint or the keys transcript (they hold the tenancy's name), so the answer cannot be authenticated:
// ErrServerIdentity, told to the observer, on both transports, and nothing is cached.
func TestAnUnknownTenancyIsRefused(t *testing.T) {
	transports(t, func(t *testing.T, overHTTP bool) {
		t.Helper()
		fake := cipherontest.New(t, "docs")
		fake.SetMode(cipherontest.UnknownTenancy)
		obs := &observed{}
		c := dialFake(t, fake, overHTTP, WithObserver(obs.f))
		if _, err := c.Encrypt(ctxT(t), "docs", []byte("p")); !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrBadResponse) {
			t.Fatalf("an unknown tenancy: %v, want ErrServerIdentity", err)
		}
		if _, ok := c.keys.Load("docs"); ok {
			t.Fatal("a profile of an unknown tenancy was cached")
		}
		if n := obs.count("docs/" + KindServerIdentity); n != 1 {
			t.Fatalf("the observer was told of %d identity failures, want 1", n)
		}
	})
}

// TestAnUnknownCiphertextFormatIsRefused: a signed Encrypt (or ReEncrypt) answer in a format this protocol does not
// have is refused, ErrBadResponse (and not the caller's input: not transport.ErrCiphertext); a ciphertext of such a
// format handed to Decrypt or ReEncrypt is refused before anything is sent, as the caller's input
// (transport.ErrCiphertextFormat, which is transport.ErrCiphertext). Format 2 and an unknown byte alike.
func TestAnUnknownCiphertextFormatIsRefused(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	ct, err := c.Encrypt(ctx, "docs", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	fake.SetMode(cipherontest.UnknownFormatCiphertext)
	if got, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrBadResponse) || errors.Is(err, transport.ErrCiphertext) || got != nil {
		t.Fatalf("Encrypt answered in an unknown format: %v, want ErrBadResponse", err)
	}
	if got, err := c.ReEncrypt(ctx, "docs", ct); !errors.Is(err, ErrBadResponse) || got != nil {
		t.Fatalf("ReEncrypt answered in an unknown format: %v, want ErrBadResponse", err)
	}
	fake.SetMode(cipherontest.Honest)
	k, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	n := len(ct) - transport.VersionedOverhead("v1")
	for _, format := range []byte{2, cipherontest.UnknownFormat} {
		other := append([]byte(nil), ct...)
		other[len(transport.CiphertextMagic)] = format
		// The answer path, for every byte: refused as malformed.
		if err := (&Client{}).checkCiphertext(scope{profile: "docs", k: k}, other, n, nil, false); !errors.Is(err, ErrBadResponse) ||
			errors.Is(err, transport.ErrCiphertext) {
			t.Errorf("format %d answered: %v, want ErrBadResponse", format, err)
		}
		for name, call := range map[string]func() error{
			"Decrypt":   func() error { _, err := c.Decrypt(ctx, "docs", other); return err },
			"ReEncrypt": func() error { _, err := c.ReEncrypt(ctx, "docs", other); return err },
		} {
			if err := call(); !errors.Is(err, transport.ErrCiphertextFormat) || errors.Is(err, ErrBadResponse) {
				t.Errorf("%s of a ciphertext of format %d: %v", name, format, err)
			}
		}
	}
}

// TestVerifyRefusesARevokedKey: a signature under a key the profile revoked is (false, ErrSigningKeyRevoked) —
// genuine or not — for the Client's Verify, a derived tenant's Verify, and VerifyWithKeys; the other keys verify.
func TestVerifyRefusesARevokedKey(t *testing.T) {
	ctx := ctxT(t)
	for _, derived := range []bool{false, true} {
		fake := cipherontest.New(t, "docs")
		signer := dialFake(t, fake, false)
		sign := func(data string) Signature {
			if !derived {
				return signedBy(t, signer, "docs", []byte(data))
			}
			s, err := signer.Tenant("docs", "t_1", nil).Sign(ctx, []byte(data))
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		if derived {
			fake.MakeDerived("docs")
		}
		old := sign("old")
		fake.RotateSigning("docs")
		cur := sign("new")
		fake.RevokeSigning("docs", old.KeyID)

		c := dialFake(t, fake, false)
		verify := func(data string, s Signature) (bool, error) {
			if derived {
				return c.Tenant("docs", "t_1", nil).Verify(ctx, []byte(data), s.Bytes, s.KeyID)
			}
			return c.Verify(ctx, "docs", []byte(data), s.Bytes, s.KeyID)
		}
		for name, data := range map[string]string{"genuine": "old", "not over this data": "other"} {
			if ok, err := verify(data, old); ok || !errors.Is(err, ErrSigningKeyRevoked) {
				t.Fatalf("derived %v, %s, under the revoked key: %v, %v; want ErrSigningKeyRevoked", derived, name, ok, err)
			}
		}
		if ok, err := verify("new", cur); !ok || err != nil {
			t.Fatalf("derived %v, under the active key: %v, %v", derived, ok, err)
		}
		k, err := c.Keys(ctx, "docs")
		if err != nil {
			t.Fatal(err)
		}
		offline := func(s Signature, data string) (bool, error) {
			if derived {
				return VerifyTenantWithKeys(k.SigningKeys, "docs", "t_1", []byte(data), s.Bytes, s.KeyID)
			}
			return VerifyWithKeys(k.SigningKeys, []byte(data), s.Bytes, s.KeyID)
		}
		if ok, err := offline(old, "old"); ok || !errors.Is(err, ErrSigningKeyRevoked) {
			t.Fatalf("derived %v, offline under the revoked key: %v, %v", derived, ok, err)
		}
		if ok, err := offline(cur, "new"); !ok || err != nil {
			t.Fatalf("derived %v, offline under the active key: %v, %v", derived, ok, err)
		}
		if ok, err := offline(cur, "other"); ok || err != nil {
			t.Fatalf("derived %v, offline, not over this data: %v, %v; want false, nil", derived, ok, err)
		}
		if ok, err := offline(Signature{Bytes: cur.Bytes, KeyID: make([]byte, transport.SigningKeyIDLen)}, "new"); ok ||
			!errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("derived %v, offline, a key id the list does not name: %v, %v", derived, ok, err)
		}
		// The raw-key verification is state-agnostic, on purpose.
		key, _ := k.SigningKey(old.KeyID)
		if derived {
			if !VerifyTenant(key.PublicKey, "docs", "t_1", []byte("old"), old.Bytes) {
				t.Fatal("VerifyTenant with the revoked key's public key")
			}
		} else if !Verify(key.PublicKey, []byte("old"), old.Bytes) {
			t.Fatal("Verify with the revoked key's public key")
		}
	}
}

// TestARevocationIsNeverUndone: once a Client has verified a list with a key revoked, a later list that lists it
// verify-only again (a stale replica, or a forged history signed by a compromised response key) does not un-revoke it.
func TestARevocationIsNeverUndone(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	old := signedBy(t, c, "docs", []byte("old"))
	fake.RotateSigning("docs")
	fake.RevokeSigning("docs", old.KeyID)
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.UnrevokeSigning("docs", old.KeyID)
	k, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if key, _ := k.SigningKey(old.KeyID); key.State != transport.SigningKeyRevoked {
		t.Fatalf("a later list un-revoked the key: %+v", key)
	}
	longAgo(t, c, "docs")
	staleList(c, "docs") // force a fetch before Verify, too
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("Verify after a list that un-revokes: %v, %v; want ErrSigningKeyRevoked", ok, err)
	}
}

// TestASignAnswerUnderARevokedKeyIsRefused: a replica that has not learnt a revocation signs with the revoked key;
// its answer, signed by the response key, is refused with ErrSigningKeyRevoked.
func TestASignAnswerUnderARevokedKeyIsRefused(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	old := signedBy(t, c, "docs", []byte("old"))
	fake.RotateSigning("docs")
	fake.SetMode(cipherontest.SignRevoked) // no key revoked yet: the active key signs
	if _, err := c.Sign(ctx, "docs", []byte("d")); err != nil {
		t.Fatalf("no key revoked: %v", err)
	}
	fake.RevokeSigning("docs", old.KeyID)
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	if s, err := c.Sign(ctx, "docs", []byte("d")); !errors.Is(err, ErrSigningKeyRevoked) || s.Bytes != nil {
		t.Fatalf("a Sign answer under the revoked key: %v, want ErrSigningKeyRevoked", err)
	}
	fake.SetMode(cipherontest.Honest)
}

// TestTheKeysMaximumAge: Verify fetches a list older than the maximum age first — so a revocation made since is
// refused — and fails closed when it cannot: (false, ErrKeysStale) wrapping the fetch's error, the failure not
// retried for a few seconds, and served again once the list is fresh.
func TestTheKeysMaximumAge(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	old := signedBy(t, c, "docs", []byte("old"))
	fake.RotateSigning("docs")
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); !ok || err != nil {
		t.Fatalf("before the revocation: %v, %v", ok, err)
	}
	fake.RevokeSigning("docs", old.KeyID)
	calls := fake.PublicKeyCalls()
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); !ok || err != nil || fake.PublicKeyCalls() != calls {
		t.Fatalf("within the maximum age the cached list decides: %v, %v", ok, err)
	}
	staleList(c, "docs") // the list is older than the maximum age
	if ok, err := c.Verify(ctx, "docs", []byte("old"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("past the maximum age, the refreshed list: %v, %v; want ErrSigningKeyRevoked", ok, err)
	}
	if n := fake.PublicKeyCalls() - calls; n != 1 {
		t.Fatalf("the refresh made %d PublicKey calls, want 1", n)
	}

	// cipheron cannot answer: fail closed.
	cur := signedBy(t, c, "docs", []byte("new"))
	staleList(c, "docs")
	fake.FailPublicKey(cipherontest.Internal)
	calls = fake.PublicKeyCalls()
	ok, err := c.Verify(ctx, "docs", []byte("new"), cur.Bytes, cur.KeyID)
	if ok || !errors.Is(err, ErrKeysStale) || status.Code(err) != codes.Internal {
		t.Fatalf("a stale list that cannot be refreshed: %v, %v; want ErrKeysStale wrapping INTERNAL", ok, err)
	}
	for range 5 { // not retried for a few seconds
		if ok, err := c.Verify(ctx, "docs", []byte("new"), cur.Bytes, cur.KeyID); ok || !errors.Is(err, ErrKeysStale) {
			t.Fatalf("while the failure stands: %v, %v", ok, err)
		}
	}
	if n := fake.PublicKeyCalls() - calls; n != 1 {
		t.Fatalf("a failing refresh was tried %d times, want 1", n)
	}
	fake.FailPublicKey(cipherontest.NoFault)
	if _, err := c.Keys(ctx, "docs"); err != nil { // any successful fetch makes the list fresh again
		t.Fatal(err)
	}
	if ok, err := c.Verify(ctx, "docs", []byte("new"), cur.Bytes, cur.KeyID); !ok || err != nil {
		t.Fatalf("fresh again: %v, %v", ok, err)
	}
}

// TestTheKeysMaximumAgeWithAnUnreachableServer: the server does not answer at all (its PublicKey fails at once, as a
// connection that cannot be made): ErrKeysStale, and the other calls are untouched by the list's age.
func TestTheKeysMaximumAgeWithAnUnreachableServer(t *testing.T) {
	const profile = "credentials"
	s, _, _ := newKeysServer(t, profile)
	s.id.Tenancy = transport.TenancyShared
	pub, priv := keyPair(t)
	s.set(t, pub, []ed25519.PublicKey{pub})
	c := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20, keysMaxAge: MinKeysMaxAge})
	ctx := context.Background()
	if _, err := c.Keys(ctx, profile); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte("d"))
	id := transport.SigningKeyID(pub)
	if ok, err := c.Verify(ctx, profile, []byte("d"), sig, id); !ok || err != nil {
		t.Fatalf("fresh: %v, %v", ok, err)
	}
	old := time.Now().Add(-MinKeysMaxAge - time.Second)
	c.freshnessOf(profile).verified.Store(&old)
	s.fail.Store(true)
	ok, err := c.Verify(ctx, profile, []byte("d"), sig, id)
	if ok || !errors.Is(err, ErrKeysStale) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unreachable: %v, %v; want ErrKeysStale wrapping the fetch's error", ok, err)
	}
}

// TestWithKeysMaxAge: the bounds, and one answer.
func TestWithKeysMaxAge(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	sock := fake.ServeSocket(t)
	for _, d := range []time.Duration{0, MinKeysMaxAge - 1, MaxKeysMaxAge + 1, -time.Minute} {
		if _, err := DialGRPC(sock, WithAnyServer(), WithKeysMaxAge(d)); err == nil {
			t.Errorf("WithKeysMaxAge(%s) was accepted", d)
		}
	}
	if _, err := DialGRPC(sock, WithAnyServer(), WithKeysMaxAge(time.Minute), WithKeysMaxAge(time.Hour)); err == nil {
		t.Error("two answers were accepted")
	}
	for d, want := range map[time.Duration]time.Duration{0: DefaultKeysMaxAge, MinKeysMaxAge: MinKeysMaxAge, MaxKeysMaxAge: MaxKeysMaxAge} {
		var opts []Option
		if d != 0 {
			opts = append(opts, WithKeysMaxAge(d), WithKeysMaxAge(d))
		}
		c, err := DialGRPC(sock, append(opts, WithAnyServer())...)
		if err != nil {
			t.Fatal(err)
		}
		if c.keysMaxAge != want {
			t.Errorf("WithKeysMaxAge(%s): %s, want %s", d, c.keysMaxAge, want)
		}
		_ = c.Close()
	}
}

// TestTenantKeyBlobVersion: a version-1 blob — the one layout — is accepted from CreateTenantKey and from
// RewrapTenantKey; a blob of any other version answered by either — below (0) or above (2) — is ErrBadResponse.
func TestTenantKeyBlobVersion(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	c := dialFake(t, fake, false)
	k1, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	if i, err := ReadTenantKey(k1.Blob); err != nil || i.Version != transport.TenantKeyVersion {
		t.Fatalf("the blob: %+v %v", i, err)
	}
	if _, err := c.Tenant("docs", "t_1", k1.Blob).Encrypt(ctx, []byte("p")); err != nil {
		t.Fatalf("a version-1 blob's tenant: %v", err)
	}
	if r, err := c.RewrapTenantKey(ctx, "docs", "t_1", k1.Blob); err != nil {
		t.Fatal(err)
	} else if i, _ := ReadTenantKey(r.Blob); i.Version != transport.TenantKeyVersion || !i.Created.Equal(mustRead(t, k1.Blob).Created) {
		t.Fatalf("a version-1 blob rewrapped: %+v", i)
	}
	fake.SetMode(cipherontest.UnknownVersionBlob)
	if got, err := c.CreateTenantKey(ctx, "docs", "t_2"); !errors.Is(err, ErrBadResponse) || got != nil {
		t.Errorf("a blob of an unknown version answered: %v, want ErrBadResponse", err)
	}
	if got, err := c.RewrapTenantKey(ctx, "docs", "t_1", k1.Blob); !errors.Is(err, ErrBadResponse) || got != nil {
		t.Errorf("a rewrap answered a blob of an unknown version: %v, want ErrBadResponse", err)
	}
	fake.SetMode(cipherontest.Honest)
	// The answer's check itself, for a version below and one above the one version: refused, never the caller's input.
	h := mustRead(t, k1.Blob)
	for _, v := range []byte{0, transport.TenantKeyVersion + 1} {
		other := append([]byte(nil), k1.Blob...)
		other[len(transport.TenantKeyMagic)] = v
		if _, err := tenantKeyAnswer("docs", "t_1", other, h.SigningPublicKey, h.Fingerprint); !errors.Is(err, ErrBadResponse) ||
			errors.Is(err, ErrTenantKey) {
			t.Errorf("a version-%d blob answered: %v, want ErrBadResponse", v, err)
		}
	}
}

func mustRead(t *testing.T, blob []byte) *TenantKeyInfo {
	t.Helper()
	i, err := ReadTenantKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// TestABatchAnswerIsAuthenticatedBeforeItIsRead: a batch answer's response signature covers every result as received
// and is checked before the results are counted, for each of the four batch operations, on gRPC and on HTTP. A result
// dropped AFTER the answer was signed (a party in the path, cipherontest.BatchResultDropped) fails the signature:
// ErrServerIdentity, not ErrBadResponse, each call told to the observer as server_identity. An answer signed with one
// result too few (cipherontest.ShortBatch) is authenticated and then refused for its count: ErrBadResponse, not
// ErrServerIdentity, a defect the observer is not told of. Nothing of either answer is returned.
func TestABatchAnswerIsAuthenticatedBeforeItIsRead(t *testing.T) {
	transports(t, func(t *testing.T, overHTTP bool) {
		t.Helper()
		ctx := ctxT(t)
		fake := cipherontest.New(t, "docs", "wrapped")
		fake.MakePerTenant("wrapped")
		obs := &observed{}
		c := dialFake(t, fake, overHTTP, WithObserver(obs.f))
		items := []BatchItem{{Data: []byte("a")}, {Data: []byte("b")}}
		cts, err := c.EncryptBatch(ctx, "docs", items)
		if err != nil {
			t.Fatal(err)
		}
		sealed := []BatchItem{{Data: cts[0].Value}, {Data: cts[1].Value}}
		var keys []TenantKeyRef
		for _, tenant := range []string{"t_1", "t_2"} {
			k, err := c.CreateTenantKey(ctx, "wrapped", tenant)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, TenantKeyRef{Tenant: tenant, Blob: k.Blob})
		}
		calls := map[string]func() (bool, error){
			"EncryptBatch": func() (bool, error) { r, err := c.EncryptBatch(ctx, "docs", items); return r != nil, err },
			"DecryptBatch": func() (bool, error) { r, err := c.DecryptBatch(ctx, "docs", sealed); return r != nil, err },
			"ReEncryptBatch": func() (bool, error) {
				r, err := c.ReEncryptBatch(ctx, "docs", sealed)
				return r != nil, err
			},
			"RewrapTenantKeyBatch": func() (bool, error) {
				r, err := c.RewrapTenantKeyBatch(ctx, "wrapped", keys)
				return r != nil, err
			},
		}
		fake.SetMode(cipherontest.BatchResultDropped)
		for name, call := range calls {
			if got, err := call(); got || !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrBadResponse) ||
				!strings.Contains(err.Error(), "is not signed by the profile's response key") {
				t.Fatalf("%s, a result dropped in the path: %v (results returned: %v), want ErrServerIdentity", name, err, got)
			}
		}
		if n := obs.count("docs/"+KindServerIdentity) + obs.count("wrapped/"+KindServerIdentity); n != len(calls) {
			t.Fatalf("the observer was told of %d identity failures; %d calls met one", n, len(calls))
		}
		fake.SetMode(cipherontest.ShortBatch)
		for name, call := range calls {
			if got, err := call(); got || !errors.Is(err, ErrBadResponse) || errors.Is(err, ErrServerIdentity) ||
				!strings.Contains(err.Error(), "1 results for a batch of 2 items") {
				t.Fatalf("%s, a signed answer with one result too few: %v (results returned: %v), want ErrBadResponse", name,
					err, got)
			}
		}
		if n := obs.count("docs/"+KindServerIdentity) + obs.count("wrapped/"+KindServerIdentity); n != len(calls) {
			t.Fatalf("a signed answer with the wrong count was told to the observer as an identity failure (%d)", n-len(calls))
		}
		fake.SetMode(cipherontest.Honest)
		if _, err := c.EncryptBatch(ctx, "docs", items); err != nil {
			t.Fatalf("served honestly again: %v", err)
		}
	})
}

// TestWhatTheBatchSignatureDoesNotCover: an error item's digest is its error's alone, so a result field beside it is
// not cipheron's answer (ErrServerIdentity), while an error code no item is answered with is signed (ErrBadResponse);
// an error item with nothing else is accepted. A batch answer of more results than any batch holds is refused before
// a single result is hashed, as not shown to be cipheron's (ErrServerIdentity).
func TestWhatTheBatchSignatureDoesNotCover(t *testing.T) {
	s := scope{profile: "docs"}
	itemErr := &cipheronv1.ItemError{Code: uint32(codes.InvalidArgument), Reason: transport.ReasonAssociatedData, Message: "m"}
	if err := itemErrorAlone(s, 0, itemErr, nil, []byte{}); err != nil {
		t.Fatalf("an error item alone: %v", err)
	}
	if err := itemErrorAlone(s, 1, itemErr, nil, []byte("ct")); !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrBadResponse) {
		t.Fatalf("an error item carrying a result: %v, want ErrServerIdentity", err)
	}
	ok := &cipheronv1.ItemError{Code: uint32(codes.OK)}
	if err := itemErrorAlone(s, 2, ok); !errors.Is(err, ErrBadResponse) || errors.Is(err, ErrServerIdentity) {
		t.Fatalf("an error item of code OK: %v, want ErrBadResponse", err)
	}
	err := (&Client{}).verifyBatch(context.Background(), s, transport.OpEncryptBatch, nil, nil, [32]byte{}, nil,
		transport.MaxBatchItems+1, 1, func(int) [32]byte {
			t.Fatal("a result was hashed before the count was bounded")
			return [32]byte{}
		})
	if !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrBadResponse) {
		t.Fatalf("an answer of %d results: %v, want ErrServerIdentity", transport.MaxBatchItems+1, err)
	}
}
