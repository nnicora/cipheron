package client

// keystatement_test.go — the key statement a Client hands out (security review 2026-11-19, owner decisions S9 and
// S13): never one that contradicts a revocation the Client knows — the most recent statement that agrees with the
// merged signing-key list, states included, while it is younger than WithKeysMaxAge, else ErrSigningKeyRevoked or
// ErrKeysStale — and a statement's Verify and VerifyTenant refuse the other tenancy (ErrTenancy).

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// stateOf is keyID's state in keys ("" when it is not there).
func stateOf(keys []transport.SigningKey, keyID []byte) transport.SigningKeyState {
	if k, ok := findKey(keys, keyID); ok {
		return k.State
	}
	return ""
}

// nextMilli waits until the wall clock is past the millisecond it reads now: a statement the fake issues afterwards
// carries a later IssuedAtMS, so its bytes are not those of one issued before.
func nextMilli() {
	for ms := time.Now().UnixMilli(); time.Now().UnixMilli() == ms; {
		time.Sleep(100 * time.Microsecond)
	}
}

// TestASteadyProfileKeepsAFreshStatement: a profile whose signing keys never change answers every fetch with the list
// this Client holds, and each such answer's statement replaces the one held (the most recent agreeing statement). So
// KeyStatement hands out the newest one, and still hands one out once WithKeysMaxAge has passed since the first. A
// Client that kept its first statement would refuse a steady profile ErrKeysStale from then on.
func TestASteadyProfileKeepsAFreshStatement(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	var mu sync.Mutex
	clock := time.Now()
	c.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}
	first, err := c.KeyStatement(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}

	nextMilli()
	second, err := c.KeyStatement(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(second.Raw, first.Raw) || second.IssuedAtMS <= first.IssuedAtMS {
		t.Fatal("KeyStatement handed out the statement it held, not the newer one the profile answered with the same keys")
	}

	mu.Lock()
	clock = clock.Add(DefaultKeysMaxAge + time.Minute)
	mu.Unlock()
	nextMilli()
	third, err := c.KeyStatement(ctx, "docs")
	if err != nil {
		t.Fatalf("a steady profile's statement once the maximum age has passed since the first: %v; want a fresh one", err)
	}
	if bytes.Equal(third.Raw, second.Raw) || third.IssuedAtMS <= second.IssuedAtMS {
		t.Fatal("the statement handed out past the maximum age is not the newest one")
	}
}

// TestAKeyStatementNeverUndoesARevocation: after a key is revoked and the Client saw it, a replica that lags the
// revocation answers a statement listing the key verify-only. The Client keeps the key revoked in its list, and
// KeyStatement hands out the most recent statement that agrees with that list — the one with the revocation — not the
// lagging one: its Export, imported offline, refuses the key's signatures, and its JWKS leaves the key out. Once that
// statement is older than the maximum age and the replicas still lag, nothing is handed out (ErrKeysStale). When the
// replicas agree again, the fresh statement is handed out.
func TestAKeyStatementNeverUndoesARevocation(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
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
	old := signedBy(t, c, "docs", []byte("signed before"))
	fake.RotateSigning("docs")
	fake.RevokeSigning("docs", old.KeyID)
	revoked, err := c.KeyStatement(ctx, "docs")
	if err != nil || stateOf(revoked.SigningKeys, old.KeyID) != transport.SigningKeyRevoked {
		t.Fatalf("the statement after the revocation: %v", err)
	}

	step(time.Second)
	fake.UnrevokeSigning("docs", old.KeyID) // a replica that lags the revocation answers
	st, err := c.KeyStatement(ctx, "docs")
	if err != nil {
		t.Fatalf("the statement after a lagging answer: %v; want the one with the revocation", err)
	}
	if k, _ := c.cachedKeys("docs"); stateOf(k.SigningKeys, old.KeyID) != transport.SigningKeyRevoked {
		t.Fatal("the Client's list forgot the revocation")
	}
	if !bytes.Equal(st.Raw, revoked.Raw) || stateOf(st.SigningKeys, old.KeyID) != transport.SigningKeyRevoked {
		t.Fatalf("a statement that un-revokes key %x was handed out: %s", old.KeyID, stateOf(st.SigningKeys, old.KeyID))
	}
	ex, err := st.Export()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportKeyStatement(ex, "docs", fake.Fingerprint("docs"), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := imported.Verify([]byte("signed before"), old.Bytes, old.KeyID); ok || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("an offline verifier of the statement handed out accepts the revoked key: %v, %v", ok, err)
	}
	if jwks, err := st.JWKS(); err != nil || strings.Contains(string(jwks), hex.EncodeToString(old.KeyID)) {
		t.Fatalf("the JWKS lists the revoked key: %s %v", jwks, err)
	}

	// Older than the maximum age, the replicas still lagging: nothing is handed out.
	step(DefaultKeysMaxAge + time.Second)
	if st, err := c.KeyStatement(ctx, "docs"); st != nil || (!errors.Is(err, ErrKeysStale) && !errors.Is(err, ErrSigningKeyRevoked)) {
		t.Fatalf("a statement older than the maximum age: %v, %v; want none, ErrKeysStale or ErrSigningKeyRevoked", st, err)
	}

	// The replicas agree again: the fresh statement, with the revocation.
	fake.RevokeSigning("docs", old.KeyID)
	nextMilli()
	st, err = c.KeyStatement(ctx, "docs")
	if err != nil || stateOf(st.SigningKeys, old.KeyID) != transport.SigningKeyRevoked || bytes.Equal(st.Raw, revoked.Raw) {
		t.Fatalf("the statement once the replicas agree: %v", err)
	}
}

// TestAStatementThatDoesNotCoverTheListIsNotKept: the other direction. A replica answers a list that leaves out a key
// the Client knows (not adopted: it does not cover the cached list) but revokes another; the Client merges the
// revocation into its list. Neither the answer's statement (a key missing) nor the one the Client held (the key
// verify-only) agrees with the merged list, so nothing is handed out: ErrSigningKeyRevoked, as the held one lists a
// key the Client holds revoked as usable. An honest answer brings a statement that agrees.
func TestAStatementThatDoesNotCoverTheListIsNotKept(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	k2, k3 := fake.AddSigningKey("docs"), fake.AddSigningKey("docs")
	held, err := c.KeyStatement(ctx, "docs")
	if err != nil || stateOf(held.SigningKeys, k2) != transport.SigningKeyVerifyOnly || len(held.SigningKeys) != 3 {
		t.Fatalf("the first statement: %v", err)
	}
	fake.RevokeSigning("docs", k2)
	fake.SetMode(cipherontest.ForgetVerifyOnlyKeys) // the answer: the active key and k2 revoked; k3 left out
	if st, err := c.KeyStatement(ctx, "docs"); st != nil || !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("no statement agrees with the merged list: %v, %v; want none, ErrSigningKeyRevoked", st, err)
	}
	k, _ := c.cachedKeys("docs")
	if stateOf(k.SigningKeys, k2) != transport.SigningKeyRevoked || stateOf(k.SigningKeys, k3) != transport.SigningKeyVerifyOnly {
		t.Fatalf("the merged list: %v", k.SigningKeys)
	}
	fake.SetMode(cipherontest.Honest)
	st, err := c.KeyStatement(ctx, "docs")
	if err != nil || stateOf(st.SigningKeys, k2) != transport.SigningKeyRevoked || stateOf(st.SigningKeys, k3) != transport.SigningKeyVerifyOnly {
		t.Fatalf("the statement of an honest answer: %v", err)
	}
}

// TestAStatementVerifiesItsOwnTenancy (S13): a shared profile's statement verifies a raw signature (Verify) and refuses
// VerifyTenant; a derived profile's verifies a tenant-bound signature (VerifyTenant) and refuses Verify — both with
// ErrTenancy and nothing verified, whatever the bytes. The mirror attack fails: a shared profile's signature over bytes
// built as a TenantSignedMessage is not a derived profile's, and a derived profile's signature is not a raw one.
func TestAStatementVerifiesItsOwnTenancy(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs", "prof")
	fake.MakeDerived("prof")
	c := dialFake(t, fake, false)
	data := []byte("the data")
	crafted := transport.TenantSignedMessage("docs", "t_1", data)

	shared, err := c.KeyStatement(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	raw := signedBy(t, c, "docs", data)
	if ok, err := shared.Verify(data, raw.Bytes, raw.KeyID); !ok || err != nil {
		t.Fatalf("a shared profile's signature: %v, %v", ok, err)
	}
	mirror := signedBy(t, c, "docs", crafted)
	if ok, err := shared.VerifyTenant("t_1", data, mirror.Bytes, mirror.KeyID); ok || !errors.Is(err, ErrTenancy) {
		t.Fatalf("VerifyTenant of a shared profile's statement: %v, %v; want ErrTenancy", ok, err)
	}

	derived, err := c.KeyStatement(ctx, "prof")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := c.Tenant("prof", "t_1", nil).Sign(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := derived.VerifyTenant("t_1", data, ts.Bytes, ts.KeyID); !ok || err != nil {
		t.Fatalf("a derived profile's signature: %v, %v", ok, err)
	}
	signedMessage := transport.TenantSignedMessage("prof", "t_1", data)
	if ok, err := derived.Verify(signedMessage, ts.Bytes, ts.KeyID); ok || !errors.Is(err, ErrTenancy) {
		t.Fatalf("Verify of a derived profile's statement: %v, %v; want ErrTenancy", ok, err)
	}
	// The list-based calls leave the choice to the caller: they verify whatever the tenancy.
	if ok, err := VerifyWithKeys(derived.SigningKeys, signedMessage, ts.Bytes, ts.KeyID); !ok || err != nil {
		t.Fatalf("VerifyWithKeys of a derived list: %v, %v", ok, err)
	}
}
