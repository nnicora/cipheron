//go:build linux || darwin

package cipheron_test

// rotation_test.go — the library across key rotations, against the fake (cipherontest): the signing-key
// list authenticated by the identity (forgeries refused, a rotated list adopted, an identity change refused),
// Sign's key ids (an unknown one learnt by one shared re-fetch, never from the answer), every ciphertext format
// decrypting, retired key versions, and the offline verifiers.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestForgedKeyListsAreRefused: a signing-key list that is not signed by the profile's identity — by another key,
// for another profile, over another context digest, another identity's list, a key slipped in after signing — is
// ErrServerIdentity, on the first fetch (with and without a pin) and as a later fetch, and is never adopted.
func TestForgedKeyListsAreRefused(t *testing.T) {
	for _, mode := range []cipherontest.Mode{cipherontest.ForgedKeysSignature, cipherontest.KeysForOtherProfile,
		cipherontest.KeysForOtherContext, cipherontest.KeysOfAnotherIdentity, cipherontest.UnsignedExtraKey} {
		fake := cipherontest.New(t, profile)
		sock := fake.ServeSocket(t)
		ctx := ctxFor(t, 20*time.Second)
		fake.SetMode(mode)
		for name, c := range map[string]*cipheron.Client{
			"pinned": newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithProfileFingerprint(profile, fake.Fingerprint(profile))),
			"tofu":   newClient(t, sock, cipheron.WithAnyServer()),
		} {
			if _, err := c.Encrypt(ctx, profile, []byte("secret")); !errors.Is(err, cipheron.ErrServerIdentity) ||
				!strings.Contains(err.Error(), "signing keys") {
				t.Errorf("mode %d %s: Encrypt under a forged list: %v", mode, name, err)
			}
			if _, err := c.Keys(ctx, profile); !errors.Is(err, cipheron.ErrServerIdentity) {
				t.Errorf("mode %d %s: Keys: %v", mode, name, err)
			}
		}
		// Cached first, then a forged list: refused, the cache unchanged.
		fake.SetMode(cipherontest.Honest)
		c := newClient(t, sock, cipheron.WithAnyServer())
		before, err := c.Keys(ctx, profile)
		if err != nil {
			t.Fatal(err)
		}
		fake.SetMode(mode)
		if _, err := c.Keys(ctx, profile); !errors.Is(err, cipheron.ErrServerIdentity) || errors.Is(err, cipheron.ErrServerKeyChanged) {
			t.Errorf("mode %d: a forged list after the cache: %v", mode, err)
		}
		fake.SetMode(cipherontest.Honest)
		after, err := c.Keys(ctx, profile)
		if err != nil || len(after.SigningKeys) != len(before.SigningKeys) || after.ContextDigest != before.ContextDigest {
			t.Errorf("mode %d: the cache moved: %+v %v", mode, after, err)
		}
	}
}

// TestASigningRotationIsAdopted: a new signing-key list signed by the same identity is a rotation: Sign's answer
// names the new key, the Client learns the list with exactly one PublicKey call however many Signs ask, old
// signatures keep verifying, and the pin (the identity's fingerprint) holds throughout.
func TestASigningRotationIsAdopted(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()), cipheron.WithProfileFingerprint(profile, fake.Fingerprint(profile)))
	ctx := ctxFor(t, 30*time.Second)
	fp := fake.Fingerprint(profile)
	old, err := c.Sign(ctx, profile, []byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := c.Keys(ctx, profile)
	calls := fake.PublicKeyCalls()

	newID := fake.RotateSigning(profile)
	if fake.Fingerprint(profile) != fp {
		t.Fatal("a signing rotation changed the fingerprint")
	}
	release := fake.HoldPublicKey()
	const n = 16
	var wg sync.WaitGroup
	sigs := make(chan cipheron.Signature, n)
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.Sign(ctx, profile, []byte("after"))
			sigs <- s
			errs <- err
		}()
	}
	// One fetch is held at the fake: the rotation is being learnt. The other Signs join it, or find the key it
	// learnt once it is released; none makes a fetch of its own (no sleep: the count does not depend on timing).
	for deadline := time.Now().Add(10 * time.Second); fake.PublicKeyCalls()-calls < 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no Sign fetched the rotated list")
		}
	}
	release()
	wg.Wait()
	close(errs)
	close(sigs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a Sign after the rotation: %v", err)
		}
	}
	for s := range sigs {
		if !bytes.Equal(s.KeyID, newID) {
			t.Fatalf("a Sign after the rotation names %x, not the new key %x", s.KeyID, newID)
		}
	}
	if got := fake.PublicKeyCalls() - calls; got != 1 {
		t.Fatalf("%d PublicKey calls to learn the rotation, want 1", got)
	}
	keys, err := c.Keys(ctx, profile)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.Active()
	if len(keys.SigningKeys) != 2 || !bytes.Equal(active.KeyID, newID) || keys.Fingerprint != first.Fingerprint ||
		!keys.Response.Equal(first.Response) {
		t.Fatalf("the adopted list: %+v", keys)
	}
	if k, ok := keys.SigningKey(old.KeyID); !ok || k.State != cipheron.SigningKeyVerifyOnly {
		t.Fatalf("the old key: %+v %v", k, ok)
	}
	// Old and new signatures verify, through the Client and offline.
	if ok, err := c.Verify(ctx, profile, []byte("before"), old.Bytes, old.KeyID); !ok || err != nil {
		t.Fatalf("an old signature: %v %v", ok, err)
	}
	s, _ := c.Sign(ctx, profile, []byte("after"))
	if !okWithKeys(keys.SigningKeys, []byte("after"), s.Bytes, s.KeyID) ||
		!okWithKeys(keys.SigningKeys, []byte("before"), old.Bytes, old.KeyID) ||
		okWithKeys(keys.SigningKeys, []byte("after"), s.Bytes, old.KeyID) ||
		okWithKeys(first.SigningKeys, []byte("after"), s.Bytes, s.KeyID) {
		t.Fatal("VerifyWithKeys")
	}
	// A Client that started before the rotation verifies a new signature by learning the list (Verify's own
	// re-fetch), and one that never fetched learns it on first use.
	late := newClient(t, fake.SocketPath(), cipheron.WithServerUID(myUID()))
	if ok, err := late.Verify(ctx, profile, []byte("after"), s.Bytes, s.KeyID); !ok || err != nil {
		t.Fatalf("a new Client's Verify: %v %v", ok, err)
	}
}

// TestVerifyRefetchesSparingly: a Verify naming a key id the Client does not know fetches the keys again only
// when the last fetch is old enough, so forged key ids cannot turn verifications into PublicKey calls.
func TestVerifyRefetchesSparingly(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 20*time.Second)
	s, err := c.Sign(ctx, profile, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	calls := fake.PublicKeyCalls()
	// Each answers ErrUnknownSigningKey — "nothing was verified", never (false, nil), which would read as a verdict
	// on the signature — and none costs a call.
	for range 20 {
		if ok, err := c.Verify(ctx, profile, []byte("x"), s.Bytes, random(t, 16)); ok || !errors.Is(err, cipheron.ErrUnknownSigningKey) {
			t.Fatalf("an unknown key id: %v %v; want ErrUnknownSigningKey", ok, err)
		}
	}
	if ok, err := c.Verify(ctx, profile, []byte("x"), s.Bytes, s.KeyID[:15]); ok || !errors.Is(err, cipheron.ErrUnknownSigningKey) {
		t.Fatalf("a short key id: %v %v; want ErrUnknownSigningKey", ok, err)
	}
	if got := fake.PublicKeyCalls() - calls; got != 0 {
		t.Fatalf("%d PublicKey calls for unknown key ids right after a fetch", got)
	}
}

// TestAListThatForgetsAKeyIsNotAdopted: a list that verifies but leaves out a key the Client knew — an older
// list replayed — is not adopted: the Client keeps every key, and old signatures keep verifying.
func TestAListThatForgetsAKeyIsNotAdopted(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 20*time.Second)
	fake.RotateSigning(profile)
	middle, err := c.Sign(ctx, profile, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	fake.RotateSigning(profile)
	if _, err := c.Sign(ctx, profile, []byte("n")); err != nil {
		t.Fatal(err)
	}
	if keys, _ := c.Keys(ctx, profile); len(keys.SigningKeys) != 3 {
		t.Fatalf("%d keys", len(keys.SigningKeys))
	}
	fake.SetMode(cipherontest.ForgetVerifyOnlyKeys)
	keys, err := c.Keys(ctx, profile)
	if err != nil || len(keys.SigningKeys) != 3 {
		t.Fatalf("a list forgetting a key was adopted: %d keys, %v", len(keys.SigningKeys), err)
	}
	if ok, err := c.Verify(ctx, profile, []byte("m"), middle.Bytes, middle.KeyID); !ok || err != nil {
		t.Fatalf("the forgotten key's signature: %v %v", ok, err)
	}
}

// TestAnIdentityChangeIsRefusedThroughRotations: a profile re-created (a new identity) is ErrServerKeyChanged —
// for Sign's unknown-key re-fetch too — while a key-context change (a master version listed) is adopted.
func TestAnIdentityChangeIsRefusedThroughRotations(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 20*time.Second)
	first, err := c.Keys(ctx, profile)
	if err != nil {
		t.Fatal(err)
	}
	fake.SetWriteVersion(profile, "v2")
	keys, err := c.Keys(ctx, profile)
	if err != nil || keys.ContextDigest == first.ContextDigest || keys.ContextDigest != fake.ContextDigest(profile) {
		t.Fatalf("a new master version's context digest was not adopted: %v", err)
	}
	if d, err := c.ContextDigest(ctx, profile); err != nil || d != fake.ContextDigest(profile) {
		t.Fatalf("ContextDigest: %q %v", d, err)
	}
	fake.Rekey(profile)
	for name, call := range map[string]func() error{
		"sign":    func() error { _, err := c.Sign(ctx, profile, []byte("x")); return err },
		"keys":    func() error { _, err := c.Keys(ctx, profile); return err },
		"encrypt": func() error { _, err := c.Encrypt(ctx, profile, []byte("x")); return err },
	} {
		if err := call(); !errors.Is(err, cipheron.ErrServerKeyChanged) || !errors.Is(err, cipheron.ErrServerIdentity) {
			t.Errorf("%s after the identity changed: %v", name, err)
		}
	}
}

// TestSignNamesAListedKey: Sign's answer is checked under the key its id names — a key that did not sign it is
// refused even when listed — and its signature under the answer's own say-so never counts.
func TestSignNamesAListedKey(t *testing.T) {
	fake := cipherontest.New(t, profile)
	fake.RotateSigning(profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 20*time.Second)
	if _, err := c.Sign(ctx, profile, []byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []cipherontest.Mode{cipherontest.OtherListedKeyID, cipherontest.UnknownKeyID,
		cipherontest.ForeignSignature, cipherontest.ShortSignature, cipherontest.ForeignResponseSignature} {
		fake.SetMode(mode)
		if s, err := c.Sign(ctx, profile, []byte("x")); !errors.Is(err, cipheron.ErrServerIdentity) || s.Bytes != nil {
			t.Errorf("mode %d: %v", mode, err)
		}
	}
}

// TestAnAnswerOfAnUnknownFormatIsRefused: a shared or derived profile's Encrypt or ReEncrypt answered with a
// ciphertext under a format byte this protocol does not have, signed by the profile's response key over the request,
// is refused (ErrBadResponse): cipheron writes format 4 there, and the client accepts no other format in such an
// answer. (Each format byte the client refuses, format 2 included: internal/client TestAnUnknownCiphertextFormatIsRefused.)
func TestAnAnswerOfAnUnknownFormatIsRefused(t *testing.T) {
	fake := cipherontest.New(t, profile, "people")
	fake.MakeDerived("people")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 30*time.Second)
	ct4, err := c.Encrypt(ctx, profile, []byte("row"))
	if kid, _ := cipheron.KeyID(ct4); err != nil || kid.Format != transport.FormatVersioned {
		t.Fatalf("Encrypt: %s %v", kid, err)
	}
	refused := func(err error) bool {
		return errors.Is(err, cipheron.ErrBadResponse) && !errors.Is(err, cipheron.ErrInvalidInput)
	}
	fake.SetMode(cipherontest.UnknownFormatCiphertext)
	if got, err := c.Encrypt(ctx, profile, []byte("row")); !refused(err) || got != nil {
		t.Errorf("Encrypt answered in an unknown format: %v, want ErrBadResponse", err)
	}
	if got, err := c.ReEncrypt(ctx, profile, ct4); !refused(err) || got != nil {
		t.Errorf("ReEncrypt answered in an unknown format: %v, want ErrBadResponse", err)
	}
	if got, err := c.Tenant("people", "t_1", nil).Encrypt(ctx, []byte("row")); !refused(err) || got != nil {
		t.Errorf("a derived profile answering an unknown format: %v, want ErrBadResponse", err)
	}
	fake.SetMode(cipherontest.Honest)
	if _, err := c.Tenant("people", "t_1", nil).Encrypt(ctx, []byte("row")); err != nil {
		t.Fatalf("the honest answer: %v", err)
	}
}

// TestEveryFormatDecrypts: format 4 across master versions decrypts with no re-encryption; ReEncrypt
// moves a row to the current version; a retired version is ErrKeyVersionUnavailable (not ErrInvalidInput), and
// listing it again restores the rows; the bytes of the removed format 2 are refused before anything is sent.
func TestEveryFormatDecrypts(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 30*time.Second)
	rows := map[string][]byte{}
	for i, version := range []string{"v1", "v1", "v2", "v2"} {
		fake.SetWriteVersion(profile, version)
		ct, err := c.Encrypt(ctx, profile, []byte(version))
		if err != nil {
			t.Fatal(err)
		}
		kid, err := cipheron.KeyID(ct)
		if err != nil || kid.Format != transport.FormatVersioned || kid.MasterVersion != version || kid.String() != version ||
			len(ct) != len(version)+transport.VersionedOverhead(version) {
			t.Fatalf("Encrypt under %s: %s %v", version, kid, err)
		}
		rows[fmt.Sprintf("%s#%d", version, i)] = ct
	}
	want := func(name string) string { return strings.SplitN(name, "#", 2)[0] }
	for name, ct := range rows {
		if pt, err := c.Decrypt(ctx, profile, ct); err != nil || string(pt) != want(name) {
			t.Errorf("Decrypt of %s: %q %v", name, pt, err)
		}
	}
	moved, err := c.ReEncrypt(ctx, profile, rows["v1#0"])
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := cipheron.KeyID(moved); kid.String() != "v2" {
		t.Fatalf("ReEncrypt of a v1 row is under %s, not v2", kid)
	}

	fake.RetireVersion(profile, "v1")
	for name, ct := range rows {
		_, err := c.Decrypt(ctx, profile, ct)
		if strings.HasPrefix(name, "v1#") {
			if !errors.Is(err, cipheron.ErrKeyVersionUnavailable) || errors.Is(err, cipheron.ErrInvalidInput) {
				t.Errorf("Decrypt of %s under a retired version: %v", name, err)
			}
			if _, err := c.ReEncrypt(ctx, profile, ct); !errors.Is(err, cipheron.ErrKeyVersionUnavailable) {
				t.Errorf("ReEncrypt of %s under a retired version: %v", name, err)
			}
		} else if err != nil {
			t.Errorf("Decrypt of %s with v1 retired: %v", name, err)
		}
	}
	fake.ListVersion(profile, "v1")
	for name, ct := range rows {
		if pt, err := c.Decrypt(ctx, profile, ct); err != nil || string(pt) != want(name) {
			t.Errorf("Decrypt of %s after un-retiring: %q %v", name, pt, err)
		}
	}

	// Not a ciphertext — cipheron's magic with a format this protocol does not have (9, or 2) included: refused here,
	// before anything is sent, as the caller's input (ErrInvalidInput), never ErrBadResponse.
	_, sent, _ := fake.Auth()
	newer := append([]byte("CPH1\x09"), make([]byte, 80)...)
	format2 := append([]byte("CPH1\x02"), make([]byte, 80)...)
	for _, junk := range [][]byte{nil, []byte("CPH1"), newer, format2, []byte("plaintext")} {
		want, notWant := cipheron.ErrInvalidInput, cipheron.ErrBadResponse
		if _, err := c.Decrypt(ctx, profile, junk); !errors.Is(err, want) || errors.Is(err, notWant) {
			t.Errorf("Decrypt of %q: %v, want %v", junk, err, want)
		}
		if _, err := c.ReEncrypt(ctx, profile, junk); !errors.Is(err, want) || errors.Is(err, notWant) {
			t.Errorf("ReEncrypt of %q: %v, want %v", junk, err, want)
		}
		if _, err := cipheron.KeyID(junk); !errors.Is(err, want) || errors.Is(err, notWant) {
			t.Errorf("KeyID of %q: %v, want %v", junk, err, want)
		}
	}
	if _, absent, _ := fake.Auth(); absent != sent {
		t.Errorf("junk was sent: %d requests", absent-sent)
	}
}
