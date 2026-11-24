package cipheron_test

// wave1_fake_test.go — the client's side of the design-gap program's wave 1, against the fake answering as an
// impostor would, or with what the client does not implement: the key statement checked against the fresh answer, the identity's suite and
// algorithms (tolerated in lists, refused for use), the cross-profile answer's second signature, the batches' and
// the objects' answers checked like the single operations'.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestTheKeyStatementIsChecked(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	for _, m := range []cipherontest.Mode{cipherontest.ForgedKeyStatement, cipherontest.MismatchedKeyStatement} {
		fake := cipherontest.New(t, "docs")
		fake.SetMode(m)
		c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
		if _, err := c.Encrypt(ctx, "docs", []byte("x")); !errors.Is(err, cipheron.ErrServerIdentity) {
			t.Fatalf("mode %d: %v", m, err)
		}
	}
	// Honest: the statement is the answer's, exported and imported offline.
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	st, err := c.KeyStatement(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	ex, err := st.Export()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipheron.ImportKeyStatement(ex, "docs", fake.Fingerprint("docs"), time.Minute); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := cipheron.ImportKeyStatement(bytes.Replace(ex, []byte(`"signature": "`), []byte(`"signature": "AA`), 1),
		"docs", fake.Fingerprint("docs"), time.Minute); !errors.Is(err, cipheron.ErrKeyStatement) {
		t.Fatalf("a tampered export: %v", err)
	}
	// maxAge 0 is refused, never read as "any age" (P10); the call without an age check has its own name.
	for _, age := range []time.Duration{0, -time.Second} {
		if _, err := cipheron.ImportKeyStatement(ex, "docs", fake.Fingerprint("docs"), age); !errors.Is(err, cipheron.ErrKeyStatement) {
			t.Fatalf("maxAge %v: %v", age, err)
		}
	}
	if _, err := cipheron.ImportKeyStatementAnyAge(ex, "docs", fake.Fingerprint("docs")); err != nil {
		t.Fatalf("any age: %v", err)
	}
	if _, err := cipheron.ImportKeyStatementAnyAge(ex, "docs", "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, cipheron.ErrKeyStatement) {
		t.Fatalf("any age, another pin: %v", err)
	}
}

func TestTheIdentityIsAgile(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	// No suite named: cipheron always writes it, and nothing signed covers its absence — refused as not the profile's
	// cipheron's answer.
	fake := cipherontest.New(t, "docs")
	fake.SetMode(cipherontest.NoHPKESuite)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer())
	if _, err := c.Keys(ctx, "docs"); !errors.Is(err, cipheron.ErrServerIdentity) || errors.Is(err, cipheron.ErrBadResponse) {
		t.Fatalf("an answer without a suite: %v, want ErrServerIdentity", err)
	}
	// An added identity key: fingerprint version 2 — the classical pin no longer matches; unpinned, it is tolerated
	// and nothing uses it.
	fake = cipherontest.New(t, "docs")
	fake.SetMode(cipherontest.AdditionalIdentityKey)
	sock := fake.ServeSocket(t)
	pinned := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	if _, err := pinned.Encrypt(ctx, "docs", []byte("x")); !errors.Is(err, cipheron.ErrServerIdentity) {
		t.Fatalf("a key added to a pinned classical identity: %v", err)
	}
	open := newClient(t, sock, cipheron.WithAnyServer())
	k, err := open.Keys(ctx, "docs")
	if err != nil || k.FingerprintVersion != 2 || k.Fingerprint == fake.Fingerprint("docs") {
		t.Fatalf("an identity with an added key: %+v %v", k, err)
	}
	ct, err := open.Encrypt(ctx, "docs", []byte("x"))
	if err != nil {
		t.Fatalf("encrypt beside an added key it does not use: %v", err)
	}
	if pt, err := open.Decrypt(ctx, "docs", ct); err != nil || string(pt) != "x" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	// A primary HPKE suite this client does not implement: the keys verify, sealing is refused.
	fake = cipherontest.New(t, "docs")
	fake.SetMode(cipherontest.UnknownHPKESuite)
	c = newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer())
	if k, err := c.Keys(ctx, "docs"); err != nil || k.HPKE != nil || k.FingerprintVersion != 2 {
		t.Fatalf("keys of an unknown suite: %+v %v", k, err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("x")); !errors.Is(err, cipheron.ErrBadResponse) {
		t.Fatalf("encrypt under an unknown suite: %v", err)
	}
	if _, err := c.Sign(ctx, "docs", []byte("x")); !errors.Is(err, cipheron.ErrBadResponse) {
		t.Fatalf("sign under an unknown suite: %v", err)
	}
	// A signing key of an algorithm this client does not implement: listed, the list verifies, the key is unusable.
	fake = cipherontest.New(t, "docs")
	fake.SetMode(cipherontest.UnknownSigningAlgorithm)
	c = newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	k, err = c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	var odd *cipheron.SigningKey
	for i := range k.SigningKeys {
		if k.SigningKeys[i].Algorithm == cipherontest.UnknownAlgorithm {
			odd = &k.SigningKeys[i]
		}
	}
	if odd == nil {
		t.Fatalf("the key of an unknown algorithm is not listed: %+v", k.SigningKeys)
	}
	if ok, err := cipheron.VerifyWithKeys(k.SigningKeys, []byte("d"), make([]byte, 64), odd.KeyID); ok || !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("a signature under the unknown algorithm's key, offline: %v %v", ok, err)
	}
	if ok, err := c.Verify(ctx, "docs", []byte("d"), make([]byte, 64), odd.KeyID); ok || !errors.Is(err, cipheron.ErrBadResponse) {
		t.Fatalf("a signature under the unknown algorithm's key: %v %v", ok, err)
	}
	if _, err := c.Sign(ctx, "docs", []byte("d")); err != nil {
		t.Fatalf("the other keys keep working: %v", err)
	}
}

func TestTheCrossProfileAnswerIsSignedByBoth(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "a", "b")
	sock := fake.ServeSocket(t)
	c := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("a", fake.Fingerprint("a")),
		cipheron.WithProfileFingerprint("b", fake.Fingerprint("b")))
	ct, err := c.Encrypt(ctx, "a", []byte("m"), cipheron.WithAssociatedData([]byte("k")))
	if err != nil {
		t.Fatal(err)
	}
	aad, keep := cipheron.WithAssociatedData([]byte("k")), cipheron.WithTargetAssociatedData([]byte("k"))
	moved, err := c.ReEncryptAcross(ctx, cipheron.Scope{Profile: "a"}, cipheron.Scope{Profile: "b"}, ct, aad, keep)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.Decrypt(ctx, "b", moved, aad); err != nil || string(pt) != "m" {
		t.Fatalf("the moved ciphertext: %q %v", pt, err)
	}
	fake.SetMode(cipherontest.NoSecondSignature)
	if _, err := c.ReEncryptAcross(ctx, cipheron.Scope{Profile: "a"}, cipheron.Scope{Profile: "b"}, ct,
		aad, keep); !errors.Is(err, cipheron.ErrServerIdentity) {
		t.Fatalf("an answer without the target's signature: %v", err)
	}
}

func TestBatchAnswersAreChecked(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	items := []cipheron.BatchItem{{Data: []byte("a")}, {Data: []byte("b"), AssociatedData: []byte("x")}}
	res, err := c.EncryptBatch(ctx, "docs", items)
	if err != nil || res[0].Err != nil || res[1].Err != nil {
		t.Fatalf("a batch: %+v %v", res, err)
	}
	for _, m := range []cipherontest.Mode{cipherontest.ForeignResponseSignature, cipherontest.NoResponseSignature} {
		fake.SetMode(m)
		if _, err := c.EncryptBatch(ctx, "docs", items); !errors.Is(err, cipheron.ErrServerIdentity) {
			t.Fatalf("mode %d: %v", m, err)
		}
	}
	for _, m := range []cipherontest.Mode{cipherontest.JunkCiphertext, cipherontest.LongCiphertext} {
		fake.SetMode(m)
		if _, err := c.EncryptBatch(ctx, "docs", items); !errors.Is(err, cipheron.ErrBadResponse) {
			t.Fatalf("mode %d: %v", m, err)
		}
	}
	fake.SetMode(cipherontest.GarbledPlaintext)
	if _, err := c.DecryptBatch(ctx, "docs", []cipheron.BatchItem{{Data: res[0].Value}}); !errors.Is(err, cipheron.ErrBadResponse) {
		t.Fatalf("a garbled plaintext in a batch: %v", err)
	}
	fake.SetMode(cipherontest.Honest)
	// The object helpers adopt a smaller limit from cipheron's refusal: every segment still in order.
	fake.SetBatchMaxItems(2)
	obj := bytes.Repeat([]byte("q"), 5*transport.MinSegmentSize+7)
	enc, err := c.EncryptObject(ctx, "docs", obj, cipheron.WithSegmentSize(transport.MinSegmentSize))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.DecryptObject(ctx, "docs", enc); err != nil || !bytes.Equal(got, obj) {
		t.Fatalf("an object over batches of two: %d %v", len(got), err)
	}
	if fake.BatchCalls() < 6 {
		t.Fatalf("%d batches for 6 segments each way, at most 2 per batch", fake.BatchCalls())
	}
}
