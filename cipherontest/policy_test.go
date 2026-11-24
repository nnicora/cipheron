package cipherontest

// policy_test.go — the fake reads and writes the policy it holds: under a test policy whose master-version writer is a
// test format (0xF4: the release's format-4 fields under a test suite with a 48-byte salt), the fake writes that format
// and opens it; a fake of the release (New) refuses it and still writes format 4, which the test policy also reads.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"testing"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestTheFakeReadsAndWritesItsPolicy(t *testing.T) {
	t.Parallel()
	rel := transport.Release()
	suite := format.TestSuite("HKDF-SHA256-Expand/AES-256-GCM (fake test)", format.TestNamespace("fake"), 32, 48, 12, 16,
		sha256.New, func(key []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCMWithRandomNonce(b)
		})
	cts := transport.Ciphertexts()
	rule := cts.Reads(3, 4, 5, 6, 0xF4)
	for slot := format.Slot(0); slot < 4; slot++ {
		v := format.Write(rel, cts, slot).Version()
		if v == uint32(transport.FormatVersioned) {
			v = 0xF4
		}
		rule = rule.Writes(slot, v)
	}
	w := format.Write(rel, cts, 2)
	p, err := rel.With([]format.Entry{cts.Scheme(0xF4, "a test format", w.Codec(), format.SealedBy(suite, "data key"),
		format.ForSlot(w.Slot()))}, rule)
	if err != nil {
		t.Fatal(err)
	}

	s := newServer(t, p, "docs")
	k := s.profile("docs")
	ct := s.encryptVersioned(k, "docs", "", []byte("a row"), nil)
	if ct[4] != 0xF4 {
		t.Fatalf("the fake of the test policy wrote format %#x", ct[4])
	}
	if pt, err := s.open(k, "docs", "", nil, ct, nil); err != nil || string(pt) != "a row" {
		t.Fatalf("the fake of the test policy does not open its own format: %q, %v", pt, err)
	}

	released := New(t, "docs")
	rk := released.profile("docs")
	if _, err := released.open(rk, "docs", "", nil, ct, nil); err == nil {
		t.Fatal("a fake of the release opened a test format")
	}
	old := released.encryptVersioned(rk, "docs", "", []byte("before"), nil)
	if old[4] != transport.FormatVersioned {
		t.Fatalf("a fake of the release wrote format %#x", old[4])
	}
	// The test policy reads format 4: the fake of the test policy opens a format-4 ciphertext under its own keys.
	own := s.encryptVersioned(k, "docs", "", []byte("x"), []byte("aad"))
	if own[4] != transport.FormatVersionedAAD {
		t.Fatalf("the test policy writes format %#x with associated data", own[4])
	}
	if pt, err := s.open(k, "docs", "", nil, own, []byte("aad")); err != nil || string(pt) != "x" {
		t.Fatalf("format 5 under the test policy: %q, %v", pt, err)
	}
}
