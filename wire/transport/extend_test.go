package transport_test

// extend_test.go — the catalog refuses a second scheme of one byte, a second writer for a slot, a magic another kind
// has, a suite sharing another's label namespace and a sealed scheme without a suite; a suite derives only in its own
// namespace. Test formats of the ciphertext kind use a suite of their own (HKDF-SHA512 and AES-256-GCM with a 16-byte
// nonce, under the label namespace "cipheron-test/v1|"). That a format is added by a policy alone — written, read and
// opened through cipheron's envelope — is checked with cipheron's server.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

// The test formats: two that name a master version (without and with associated data) and one that names a tenant
// key.
const (
	formatTestTenant       byte = 0xF3
	formatTestVersioned    byte = 0xF4
	formatTestVersionedAAD byte = 0xF5
)

// gcm16 is AES-256-GCM with a 16-byte nonce field the AEAD draws itself: 4 random bytes, then the module's own random
// 12-byte nonce (cipher.NewGCMWithRandomNonce, so the test suite runs under GODEBUG=fips140=only too), laid out as
// nonce || ciphertext || tag, the 4 bytes authenticated as the end of the additional data: an AEAD whose overhead, 32,
// is not the stored suite's 28.
type gcm16 struct{ g cipher.AEAD }

func newGCM16(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCMWithRandomNonce(b)
	return gcm16{g}, err
}

func (a gcm16) NonceSize() int { return 0 }
func (a gcm16) Overhead() int  { return 4 + a.g.Overhead() }
func (a gcm16) Seal(dst, _, plaintext, ad []byte) []byte {
	extra := make([]byte, 4)
	_, _ = rand.Read(extra)
	return a.g.Seal(append(dst, extra...), nil, plaintext, append(append([]byte(nil), ad...), extra...))
}

func (a gcm16) Open(dst, _, body, ad []byte) ([]byte, error) {
	if len(body) < 4 {
		return nil, errors.New("short")
	}
	return a.g.Open(dst, nil, body[4:], append(append([]byte(nil), ad...), body[:4]...))
}

// testSuite is a suite of the test's own namespace.
func testSuite() format.Suite {
	return format.TestSuite("HKDF-SHA512-Expand/AES-256-GCM-16", format.TestNamespace(""), 32, 32, 16, 16, sha512.New,
		newGCM16)
}

func TestTheCatalogRefuses(t *testing.T) {
	t.Parallel()
	release, s := transport.Release(), testSuite()
	f4 := transport.CiphertextSchemeForTest(formatTestVersioned, "test format 4", transport.NamesMasterVersion, false,
		s, "data key")
	slot := transport.CiphertextSlotForTest(transport.NamesMasterVersion, false)
	writer := func(extra ...uint32) format.Rule {
		return transport.Ciphertexts().Reads(append([]uint32{3, 4, 5, 6}, extra...)...).
			Writes(transport.CiphertextSlotForTest(transport.NamesTenantKey, false), 3).
			Writes(transport.CiphertextSlotForTest(transport.NamesTenantKey, true), 6).
			Writes(transport.CiphertextSlotForTest(transport.NamesMasterVersion, true), 5)
	}
	for _, c := range []struct {
		name    string
		schemes []format.Entry
		rules   []format.Rule
		want    string
	}{
		{"a second scheme of one byte", []format.Entry{transport.CiphertextSchemeForTest(4, "another format 4",
			transport.NamesMasterVersion, false, s, "data key")}, nil, "the ciphertext kind has a scheme of version 4 already"},
		{"a second writer for a slot", []format.Entry{f4}, []format.Rule{writer(0xF4).Writes(slot, 4).Writes(slot, 0xF4)},
			"the ciphertext kind writes format 4 for slot 2 already"},
		{"a suite sharing a namespace", []format.Entry{f4, transport.CiphertextSchemeForTest(0xF6, "test format 6",
			transport.NamesMasterVersion, true, testSuite(), "data key")}, nil, `the label namespace "cipheron-test/v1|" is suite`},
		{"a sealed scheme without a suite", []format.Entry{transport.CiphertextSchemeForTest(0xF6, "test format 6",
			transport.NamesMasterVersion, false, format.Suite{}, "data key")}, nil, "is sealed and has no suite"},
		{"a magic another kind has", []format.Entry{format.NewStoredKind[format.Codec[transport.KeyID]]("a test kind",
			"CPH", format.Unsealed, transport.ErrCiphertext, func(uint32, uint32) error { return nil }).Scheme(1,
			"version 1", nil)}, nil, `the magic "CPH" is the ciphertext kind's "CPH1", or begins it, or is begun by it`},
	} {
		if _, err := release.With(c.schemes, c.rules...); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.HasPrefix(err.Error(), "cipheron: layout registry: ") {
			t.Errorf("%s: %v; want %q", c.name, err, c.want)
		}
	}
}

// TestASuiteDerivesOnlyInItsNamespace: a scheme derives under a label in its suite's namespace — the namespace first,
// or behind a 4-byte length — and refuses any other, and a key of another length, before anything is derived.
func TestASuiteDerivesOnlyInItsNamespace(t *testing.T) {
	t.Parallel()
	s := format.Write(transport.Release(), transport.Ciphertexts(), transport.CiphertextSlotForTest(transport.NamesTenantKey, false))
	key := bytes.Repeat([]byte{1}, transport.CiphertextKeyLen)
	for _, info := range []string{"cipheron/v1|docs|t|message", "\x00\x00\x00\x1ccipheron/v1|tenant-blob-wrap"} {
		if _, err := s.ItemKey(key, info); err != nil {
			t.Fatalf("%q: %v", info, err)
		}
	}
	for _, info := range []string{"cipheron-test/v1|x", "", "\x00\x00\x00\x40cipheron/v1|short", "\x01\x00\x00\x0ccipheron/v1|"} {
		if _, err := s.ItemKey(key, info); err == nil ||
			err.Error() != `cipheron: a label outside the namespace "cipheron/v1|" of the suite HKDF-SHA256-Expand/AES-256-GCM` {
			t.Fatalf("%q: %v", info, err)
		}
	}
	if _, err := s.ItemKey(key[:31], "cipheron/v1|x"); err == nil || err.Error() != "cipheron: the storage key is 31 bytes, not 32" {
		t.Fatalf("a short key: %v", err)
	}
}
