package client

// ciphertextfits_test.go — the client's answer check of a ciphertext is a function of the policy it is given: under a
// test policy a test format (0xF4: the release's format-4 fields under a test suite with a 48-byte salt) is an answer of
// a master-version profile, its overhead the test scheme's; under the release the same bytes are a format the protocol
// does not have.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestCiphertextFitsReadsThePolicy(t *testing.T) {
	t.Parallel()
	rel := transport.Release()
	suite := format.TestSuite("HKDF-SHA256-Expand/AES-256-GCM (client test)", format.TestNamespace("client"), 32, 48, 12,
		16, sha256.New, func(key []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCMWithRandomNonce(b)
		})
	cts := transport.Ciphertexts()
	w := format.Write(rel, cts, 2) // the slot of format 4: a master version, no associated data
	if w.Version() != uint32(transport.FormatVersioned) {
		t.Fatalf("slot 2 writes format %d", w.Version())
	}
	rule := cts.Reads(3, 4, 5, 6, 0xF4)
	for slot := format.Slot(0); slot < 4; slot++ {
		v := format.Write(rel, cts, slot).Version()
		if slot == 2 {
			v = 0xF4
		}
		rule = rule.Writes(slot, v)
	}
	p, err := rel.With([]format.Entry{cts.Scheme(0xF4, "a test format", w.Codec(), format.SealedBy(suite, "data key"),
		format.ForSlot(2))}, rule)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	seal := func(p *format.Policy, names transport.Names, k transport.KeyID, aad []byte) []byte {
		s, err := transport.NewCiphertextSealer(p, names, key, k, "docs", "", aad)
		if err != nil {
			t.Fatal(err)
		}
		return s.Seal([]byte("seven b"))
	}
	test := seal(p, transport.NamesMasterVersion, transport.KeyID{MasterVersion: "v1"}, nil)
	if test[4] != 0xF4 {
		t.Fatalf("the test policy wrote format %#x", test[4])
	}
	released := seal(rel, transport.NamesMasterVersion, transport.KeyID{MasterVersion: "v1"}, nil)
	keyID := make([]byte, transport.TenantKeyIDLen)
	tenantKey := seal(rel, transport.NamesTenantKey, transport.KeyID{TenantKeyID: keyID}, nil)
	withAAD := seal(rel, transport.NamesMasterVersion, transport.KeyID{MasterVersion: "v1"}, []byte("row 7"))
	if len(test) == len(released) {
		t.Fatal("the test format's overhead is the release's: the test proves nothing about the overhead")
	}

	for _, c := range []struct {
		name    string
		p       *format.Policy
		ct      []byte
		n       int
		names   transport.Names
		keyID   []byte
		withAAD bool
		ok      bool
		err     error
	}{
		{"the test format under the test policy", p, test, 7, transport.NamesMasterVersion, nil, false, true, nil},
		{"the test format under the release", rel, test, 7, transport.NamesMasterVersion, nil, false, false, transport.ErrCiphertextFormat},
		{"format 4 under the test policy", p, released, 7, transport.NamesMasterVersion, nil, false, true, nil},
		{"format 4 under the release", rel, released, 7, transport.NamesMasterVersion, nil, false, true, nil},
		{"the test format for another plaintext length", p, test, 6, transport.NamesMasterVersion, nil, false, false, nil},
		{"the test format with associated data expected", p, test, 7, transport.NamesMasterVersion, nil, true, false, nil},
		{"the test format for a tenant key", p, test, 7, transport.NamesTenantKey, keyID, false, false, nil},
		{"format 5 without associated data expected", rel, withAAD, 7, transport.NamesMasterVersion, nil, false, false, nil},
		{"format 5 with associated data expected", rel, withAAD, 7, transport.NamesMasterVersion, nil, true, true, nil},
		{"format 3 under its key id", rel, tenantKey, 7, transport.NamesTenantKey, keyID, false, true, nil},
		{"format 3 under another key id", rel, tenantKey, 7, transport.NamesTenantKey, make([]byte, 15), false, false, nil},
		{"format 3 for a master version", rel, tenantKey, 7, transport.NamesMasterVersion, nil, false, false, nil},
	} {
		_, ok, err := ciphertextFits(c.p, c.ct, c.n, c.names, c.keyID, c.withAAD)
		if ok != c.ok || (c.err == nil) != (err == nil) || c.err != nil && !errors.Is(err, c.err) {
			t.Errorf("%s: ok %v, err %v; want %v, %v", c.name, ok, err, c.ok, c.err)
		}
	}
}
