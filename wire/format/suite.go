package format

// suite.go — the cryptography of a sealed scheme (Suite) and one item's derived key (ItemKey).
//
// ONE KEY PER ITEM. A data key serves for its master version's whole life, and a random 96-bit GCM nonce bounds one key
// to 2^32 encryptions (NIST SP 800-38D, section 8.3) — a bound a busy profile could pass, and that a process keeping no
// state across restarts could not count. So the key an item is made under never encrypts: each item is encrypted under
// its own key, derived with HKDF-Expand (RFC 5869 section 2.3, SP 800-56C's expansion step) over the scheme's label
// followed by a fresh random salt the header carries. Two items share a key only if their salts collide, which a
// 256-bit random salt makes negligible however many are written.
//
// EXPAND ONLY, NOT EXTRACT-THEN-EXPAND. The keys items are made under are uniformly random 256-bit keys (drawn by the
// module's DRBG, or HKDF-Expand outputs of a master key version), so each is a pseudorandom key as HKDF-Expand wants
// one; HKDF-Extract over it with the salt as the extraction salt would use one key both as HMAC key material and as
// input keying material, and costs a second HMAC per item for nothing.
//
// The nonce is drawn inside the Go Cryptographic Module (cipher.NewGCMWithRandomNonce, which lays its output out as
// nonce || ciphertext || tag — exactly every sealed layout's tail), so the encryption is the module's approved GCM
// service and the repository's check-gcm-nonce rule holds. The salt is drawn by crypto/rand, the module's DRBG, and the
// derivation is the module's HKDF.
//
// A SUITE OWNS ITS LABEL NAMESPACE. Every label a suite derives under begins with its namespace, or with a 4-byte
// big-endian length whose first byte is 0x00 and then the namespace (a length-prefixed label); it refuses any other
// before anything is derived. A namespace is printable ASCII ending with its only "|", so no namespace begins another,
// and NewCatalog refuses two suites of one namespace: two suites never derive under the same info string, so a suite
// added later never derives a key another derives, whatever key both are given.
//
// A SUITE IS CLOSED. Suite is a struct with one unexported pointer: its only values are HKDFSHA256AESGCM's (the same
// value on every call) and TestSuite's (test code only: make check-label-namespace refuses the name elsewhere, and its
// namespace is a TestNamespace). No type outside this package can be a Suite.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"

	"github.com/nnicora/cipheron/internal/zeroize"
)

// maxSaltLen bounds a suite's salt.
const maxSaltLen = 64

// Suite is the cryptography of a Sealed scheme: how an item's own key is derived from the key the item is made under,
// and the AEAD that seals the item under it, under a label namespace it owns. Only HKDFSHA256AESGCM and TestSuite make
// one; the zero Suite is none, and NewCatalog refuses it for a Sealed kind. Suites are compared with == (a Suite holds
// one pointer).
type Suite struct{ s *suite }

type suite struct {
	name string
	ns   Namespace
	// keyLen is the length of the key an item is made under and of the item's own key; saltLen the salt's.
	keyLen, saltLen int
	// nonceLen and tagLen are what the AEAD adds: nonce || ciphertext || tag.
	nonceLen, tagLen int
	hash             func() hash.Hash
	// newAEAD makes the AEAD under an item's own key, drawing its nonces inside the module.
	newAEAD func(key []byte) (cipher.AEAD, error)
}

// hkdfSHA256AESGCM is HKDFSHA256AESGCM's one value.
var hkdfSHA256AESGCM = Suite{&suite{
	name: "HKDF-SHA256-Expand/AES-256-GCM", ns: protocolNamespace,
	keyLen: 32, saltLen: 32, nonceLen: 12, tagLen: 16,
	hash: sha256.New, newAEAD: newAESGCM,
}}

// HKDFSHA256AESGCM is the suite of every Sealed scheme of this release: HKDF-SHA256-Expand (RFC 5869 section 2.3,
// expand only: the keys items are made under are uniformly random 256-bit keys) and AES-256-GCM with the module's
// random 96-bit nonce (cipher.NewGCMWithRandomNonce, the approved GCM service; make check-gcm-nonce), 32-byte keys and
// salts, under the protocol's namespace "cipheron/v1|". Every call returns the same value.
func HKDFSHA256AESGCM() Suite { return hkdfSHA256AESGCM }

// newAESGCM is AES-256-GCM under key with a nonce the module draws (cipher.NewGCMWithRandomNonce).
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// TestSuite is a suite for a test's scheme: name, ns (a TestNamespace: any other panics), the key, salt, nonce and tag
// lengths, the HKDF hash and the AEAD under an item's own key (drawing its own nonce: nonce || ciphertext || tag).
// Lengths a layout cannot hold (key below 16, salt outside 16 to 64, tag below 12, nonce below 0) panic, as does a
// missing name, hash or AEAD. Each call is a new suite. Only test code calls it: make check-label-namespace refuses the
// identifier in any non-test file.
func TestSuite(name string, ns Namespace, keyLen, saltLen, nonceLen, tagLen int, h func() hash.Hash,
	newAEAD func(key []byte) (cipher.AEAD, error),
) Suite {
	switch {
	case name == "" || h == nil || newAEAD == nil:
		panic(fmt.Errorf("%w: a suite has a name, a hash and an AEAD", errRegistry))
	case !strings.HasPrefix(ns.s, testNamespacePrefix) || !validNamespace(ns.s):
		panic(fmt.Errorf("%w: suite %s: %q is not a test's label namespace (TestNamespace)", errRegistry, name, ns.s))
	case keyLen < 16 || saltLen < 16 || saltLen > maxSaltLen || nonceLen < 0 || tagLen < 12:
		panic(fmt.Errorf("%w: suite %s: key, salt, nonce or tag lengths out of bounds", errRegistry, name))
	}
	return Suite{&suite{name: name, ns: ns, keyLen: keyLen, saltLen: saltLen, nonceLen: nonceLen, tagLen: tagLen,
		hash: h, newAEAD: newAEAD}}
}

// Name names the suite ("HKDF-SHA256-Expand/AES-256-GCM"); "" for the zero Suite.
func (s Suite) Name() string {
	if s.s == nil {
		return ""
	}
	return s.s.name
}

// Namespace is the label namespace the suite owns; the zero Namespace for the zero Suite.
func (s Suite) Namespace() Namespace {
	if s.s == nil {
		return Namespace{}
	}
	return s.s.ns
}

// KeyLen is the length of the key an item is made under and of the item's own key; 0 for the zero Suite.
func (s Suite) KeyLen() int {
	if s.s == nil {
		return 0
	}
	return s.s.keyLen
}

// SaltLen is the length of an item's salt, for a Stored kind; 0 for the zero Suite.
func (s Suite) SaltLen() int {
	if s.s == nil {
		return 0
	}
	return s.s.saltLen
}

// Overhead is what the AEAD adds after an item's header: the nonce and the tag; 0 for the zero Suite.
func (s Suite) Overhead() int {
	if s.s == nil {
		return 0
	}
	return s.s.nonceLen + s.s.tagLen
}

// owns reports whether info is in the suite's namespace: it begins with the namespace, or with a 4-byte length whose
// first byte is 0x00 and then the namespace.
func (s *suite) owns(info string) bool {
	ns := s.ns.s
	if strings.HasPrefix(info, ns) {
		return true
	}
	if len(info) < 4 || info[0] != 0 {
		return false
	}
	n, body := uint32(info[0])<<24|uint32(info[1])<<16|uint32(info[2])<<8|uint32(info[3]), info[4:]
	return uint64(n) <= uint64(len(body)) && int(n) >= len(ns) && strings.HasPrefix(body, ns)
}

// itemKey derives an item's own key from key — the key the item is made under, keyName in a refusal — over info (the
// scheme's label, then the item's salt; in the suite's namespace) and returns the suite's AEAD under it. The slice
// HKDF-Expand returned is wiped once the AEAD holds its key schedule — but not every copy of the key: Expand produces
// it as the last HMAC block, which stays in the HMAC state's buffers on the heap, and the AES key schedule (the key,
// expanded) lives as long as the AEAD; both are reclaimed, unzeroed, by the collector (cipheron's security documentation, "What
// is in locked memory, and what is not").
func (s Suite) itemKey(key []byte, keyName, info string) (ItemKey, error) {
	if len(key) != s.s.keyLen {
		return ItemKey{}, fmt.Errorf("cipheron: the %s is %d bytes, not %d", keyName, len(key), s.s.keyLen)
	}
	if !s.s.owns(info) {
		return ItemKey{}, fmt.Errorf("cipheron: a label outside the namespace %q of the suite %s", s.s.ns.s, s.s.name)
	}
	k, err := hkdf.Expand(s.s.hash, key, info, s.s.keyLen)
	if err != nil {
		return ItemKey{}, err
	}
	defer zeroize.Bytes(k)
	aead, err := s.s.newAEAD(k)
	if err != nil {
		return ItemKey{}, err
	}
	return ItemKey{aead: aead}, nil
}

// ItemKey is the own key of one item, derived: what seals or opens that item after the key it was derived from is
// closed again (the split a caller holding locked memory needs). It holds the AEAD's key schedule (heap, as every
// AEAD's) and nothing of the key it was derived from. A value: holding it allocates nothing more than the AEAD. The zero
// ItemKey is none.
type ItemKey struct{ aead cipher.AEAD }

// Seal appends nonce || ciphertext || tag of plaintext under ad to dst.
func (k ItemKey) Seal(dst, plaintext, ad []byte) []byte { return k.aead.Seal(dst, nil, plaintext, ad) }

// Open decrypts body (nonce || ciphertext || tag) under ad, appending the plaintext to dst; with dst = body[:0] it
// decrypts in place. It reports false when body does not decrypt, and then zeroes what it wrote and, in place, all of
// body: no unauthenticated plaintext is left, whatever the AEAD does on a failure.
func (k ItemKey) Open(dst, body, ad []byte) ([]byte, bool) {
	out, err := k.aead.Open(dst, nil, body, ad)
	if err != nil {
		spare := dst[len(dst):cap(dst)]
		clear(spare[:min(len(spare), len(body))])
		return nil, false
	}
	return out, true
}
