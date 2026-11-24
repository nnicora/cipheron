package transport

// identity.go — what makes a profile's identity extensible (crypto-agility): the HPKE suite its requests are sealed
// under, the algorithm of its response key and of each signing key, and keys ADDED to an identity after the
// profile was made. This release implements one suite and one algorithm and adds no key: these are the extension
// points, so that a post-quantum or hybrid key can later be added to an existing profile (Fingerprint version 2)
// instead of needing a new profile.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// HPKESuite names an HPKE suite by its RFC 9180 identifiers.
type HPKESuite struct {
	KEM, KDF, AEAD uint16
}

// ClassicalSuite is the one suite this release implements: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
var ClassicalSuite = HPKESuite{KEM: KEMID, KDF: KDFID, AEAD: AEADID}

// orClassical is s, or ClassicalSuite for the zero value (an identity built in memory before suites were named).
func (s HPKESuite) orClassical() HPKESuite {
	if s == (HPKESuite{}) {
		return ClassicalSuite
	}
	return s
}

// String is the suite's three ids, "0x0010/0x0001/0x0002".
func (s HPKESuite) String() string { return fmt.Sprintf("0x%04x/0x%04x/0x%04x", s.KEM, s.KDF, s.AEAD) }

// bytes is the suite's ids, 2 bytes each big-endian: what a fingerprint and a statement cover.
func (s HPKESuite) bytes() []byte {
	b := binary.BigEndian.AppendUint16(nil, s.KEM)
	b = binary.BigEndian.AppendUint16(b, s.KDF)
	return binary.BigEndian.AppendUint16(b, s.AEAD)
}

// SignatureAlgorithm is a signing or response key's algorithm: its number is the API's SignatureAlgorithm enum.
type SignatureAlgorithm uint32

const (
	// AlgorithmUnspecified is the enum's 0: never an algorithm.
	AlgorithmUnspecified SignatureAlgorithm = 0
	// AlgorithmEd25519 is Ed25519 (RFC 8032, pure): the one algorithm this release implements.
	AlgorithmEd25519 SignatureAlgorithm = 1
)

// orEd25519 is a, or AlgorithmEd25519 for 0 (a key built in memory before algorithms were named).
func (a SignatureAlgorithm) orEd25519() SignatureAlgorithm {
	if a == AlgorithmUnspecified {
		return AlgorithmEd25519
	}
	return a
}

// Implemented reports whether this package can verify (and cipheron make) signatures of a: Ed25519 only.
func (a SignatureAlgorithm) Implemented() bool { return a == AlgorithmEd25519 }

// IdentityKeyRole is what an additional identity key is for: its number is the API's IdentityKeyRole enum.
type IdentityKeyRole uint32

const (
	// RoleHPKE is a key requests may be sealed to.
	RoleHPKE IdentityKeyRole = 1
	// RoleResponse is a key answers may be signed by.
	RoleResponse IdentityKeyRole = 2
)

// IdentityKey is a key added to a profile's identity after it was made. The fingerprint covers it (version 2); this
// release makes none and uses none, and a client tolerates any role, suite and algorithm (the extension point).
type IdentityKey struct {
	Role IdentityKeyRole
	// Suite is an HPKE key's suite (zero for a response key).
	Suite HPKESuite
	// Algorithm is a response key's algorithm (0 for an HPKE key).
	Algorithm SignatureAlgorithm
	PublicKey []byte
}

const (
	// MaxIdentityKeyLen bounds one identity public key: room for a post-quantum key (ML-KEM-1024 is 1568 bytes,
	// ML-DSA-87 2592), and a bound for an unverified answer.
	MaxIdentityKeyLen = 4096
	// MaxAdditionalKeys bounds the keys added to one identity.
	MaxAdditionalKeys = 8
)

// algorithmID is what a fingerprint and a statement cover of an additional key's algorithm: the suite (6 bytes)
// for an HPKE key, the algorithm (4 bytes) for any other role.
func (e IdentityKey) algorithmID() []byte {
	if e.Role == RoleHPKE {
		return e.Suite.bytes()
	}
	return binary.BigEndian.AppendUint32(nil, uint32(e.Algorithm))
}

// encode is e as a fingerprint covers it: lp(role: 4) lp(algorithm id) lp(public key).
func (e IdentityKey) encode() []byte {
	return transcript(nil).addUint32(uint32(e.Role)).add(e.algorithmID()).add(e.PublicKey)
}

// sortedAdditional is each key's encoding, in canonical order (bytewise ascending).
func sortedAdditional(keys []IdentityKey) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = k.encode()
	}
	slices.SortFunc(out, bytes.Compare)
	return out
}

// validateAdditional checks the additional keys' form, whatever their role, suite and algorithm (a client
// tolerates what it does not know): at most MaxAdditionalKeys, each a role that is not 0 with a public key of 1 to
// MaxIdentityKeyLen bytes, and no key twice.
func validateAdditional(keys []IdentityKey) error {
	if len(keys) > MaxAdditionalKeys {
		return fmt.Errorf("cipheron: an identity has at most %d additional keys, not %d", MaxAdditionalKeys, len(keys))
	}
	enc := sortedAdditional(keys)
	for i, k := range keys {
		if k.Role == 0 {
			return errors.New("cipheron: an additional identity key has no role")
		}
		if len(k.PublicKey) == 0 || len(k.PublicKey) > MaxIdentityKeyLen {
			return fmt.Errorf("cipheron: an identity public key is 1 to %d bytes", MaxIdentityKeyLen)
		}
		if i > 0 && bytes.Equal(enc[i-1], enc[i]) {
			return errors.New("cipheron: an additional identity key is listed twice")
		}
	}
	return nil
}
