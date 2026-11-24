package transport

// tenant.go — what the protocol knows about tenants: a profile's tenancy, the tenant id's grammar, the tenant key
// blob's layout (the tenant key family, "CPT1": its header, the part anyone can read — everything but the wrapped
// private keys — and its wrap), a tenant key's fingerprint, and the tenant-bound message a derived profile signs. The
// blob is made and opened only by cipheron (the server's tenant key code, through SealTenantKey and TenantKeyItemKey); a
// client reads its header to know which key it holds, and to verify that key's signatures — without cipheron, but
// without proof either: the header is not authenticated until cipheron opens the blob (CreateTenantKey's and
// RewrapTenantKey's answers are signed over it).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nnicora/cipheron/wire/format"
)

// Tenancy is a profile's mode, fixed for its life. Its string is what the fingerprint, the key-context digest and
// the signing-key transcript carry, and a keyset's `kind`.
type Tenancy string

const (
	// TenancyShared is a profile whose keys serve every caller: the default.
	TenancyShared Tenancy = "shared"
	// TenancyPerTenantWrapped is a perTenant profile where every tenant has a key of its own (a tenant key blob,
	// made by CreateTenantKey and stored by the application), wrapped under the profile's tenant-wrapping key.
	TenancyPerTenantWrapped Tenancy = "perTenantWrapped"
	// TenancyPerTenantDerived is a perTenant profile where every tenant's keys are derived from the profile's keys
	// and the tenant id: nothing is stored, requests carry the tenant only, and the profile's own signing keys sign
	// TenantSignedMessage.
	TenancyPerTenantDerived Tenancy = "perTenantDerived"
)

// Valid reports whether t is one of the three tenancies.
func (t Tenancy) Valid() bool {
	return t == TenancyShared || t == TenancyPerTenantWrapped || t == TenancyPerTenantDerived
}

// PerTenant reports whether requests in a profile of tenancy t carry a tenant: wrapped or derived.
func (t Tenancy) PerTenant() bool {
	return t == TenancyPerTenantWrapped || t == TenancyPerTenantDerived
}

// Wrapped reports whether requests in a profile of tenancy t carry a tenant key blob, and whether CreateTenantKey
// and RewrapTenantKey serve it.
func (t Tenancy) Wrapped() bool { return t == TenancyPerTenantWrapped }

// HasSigningKeys reports whether a profile of tenancy t has signing keys of its own (shared and derived; a wrapped
// profile's tenant keys sign).
func (t Tenancy) HasSigningKeys() bool { return t == TenancyShared || t == TenancyPerTenantDerived }

// MaxTenantLen is the longest tenant id: 2048 bytes, the longest that URLs, ARNs and SPIFFE IDs reach, so an
// application can use the identifier it already has. It bounds what holds a tenant id: a tenant key blob (which
// records its tenant: MaxTenantKeyLen), a request, and the keys of cipheron's tenant caches.
const MaxTenantLen = 2048

// ValidTenant reports whether s is a tenant id: 1 to 2048 bytes of printable ASCII, 0x21 ('!') to 0x7E ('~') —
// letters, digits and every ASCII punctuation mark; no space, no control byte, nothing above 0x7E. It is exact and
// case-sensitive, and fits UUIDs, ULIDs, prefixed ids such as t_…, email addresses, URLs, ARNs, SPIFFE IDs and
// base64. It is the shape of an id, never a list of tenants: the host application decides which tenants exist.
//
// Why this shape. It is one byte range, which every client applies identically: no Unicode tables, no
// normalization, so one id is one byte string everywhere. No space, so no id has an invisible end ("acme" and
// "acme " would be two tenants with two keys). No control byte, so no id holds 0x00, which the HPKE info strings
// rely on to end where their length-prefixed fields begin (ResponseInfoTenant); and the audit trail, which records
// a refused request's tenant only when it is a valid id, holds no control characters and no non-ASCII look-alikes.
// "|" is allowed: the "|"-joined strings stay unambiguous, because a profile name cannot contain "|" and a tenant id
// is either their last field (RequestInfoTenant) or sits between the profile and a fixed suffix (the format-3
// message label). Every other encoding of a tenant id (the signed digests, the derived key's label, the blob, the
// audit trail's HMAC) frames it with its length. Every client is held to the same rule: spec/api.md
// documents it.
func ValidTenant(s string) bool {
	if len(s) == 0 || len(s) > MaxTenantLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < '!' || c > '~' {
			return false
		}
	}
	return true
}

// MaxProfileLen is the longest profile name: 63 bytes (ValidProfile).
const MaxProfileLen = 63

// ValidProfile reports whether name is a profile name: lower-case ASCII letters and digits in hyphen-separated words,
// starting with a letter, 1 to MaxProfileLen bytes — "^[a-z][a-z0-9]*(-[a-z0-9]+)*$". It is the one grammar of a profile
// name: cipheron's configuration accepts no other (config.ValidProfileName is this function), and every layout that
// carries a profile — a tenant key blob, a key statement, a key context — is refused with any other. It keeps "|" (the
// separator of the derivation labels and HPKE info strings) and "/" (the HTTP path segment) out of every name, so a
// label names exactly one profile; and it keeps control characters, bidirectional overrides and every other non-ASCII
// byte out of what an offline reader prints of a header no cipheron authenticated.
func ValidProfile(name string) bool {
	if len(name) == 0 || len(name) > MaxProfileLen || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && name[i-1] != '-' && i < len(name)-1:
		default:
			return false
		}
	}
	return true
}

// The tenant key blob, version 1 (what CreateTenantKey and RewrapTenantKey make; the one layout):
//
//	"CPT1" | version 1 (1) | keyID (16) | lp(profile) | lp(tenant) | signing public key (32) |
//	len(wrapping version) (1) | wrapping master version id | created (8) | salt (32) |
//	GCM nonce (12) | AES-256-GCM(storage key (32) || Ed25519 private key (64)) + tag (16)
//
// 226 bytes plus the profile, the tenant and the wrapping version id; at most MaxTenantKeyLen (2369). The salt
// (TenantKeySaltLen random bytes, new for every blob) is in the header, and the blob's own wrap key is derived from
// it (TenantKeyItemKey: HKDF-Expand of the tenant-wrapping key under an info string that carries the salt), so no AES
// key wraps two blobs. The layout is the tenant key blob kind's one scheme (catalog.go), written and read through it.
//
// lp is a 4-byte big-endian length and the bytes. The wrapping master version id is encoded as in a format-4
// ciphertext (one length byte, 1 to MaxMasterVersionIDLen bytes, ValidMasterVersionID); created is the tenant key's
// creation time, 8 bytes big-endian, Unix seconds, after 1970 (never 0) — RewrapTenantKey keeps it, so a service
// can apply its own interval to the tenant key. Everything before the nonce is the header, and is the AEAD's
// additional data: a blob whose keyID, profile, tenant, public key, wrapping version, creation time or salt was
// changed does not open.
const (
	TenantKeyMagic = "CPT1"
	// TenantKeyVersion is the blob's layout version, the one written and read; a blob of any other version is
	// refused.
	TenantKeyVersion = 1
	// TenantKeySaltLen is a blob's salt: 256 random bits.
	TenantKeySaltLen = 32
	// TenantKeyIDLen is the length of a tenant key's id: 128 random bits, new for every key, kept by a rewrap.
	TenantKeyIDLen = 16
	// TenantPrivateLen is the wrapped plaintext: the storage key (32) and the 64-byte Ed25519 private key.
	TenantPrivateLen = 32 + ed25519.PrivateKeySize
	// TenantSealedLen is the nonce, the wrapped private keys and the tag.
	TenantSealedLen = 12 + TenantPrivateLen + 16
	// tenantWrapFieldsLen is what the header holds after the public key, but the version id itself and the salt:
	// the id's length byte and the creation time.
	tenantWrapFieldsLen = 1 + 8
	// MaxTenantKeyLen is the longest blob, with the longest profile, tenant and wrapping version id (2369 bytes).
	MaxTenantKeyLen = len(TenantKeyMagic) + 1 + TenantKeyIDLen + 4 + MaxProfileLen + 4 + MaxTenantLen +
		ed25519.PublicKeySize + tenantWrapFieldsLen + MaxMasterVersionIDLen + TenantKeySaltLen + TenantSealedLen
)

// ErrTenantKey is the refusal of a blob that is not a tenant key blob of this layout, or (CheckTenantKey) is of
// another tenant or profile.
var ErrTenantKey = errors.New("cipheron: not a tenant key of this tenant in this profile")

// TenantKeyHeader is the readable part of a tenant key blob. Nothing in it is authenticated until cipheron
// opens the blob.
type TenantKeyHeader struct {
	// Version is the blob's layout version: TenantKeyVersion.
	Version          byte
	KeyID            []byte
	Profile          string
	Tenant           string
	SigningPublicKey ed25519.PublicKey
	// WrappingVersion names the tenant-wrapping key the blob is wrapped under: the master version id whose
	// tenant-wrapping key it is.
	WrappingVersion string
	// Created is the tenant key's creation time (UTC, seconds), after 1970: every blob records it.
	Created time.Time
	// Salt is the blob's salt (TenantKeySaltLen bytes; it aliases the blob), which its wrap key is derived under.
	Salt []byte
	// AAD is the header's bytes, the wrap's additional data; Sealed is the nonce, the wrapped keys and the tag.
	// Both alias the blob.
	AAD    []byte
	Sealed []byte
}

// Fingerprint is the tenant key's fingerprint (TenantFingerprint), from the header as read. It does not depend on
// the wrap: a rewrapped blob has its key's fingerprint.
func (h *TenantKeyHeader) Fingerprint() string {
	return TenantFingerprint(h.Profile, h.Tenant, h.KeyID, h.SigningPublicKey)
}

// AppendTenantKeyHeader appends the header of a blob — everything before the nonce: h's Version (which must be the
// version p writes), KeyID, Profile, Tenant, SigningPublicKey, WrappingVersion, Created and Salt — to dst. h's AAD and
// Sealed are ignored. It refuses any other version, and fields the parser would refuse: a key id not 16 bytes, a
// profile that is not a profile name (ValidProfile), an invalid tenant, a public key not 32 bytes, an invalid wrapping
// version id, no creation time or one not after 1970, a salt not TenantKeySaltLen bytes.
func AppendTenantKeyHeader(p *format.Policy, dst []byte, h *TenantKeyHeader) ([]byte, error) {
	w := format.Write(p, tenantKeys, 0)
	if uint32(h.Version) != w.Version() {
		return nil, fmt.Errorf("%w: a header of version %d is not written (only %d)", ErrTenantKey, h.Version,
			w.Version())
	}
	if len(h.Salt) != w.Suite().SaltLen() {
		return nil, fmt.Errorf("%w: a salt is %d bytes, not %d", ErrTenantKey, TenantKeySaltLen, len(h.Salt))
	}
	return format.AppendHeader(w, dst, *h, h.Salt)
}

// ParseTenantKey reads a tenant key blob's header and checks its layout: the magic, the version (one p reads: any
// other is refused), a profile name (ValidProfile), a valid tenant id, a valid wrapping version id, a creation time
// after 1970 (0 and negative are refused), the salt, and exactly the sealed part's length after the header. It does
// not open anything, and proves nothing about the blob.
func ParseTenantKey(p *format.Policy, blob []byte) (*TenantKeyHeader, error) {
	s, err := format.Marked(p, tenantKeys, blob)
	if err != nil {
		return nil, err
	}
	var h TenantKeyHeader
	n, ok := format.ParseHeader(s, blob, &h)
	if !ok {
		return nil, ErrTenantKey
	}
	salt := n - s.Suite().SaltLen()
	h.Version, h.Salt, h.AAD, h.Sealed = byte(s.Version()), blob[salt:n:n], blob[:n], blob[n:]
	return &h, nil
}

// TenantKeyItemKey derives the own wrap key of the blob whose header is h — over format.TenantBlobWrapInfo of its
// profile, tenant, wrapping version and salt — from wrapKey, the tenant-wrapping key of that version: what
// SealTenantKey seals with, and what opens h.Sealed with h.AAD as the additional data. It refuses a wrapKey of another
// length than the written scheme's suite takes, and a header of a version p does not read or whose salt is not its
// suite's length, before anything is derived.
func TenantKeyItemKey(p *format.Policy, wrapKey []byte, h *TenantKeyHeader) (format.ItemKey, error) {
	w := format.Write(p, tenantKeys, 0)
	if len(wrapKey) != w.Suite().KeyLen() {
		// The scheme's own refusal of a key of another length: it derives nothing.
		return w.ItemKey(wrapKey, "")
	}
	s, err := format.Read(p, tenantKeys, uint32(h.Version))
	if err != nil {
		return format.ItemKey{}, fmt.Errorf("cipheron: a tenant key blob of version %d; this cipheron reads version %d", h.Version,
			w.Version())
	}
	if len(h.Salt) != s.Suite().SaltLen() {
		return format.ItemKey{}, fmt.Errorf("cipheron: a tenant key blob's salt is %d bytes, not %d", len(h.Salt),
			s.Suite().SaltLen())
	}
	return s.ItemKey(wrapKey, s.Codec().info(s.Suite().Namespace(), h, h.Salt))
}

// SealTenantKey wraps private — a tenant key's storage key and 64-byte Ed25519 private key, TenantPrivateLen bytes,
// read only (it may be locked memory) — in a new blob of the scheme p writes, of h's key id, profile, tenant, signing
// public key, wrapping version and creation time, with a new salt from crypto/rand, under wrapKey (the tenant-wrapping
// key of h's wrapping version), and returns the blob: its header, then the nonce, the wrapped keys and the tag, the
// header the additional data. h's Version, Salt, AAD and Sealed are ignored. It does not check the private keys
// against the public key: the caller does.
func SealTenantKey(p *format.Policy, wrapKey []byte, h *TenantKeyHeader, private []byte) ([]byte, error) {
	if len(private) != TenantPrivateLen {
		return nil, fmt.Errorf("cipheron: a tenant key's private keys are %d bytes, not %d", len(private), TenantPrivateLen)
	}
	w := format.Write(p, tenantKeys, 0)
	salt := make([]byte, w.Suite().SaltLen())
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("cipheron: drawing a tenant key blob's salt: %w", err)
	}
	x := *h
	x.Version, x.Salt, x.AAD, x.Sealed = byte(w.Version()), salt, nil, nil
	blob, err := format.AppendHeader(w, make([]byte, 0, MaxTenantKeyLen), x, salt)
	if err != nil {
		return nil, err
	}
	key, err := TenantKeyItemKey(p, wrapKey, &x)
	if err != nil {
		return nil, err
	}
	aad := append([]byte(nil), blob...)
	return key.Seal(blob, private, aad), nil
}

// readLP reads one length-prefixed field of at most maxLen bytes.
func readLP(b []byte, maxLen int) (field, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if n > uint32(maxLen) || int(n) > len(b)-4 {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// TenantFingerprint is the string a client pins a tenant key by: "sha256:" and the hex SHA-256 of
// "cipheron/v1|tenant-fingerprint", the profile, the tenant, the key's id and its signing public key, each
// length-prefixed.
func TenantFingerprint(profile, tenant string, keyID []byte, signingPublicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(transcript(nil).addString(tenantFingerprintLabel).addString(profile).addString(tenant).
		add(keyID).add(signingPublicKey))
	return FingerprintPrefix + hex.EncodeToString(sum[:])
}

// MatchesTenantFingerprint reports whether fp is h's fingerprint, in constant time.
func MatchesTenantFingerprint(h *TenantKeyHeader, fp string) bool {
	return subtle.ConstantTimeCompare([]byte(h.Fingerprint()), []byte(fp)) == 1
}

// CheckTenantKey parses blob (ParseTenantKey) and checks that it names profile and tenant — the cheap refusal of a blob of
// another tenant or profile, before anything is opened.
func CheckTenantKey(p *format.Policy, blob []byte, profile, tenant string) (*TenantKeyHeader, error) {
	h, err := ParseTenantKey(p, blob)
	if err != nil {
		return nil, err
	}
	if h.Profile != profile || h.Tenant != tenant {
		return nil, fmt.Errorf("%w: it is tenant %q's key in profile %q", ErrTenantKey, h.Tenant, h.Profile)
	}
	return h, nil
}

// SameKeyID reports whether a and b are the same tenant key id, in constant time.
func SameKeyID(a, b []byte) bool {
	return len(a) == TenantKeyIDLen && subtle.ConstantTimeCompare(a, b) == 1
}

// TenantSignedMessage is what a perTenant derived profile's signing key signs for tenant (Sign returns a pure
// Ed25519 signature over it, RFC 8032):
//
//	lp("cipheron/v1|tenant-signature") lp(profile) lp(tenant) lp(data)
//
// A derived profile's tenants share the profile's signing keys, so the signature must name the tenant: one made for
// tenant A over some data never verifies as tenant B's over any data (the fields are length-prefixed: no tenant
// and data split the same bytes twice), nor as another profile's. It is never what a shared profile signs (the raw
// data, under keys of its own: a profile's tenancy and keys are fixed for its life).
func TenantSignedMessage(profile, tenant string, data []byte) []byte {
	return transcript(make([]byte, 0, 4*4+len(tenantSignatureLabel)+len(profile)+len(tenant)+len(data))).
		addString(tenantSignatureLabel).addString(profile).addString(tenant).add(data)
}

// VerifyTenant checks a derived profile's signature for tenant over data: signature over
// TenantSignedMessage(profile, tenant, data) under pub (a signing key of the profile's list, the one Sign's key_id
// names). Any failure is ErrAuth.
func VerifyTenant(pub ed25519.PublicKey, profile, tenant string, data, signature []byte) error {
	return verify(pub, TenantSignedMessage(profile, tenant, data), signature)
}
