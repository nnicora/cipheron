package transport

// ciphertext.go — the stored ciphertexts: the ciphertext family ("CPH1") and its four formats, the key a ciphertext's
// header names (KeyID), and how one is sealed and opened (NewCiphertextSealer, NewCiphertextOpener: cipheron's
// the server's envelope code and the test server use them). A client reads the header to check a ciphertext's form
// before sending it, and a service reads it to find the rows a migration still has to move (ParseKeyID).

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nnicora/cipheron/wire/format"
)

// The ciphertext formats. Every one opens with CiphertextMagic and a format byte, its header ends with the salt — the
// per-ciphertext HKDF-Expand salt — and it ends with the AES-256-GCM nonce (12), the ciphertext and the tag (16).
//
//	format 3  "CPH1" | 3 | tenant key id (16) | salt (32) | nonce | ct+tag
//	          A perTenant wrapped profile's: made under the storage key of the tenant key blob whose id it carries.
//	format 4  "CPH1" | 4 | len (1) | master version id (len) | salt (32) | nonce | ct+tag
//	          A shared or perTenant derived profile's: made under the data key of its master version.
//	format 5  format 4's layout with format byte 5: made WITH caller associated data.
//	format 6  format 3's layout with format byte 6: made WITH caller associated data.
//
// Each is a scheme of the ciphertext kind (catalog.go), declared with what its header names, whether it is made with
// associated data, and its suite (format.HKDFSHA256AESGCM): ParseKeyID reads every one through it, and a writer takes
// the format its policy writes for its slot (NewCiphertextSealer).
//
// Formats 5 and 6 record that the ciphertext was made with associated data (the request's associated_data): the
// AEAD's additional data is then the header, lp(profile), lp(tenant) and lp(associated data), and the format byte
// (in the header) says that it is required — a Decrypt without it is refused before anything is tried, and one
// with other associated data fails the tag. A ciphertext made without associated data is format 3 or 4.
//
// In format 4 the master version id is the configured id itself, behind ONE length byte: 1 to
// MaxMasterVersionIDLen bytes of [A-Za-z0-9._-] (ValidMasterVersionID) — readable in a stored row (a migration
// queries by it), and unambiguous: its length is explicit and bounded, so no two ids encode the same bytes and the
// salt always starts where the id ends. The header — everything before the nonce — is the AEAD's additional data,
// followed by lp(profile) and lp(tenant) (tenant empty in a shared profile; lp a 4-byte big-endian length), so a
// ciphertext whose version or salt was changed, or presented in another profile or for another tenant, fails the
// tag; and the version also selects the key, so a changed one derives another key as well.
const (
	CiphertextMagic = "CPH1"
	// FormatTenantKey is format 3, FormatVersioned format 4.
	FormatTenantKey byte = 3
	FormatVersioned byte = 4
	// FormatVersionedAAD is format 4 made with associated data, FormatTenantKeyAAD format 3.
	FormatVersionedAAD byte = 5
	FormatTenantKeyAAD byte = 6

	// CiphertextKeyLen is the length of the key a stored item is made under (a data key, a tenant's storage key, a
	// tenant-wrapping key) and of every item's own key: 256 bits (format.HKDFSHA256AESGCM's KeyLen).
	CiphertextKeyLen = 32
	// CiphertextSaltLen, CiphertextNonceLen and CiphertextTagLen are every format's salt, GCM nonce and tag.
	CiphertextSaltLen  = 32
	CiphertextNonceLen = 12
	CiphertextTagLen   = 16

	// TenantKeyHeaderLen and TenantKeyOverhead are format 3's (53, 81).
	TenantKeyHeaderLen = len(CiphertextMagic) + 1 + TenantKeyIDLen + CiphertextSaltLen
	TenantKeyOverhead  = TenantKeyHeaderLen + CiphertextNonceLen + CiphertextTagLen
	// versionedFixedLen is format 4's header but the master version id: magic, format, the id's length byte and
	// the salt (38).
	versionedFixedLen = len(CiphertextMagic) + 1 + 1 + CiphertextSaltLen
	// VersionedMinOverhead and VersionedMaxOverhead bound what format 4 adds to a plaintext: 67 with a 1-byte
	// master version id, 98 with a 32-byte one (VersionedOverhead).
	VersionedMinOverhead = versionedFixedLen + 1 + CiphertextNonceLen + CiphertextTagLen
	VersionedMaxOverhead = versionedFixedLen + MaxMasterVersionIDLen + CiphertextNonceLen + CiphertextTagLen

	// MaxMasterVersionIDLen is the longest master key version id.
	MaxMasterVersionIDLen = 32
)

// VersionedHeaderLen is format 4's header length for a master version id of that length.
func VersionedHeaderLen(versionID string) int { return versionedFixedLen + len(versionID) }

// VersionedOverhead is what format 4 adds to a plaintext under master version versionID.
func VersionedOverhead(versionID string) int {
	return VersionedHeaderLen(versionID) + CiphertextNonceLen + CiphertextTagLen
}

// ValidMasterVersionID reports whether s is a master key version id: 1 to 32 bytes of [A-Za-z0-9._-]. It keeps
// "|" (every label's separator) and "/" out, and fits ids like "v2" and "2026-12".
func ValidMasterVersionID(s string) bool {
	if len(s) == 0 || len(s) > MaxMasterVersionIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// readVersionID reads a master version id behind one length byte, and checks it (ValidMasterVersionID).
func readVersionID(b []byte) (id, rest []byte, ok bool) {
	if len(b) < 1 {
		return nil, nil, false
	}
	n := int(b[0])
	if n == 0 || n > MaxMasterVersionIDLen || n > len(b)-1 || !ValidMasterVersionID(string(b[1:1+n])) {
		return nil, nil, false
	}
	return b[1 : 1+n], b[1+n:], true
}

// ErrAssociatedData is the refusal of a ciphertext sent without the associated data it was made with (format 5 or
// 6), or with associated data it was not made with (format 3 or 4); also of associated data over
// MaxAssociatedDataLen. A client refuses it before sending; cipheron answers it CIPHERON_ASSOCIATED_DATA.
var ErrAssociatedData = errors.New("cipheron: the associated data does not match the ciphertext's format")

// CheckAssociatedData reports whether a ciphertext of id can be decrypted with associated data aad: required (not
// empty) for formats 5 and 6, refused for the others, at most MaxAssociatedDataLen. ErrAssociatedData otherwise.
func CheckAssociatedData(id KeyID, aad []byte) error {
	switch {
	case len(aad) > MaxAssociatedDataLen:
		return fmt.Errorf("%w: associated data is at most %d bytes, not %d", ErrAssociatedData, MaxAssociatedDataLen, len(aad))
	case id.AssociatedData && len(aad) == 0:
		return fmt.Errorf("%w: the ciphertext was made with associated data (format %d) and none is given", ErrAssociatedData, id.Format)
	case !id.AssociatedData && len(aad) > 0:
		return fmt.Errorf("%w: the ciphertext was made without associated data (format %d) and some is given", ErrAssociatedData, id.Format)
	}
	return nil
}

// ErrTargetAssociatedData is the refusal of a re-encryption that gives the stored ciphertext's associated data and
// none for the new ciphertext (CheckReEncryptAssociatedData). It is ErrAssociatedData too. A client refuses it before
// sending; cipheron answers it CIPHERON_ASSOCIATED_DATA, with TargetAssociatedDataMessage.
var ErrTargetAssociatedData = fmt.Errorf("%w: associated data for the stored ciphertext and none for the new one",
	ErrAssociatedData)

// ErrAssociatedDataChanged is the refusal of a re-encryption whose new ciphertext would be bound to other associated
// data than the stored one's (CheckReEncryptAssociatedData) — other bytes, or associated data where the stored
// ciphertext has none. It is ErrAssociatedData too. A re-encryption keeps the binding: changing it makes the same
// plaintext authentic for another row, record, object position or tenant, which is a decrypt followed by an encrypt.
// A client refuses it before sending. cipheron serves it only to a caller entry granted decrypt on the stored
// ciphertext's profile and encrypt on the profile the new ciphertext is made in — decided with the grants, before
// anything is decrypted — and answers any other entry PERMISSION_DENIED.
var ErrAssociatedDataChanged = fmt.Errorf("%w: a re-encryption keeps the stored ciphertext's associated data, and "+
	"to_associated_data differs from it", ErrAssociatedData)

// CheckReEncryptAssociatedData is a re-encryption's associated-data rule: ReEncrypt within a profile and across
// profiles, and each item of ReEncryptBatch. The new ciphertext is bound to the stored one's associated data: toAAD is
// aad, byte for byte. Associated data for the stored ciphertext (aad) with none for the new one (toAAD) is
// ErrTargetAssociatedData: the binding would be dropped without a word, which nobody may ask for. Any other difference
// — other bytes, or associated data for the new ciphertext only — is ErrAssociatedDataChanged: a re-binding, which only
// a caller entry holding decrypt and encrypt may ask cipheron for. The rule is on emptiness where it speaks of none:
// the protocol's bytes fields have no presence, so an empty field is none.
func CheckReEncryptAssociatedData(aad, toAAD []byte) error {
	switch {
	case len(aad) > 0 && len(toAAD) == 0:
		return ErrTargetAssociatedData
	case !bytes.Equal(aad, toAAD):
		return ErrAssociatedDataChanged
	}
	return nil
}

// ErrCiphertext is the refusal of bytes that are not a cipheron ciphertext of a known format: a wrong magic, an
// unknown format, a malformed header, or fewer bytes than the format's overhead.
var ErrCiphertext = errors.New("cipheron: not a cipheron ciphertext")

// ErrCiphertextFormat is the refusal of a ciphertext with cipheron's magic and a format byte that is not one of the
// formats (3, 4, 5, 6). It wraps ErrCiphertext, so errors.Is(err, ErrCiphertext) still holds.
var ErrCiphertextFormat = fmt.Errorf("%w: a format this protocol does not have", ErrCiphertext)

// ErrNotDecrypted is the refusal of a ciphertext that does not decrypt (Opener): a modified byte, another profile, another
// tenant, another key, other associated data. It names no cause, on purpose, and it is not ErrCiphertext: the bytes
// are a ciphertext, which this key and these names do not open.
var ErrNotDecrypted = errors.New("cipheron: the ciphertext could not be decrypted")

// KeyID names the key a ciphertext was made under — what a service needs to find the rows a migration has to move.
// It is what a ciphertext's header holds: the ciphertext kind's schemes read and write it (the salt, the header's last
// bytes, aside).
type KeyID struct {
	// Format is the ciphertext's format: FormatTenantKey, FormatVersioned, FormatVersionedAAD or
	// FormatTenantKeyAAD.
	Format byte
	// AssociatedData reports a ciphertext made with associated data (format 5 or 6): it decrypts only with the same
	// associated data.
	AssociatedData bool
	// MasterVersion names the master version whose data key a format-4 ciphertext was made under (format 3: empty —
	// a wrapped tenant's ciphertexts are the tenant key's, whichever wrap its blob has).
	MasterVersion string
	// TenantKeyID is a format-3 ciphertext's tenant key id (16 bytes, a copy): the id of the blob it needs.
	TenantKeyID []byte
	// HeaderLen is the length of the ciphertext's header: everything before the nonce.
	HeaderLen int
}

// NamesOf is what the header of a ciphertext of k's format names under p (NamesNoKey for a format p does not read).
func NamesOf(p *format.Policy, k KeyID) Names {
	s, err := format.Read(p, ciphertexts, uint32(k.Format))
	if err != nil {
		return NamesNoKey
	}
	return s.Codec().names()
}

// OverheadOf is what a ciphertext of k adds to its plaintext under p: its header and the suite's overhead; 0 for a
// format p does not read.
func OverheadOf(p *format.Policy, k KeyID) int {
	s, err := format.Read(p, ciphertexts, uint32(k.Format))
	if err != nil {
		return 0
	}
	return k.HeaderLen + s.Suite().Overhead()
}

// String names the key for a log line: "tenant-key:<hex id>" (formats 3 and 6), the master version id (formats 4
// and 5).
func (k KeyID) String() string {
	switch NamesOf(release, k) {
	case NamesTenantKey:
		return "tenant-key:" + hex.EncodeToString(k.TenantKeyID)
	case NamesMasterVersion:
		return k.MasterVersion
	}
	return "unknown"
}

// Versioned reports a ciphertext under a master version's data key: format 4 or 5 (a format of this release whose
// header names a master version).
func (k KeyID) Versioned() bool { return NamesOf(release, k) == NamesMasterVersion }

// TenantKey reports a ciphertext under a tenant key: format 3 or 6 (a format of this release whose header names a
// tenant key).
func (k KeyID) TenantKey() bool { return NamesOf(release, k) == NamesTenantKey }

// Overhead is what the ciphertext adds to its plaintext: its header, the nonce and the tag. 0 for a KeyID of no
// format of this release.
func (k KeyID) Overhead() int { return OverheadOf(release, k) }

// ParseKeyID reads a ciphertext's header and names its key. It checks the magic, the format, the header's
// layout (format 4: a valid master version id) and that the ciphertext is at least the format's overhead long
// (an empty plaintext); it decrypts nothing and proves nothing — the header is authenticated only when cipheron
// opens the ciphertext. Anything else is ErrCiphertext: ErrCiphertextFormat (which wraps it) for the right magic
// and a format p does not read. A tenant key id is a copy: the KeyID holds nothing of ciphertext.
func ParseKeyID(p *format.Policy, ciphertext []byte) (KeyID, error) {
	k, err := ReadKeyID(p, ciphertext)
	if err == nil && k.TenantKeyID != nil {
		k.TenantKeyID = bytes.Clone(k.TenantKeyID)
	}
	return k, err
}

// ReadKeyID is ParseKeyID without the copy: a tenant key id is a sub-slice of ciphertext. For a caller that reads the
// KeyID while it holds the ciphertext unchanged (cipheron's opener checks a ciphertext's tenant key id before anything
// is derived, and opening it in place leaves its header as it was).
func ReadKeyID(p *format.Policy, ciphertext []byte) (KeyID, error) {
	s, err := format.Marked(p, ciphertexts, ciphertext)
	if err != nil {
		return KeyID{}, err
	}
	return readKeyID(s, ciphertext)
}

// readKeyID reads the header of ciphertext, of scheme s.
func readKeyID(s *format.Scheme[ciphertextCodec], ciphertext []byte) (KeyID, error) {
	var k KeyID
	n, ok := format.ParseHeader(s, ciphertext, &k)
	if !ok {
		return KeyID{}, ErrCiphertext
	}
	k.Format, k.AssociatedData, k.HeaderLen = byte(s.Version()), s.Codec().associatedData(), n
	return k, nil
}

// ReadKeyIDNaming is ReadKeyID for a ciphertext of a format whose header names names (NamesTenantKey: formats 3 and 6;
// NamesMasterVersion: formats 4 and 5): a ciphertext of another format is ErrCiphertext, refused before its header is
// read. It looks the format up once — the check cipheron's opener runs on every ciphertext before anything is derived.
func ReadKeyIDNaming(p *format.Policy, ciphertext []byte, names Names) (KeyID, error) {
	s, err := format.Marked(p, ciphertexts, ciphertext)
	if err != nil {
		return KeyID{}, err
	}
	if s.Codec().names() != names {
		return KeyID{}, ErrCiphertext
	}
	return readKeyID(s, ciphertext)
}

// AppendVersionedHeader appends a format-4 header — magic, format, the master version id behind its length byte
// and the salt — to dst. It refuses an invalid version id or a salt not CiphertextSaltLen bytes.
func AppendVersionedHeader(p *format.Policy, dst []byte, versionID string, salt []byte) ([]byte, error) {
	return AppendVersionedHeaderFormat(p, dst, FormatVersioned, versionID, salt)
}

// AppendVersionedHeaderFormat is AppendVersionedHeader for format 4 or 5 (made with associated data): any format p
// reads whose header names a master version.
func AppendVersionedHeaderFormat(p *format.Policy, dst []byte, f byte, versionID string, salt []byte) ([]byte, error) {
	s, err := format.Read(p, ciphertexts, uint32(f))
	if err != nil || s.Codec().names() != NamesMasterVersion {
		return nil, fmt.Errorf("cipheron: format %d has no master version header", f)
	}
	k := KeyID{MasterVersion: versionID}
	// The key name first, then the salt: nothing is written to dst before both are checked.
	if saltLen := s.Suite().SaltLen(); len(salt) != saltLen {
		if _, err := format.AppendHeader(s, nil, k, nil); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("cipheron: a salt is %d bytes, not %d", saltLen, len(salt))
	}
	return format.AppendHeader(s, dst, k, salt)
}

// ciphertextAdditionalData is a ciphertext's AEAD additional data: its header, lp(profile) and lp(tenant), and — for a
// format made with associated data (withAAD) — lp(aad).
func ciphertextAdditionalData(withAAD bool, header []byte, profile, tenant string, aad []byte) []byte {
	n := len(header) + 8 + len(profile) + len(tenant)
	if withAAD {
		n += 4 + len(aad)
	}
	ad := make([]byte, 0, n)
	ad = append(ad, header...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(profile)))
	ad = append(ad, profile...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(tenant)))
	ad = append(ad, tenant...)
	if withAAD {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(aad)))
		ad = append(ad, aad...)
	}
	return ad
}

// NewCiphertextSealer draws a salt and derives the key of one new ciphertext: of the format p writes for a key named
// as names (NamesTenantKey or NamesMasterVersion), with associated data when aad is not empty (its slot), under key —
// the key k names: the storage key of the tenant key whose id is k.TenantKeyID, or the data key of master version
// k.MasterVersion (a derived tenant's storage key of it) — for tenant ("" in a shared profile) in profile. key is read
// here only: the sealer holds the ciphertext's own key schedule and nothing of key. It refuses a key name the header
// cannot hold, and a key of another length than the suite's; the caller checks the associated data's length.
func NewCiphertextSealer(p *format.Policy, names Names, key []byte, k KeyID, profile, tenant string, aad []byte,
) (*Sealer, error) {
	slot, ok := ciphertextSlot(names, len(aad) > 0)
	if !ok {
		return nil, fmt.Errorf("cipheron: no ciphertext format is written for %s", names)
	}
	s := format.Write(p, ciphertexts, slot)
	header, err := format.AppendHeader(s, nil, k, nil)
	if err != nil {
		return nil, err
	}
	suite := s.Suite()
	salt := header[len(header)-suite.SaltLen():]
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("cipheron: drawing a salt: %w", err)
	}
	c := s.Codec()
	ik, err := s.ItemKey(key, c.info(suite.Namespace(), profile, tenant, k, salt))
	if err != nil {
		return nil, err
	}
	return &Sealer{key: ik, overhead: suite.Overhead(), header: header,
		ad: ciphertextAdditionalData(c.associatedData(), header, profile, tenant, aad)}, nil
}

// NewCiphertextOpener derives the key of ciphertext, whose header k names (ParseKeyID's, of this ciphertext), from
// key — the key the header names: the caller chose it by it — for tenant ("" in a shared profile) in profile, with the
// associated data aad it was made with, and returns its opener; a ciphertext that does not decrypt is ErrNotDecrypted.
// It checks nothing the caller checks first: that the format is the one the caller reads, and the associated data's
// presence (CheckAssociatedData). A k that is not this ciphertext's header, or of a format p does not read, is
// ErrCiphertext.
func NewCiphertextOpener(p *format.Policy, key []byte, k KeyID, profile, tenant string, ciphertext, aad []byte,
) (*Opener, error) {
	s, err := format.Read(p, ciphertexts, uint32(k.Format))
	if err != nil {
		return nil, ErrCiphertext
	}
	minHeader, maxHeader, _ := s.Bounds()
	if k.HeaderLen < minHeader || k.HeaderLen > maxHeader || k.HeaderLen > len(ciphertext) {
		return nil, ErrCiphertext
	}
	header := ciphertext[:k.HeaderLen]
	suite, c := s.Suite(), s.Codec()
	ik, err := s.ItemKey(key, c.info(suite.Namespace(), profile, tenant, k, header[len(header)-suite.SaltLen():]))
	if err != nil {
		return nil, err
	}
	return &Opener{key: ik, body: ciphertext[k.HeaderLen:],
		ad: ciphertextAdditionalData(c.associatedData(), header, profile, tenant, aad)}, nil
}

// Sealer makes one stored item, split where the key it is made under stops being needed: its constructor
// (NewCiphertextSealer) draws the salt and derives the item's own key — the only step that reads the key, done while
// the caller holds the key's locked memory open — and Seal encrypts the plaintext under that derived key, after the
// caller has closed it again. A Sealer holds the item's AES key schedule (heap, as every AEAD's) and nothing of the key
// it was derived from. One sealer makes one item: its salt names the item's key.
type Sealer struct {
	key      format.ItemKey
	overhead int
	header   []byte
	ad       []byte
}

// Seal encrypts plaintext and returns the item: its header, then the nonce, the ciphertext and the tag.
func (s *Sealer) Seal(plaintext []byte) []byte {
	out := make([]byte, len(s.header), len(s.header)+s.overhead+len(plaintext))
	copy(out, s.header)
	return s.key.Seal(out, plaintext, s.ad)
}

// Opener opens one stored item, split as Sealer is: its constructor (NewCiphertextOpener) checks nothing the caller
// has not and derives the item's own key; Open decrypts, after the key's locked memory is closed again. An item that
// does not decrypt is ErrNotDecrypted.
type Opener struct {
	key format.ItemKey
	// body is the item after its header: the nonce, the ciphertext and the tag.
	body []byte
	ad   []byte
}

// Open decrypts the item into a new buffer; one that does not decrypt is ErrNotDecrypted.
func (o *Opener) Open() ([]byte, error) { return o.open(false) }

// OpenInPlace is Open decrypting into the item's own buffer, after its header: the plaintext returned is
// item[headerLen:headerLen+n], and nothing else holds it (wipe it there once used) — the AEAD moves the ciphertext down
// over the nonce and decrypts it there. The header is left as it was; the rest of the body is overwritten — on a
// failure too (zeroed: no unauthenticated plaintext is left), so the buffer is not an item afterwards. For a caller
// that owns the buffer and reads nothing of it but its header later.
func (o *Opener) OpenInPlace() ([]byte, error) { return o.open(true) }

// open opens the body (nonce, ciphertext and tag, as the AEAD reads them) under the additional data: into a new
// buffer, or (inPlace) into the body's own (the additional data is always a buffer of its own: it never overlaps).
func (o *Opener) open(inPlace bool) ([]byte, error) {
	var dst []byte
	if inPlace {
		dst = o.body[:0]
	}
	plaintext, ok := o.key.Open(dst, o.body, o.ad)
	if !ok {
		return nil, ErrNotDecrypted
	}
	return plaintext, nil
}
