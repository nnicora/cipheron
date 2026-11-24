package transport

// catalog.go — the protocol's versioned items, declared as data (wire/format): their kinds, every scheme of
// this release, and what this release reads and writes of each (Release). Every reader and writer of those bytes takes
// a *format.Policy and finds its scheme through it:
//
//   - a reader of a stored item (a ciphertext "CPH1", a tenant key blob "CPT1", a segmented object "CPS1") looks the
//     scheme up by the item's magic and byte (format.Marked) and reads the header with the scheme's codec
//     (format.ParseHeader); an encrypted JSON field's value by its prefix, an exported key statement by its token;
//   - a key statement is read by the version in its second field (format.Read); a transcript or seal info, which
//     carries no version, is rebuilt under each version read (format.Each), the written one first;
//   - a writer takes the scheme the policy writes for its slot (format.Write): a ciphertext's slot is what its header
//     names and whether it is made with associated data; every other kind has one slot.
//
// What a scheme's header names, whether it requires caller associated data and its overhead are the scheme's (its
// codec and its suite), never a comparison of format bytes. A magic or a byte no scheme read has is refused as its
// kind refuses it (ErrCiphertext and ErrCiphertextFormat, ErrTenantKey, ErrSegmented).
//
// Nothing here changes after initialisation: a test that adds a version builds its own policy (Release().With).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nnicora/cipheron/wire/format"
)

// Names is what a stored layout's header names: the key its item was made under, which a reader needs before it can
// open the item (a migration reads it to find the rows still under an old key).
type Names uint8

const (
	// NamesNoKey is a layout whose header names no key: a segmented object, whose segments are ciphertexts that each
	// name their own.
	NamesNoKey Names = iota
	// NamesTenantKey is a layout whose header names a tenant key by its id: the item was made under the storage key
	// of the tenant key blob of that id (formats 3 and 6).
	NamesTenantKey
	// NamesMasterVersion is a layout whose header names a master version by its id: the item was made under a key of
	// that version (formats 4 and 5: its data key, or a derived tenant's storage key; a tenant key blob: its
	// tenant-wrapping key).
	NamesMasterVersion
)

// String names what a header names, for an error.
func (n Names) String() string {
	switch n {
	case NamesNoKey:
		return "no key"
	case NamesTenantKey:
		return "a tenant key"
	case NamesMasterVersion:
		return "a master version"
	}
	return fmt.Sprintf("names(%d)", uint8(n))
}

// must is v while the package is initialised; a refusal is a programming error, and panics.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// ----- the ciphertext ("CPH1")

// ciphertextCodec is a ciphertext scheme's codec: its header's fields, what they name, whether its items are made with
// caller associated data, and the info an item's own key is derived under (the suite's namespace ns first).
type ciphertextCodec interface {
	format.Codec[KeyID]
	names() Names
	associatedData() bool
	info(ns format.Namespace, profile, tenant string, k KeyID, salt []byte) string
}

// ciphertexts is the ciphertext kind: its magic, and its refusals — ErrCiphertext for bytes that are not one of its
// formats, ErrCiphertextFormat (naming the format byte) for its magic with a byte no format read has.
var ciphertexts = format.NewStoredKind[ciphertextCodec]("ciphertext", CiphertextMagic, format.Sealed, ErrCiphertext,
	func(got, _ uint32) error { return fmt.Errorf("%w (format %d)", ErrCiphertextFormat, got) })

// The ciphertext's slots: what the header names, made with caller associated data or without.
const (
	slotTenantKey format.Slot = iota
	slotTenantKeyAAD
	slotMasterVersion
	slotMasterVersionAAD
)

// ciphertextSlot is the slot of a ciphertext whose header names names, made with associated data or not.
func ciphertextSlot(names Names, aad bool) (format.Slot, bool) {
	switch {
	case names == NamesTenantKey && !aad:
		return slotTenantKey, true
	case names == NamesTenantKey:
		return slotTenantKeyAAD, true
	case names == NamesMasterVersion && !aad:
		return slotMasterVersion, true
	case names == NamesMasterVersion:
		return slotMasterVersionAAD, true
	}
	return 0, false
}

// Ciphertexts is the ciphertext kind.
func Ciphertexts() *format.Kind[ciphertextCodec] { return ciphertexts }

// ciphertextScheme declares ciphertext format v: its slot is the one its codec names, so a scheme cannot be declared
// for a slot its header does not fit.
func ciphertextScheme(v byte, name, keyName string, c ciphertextCodec) format.Entry {
	slot, _ := ciphertextSlot(c.names(), c.associatedData())
	return ciphertexts.Scheme(uint32(v), name, c, format.SealedBy(format.HKDFSHA256AESGCM(), keyName),
		format.ForSlot(slot))
}

// tenantKeyIDHeader is the fields of formats 3 and 6: the tenant key id (16). aad: format 6. Its Parse returns the
// tenant key id as a sub-slice of the ciphertext (ParseKeyID copies it).
type tenantKeyIDHeader struct{ aad bool }

func (tenantKeyIDHeader) Layout() format.Layout {
	return format.Layout{Fields: []format.Field{{Name: "tenant key id", Min: TenantKeyIDLen, Max: TenantKeyIDLen}}}
}

func (tenantKeyIDHeader) Size(KeyID) int { return TenantKeyIDLen }

func (tenantKeyIDHeader) Append(dst []byte, k KeyID) ([]byte, error) {
	if len(k.TenantKeyID) != TenantKeyIDLen {
		return nil, fmt.Errorf("cipheron: a tenant key id is %d bytes, not %d", TenantKeyIDLen, len(k.TenantKeyID))
	}
	return append(dst, k.TenantKeyID...), nil
}

func (tenantKeyIDHeader) Parse(b []byte) (KeyID, int, bool) {
	if len(b) < TenantKeyIDLen {
		return KeyID{}, 0, false
	}
	return KeyID{TenantKeyID: b[:TenantKeyIDLen:TenantKeyIDLen]}, TenantKeyIDLen, true
}

func (tenantKeyIDHeader) names() Names           { return NamesTenantKey }
func (h tenantKeyIDHeader) associatedData() bool { return h.aad }

func (tenantKeyIDHeader) info(ns format.Namespace, profile, tenant string, _ KeyID, salt []byte) string {
	return format.TenantMessageInfo(ns, profile, tenant, salt)
}

// masterVersionHeader is the fields of formats 4 and 5: the master version id behind one length byte. aad: format 5.
type masterVersionHeader struct{ aad bool }

func (masterVersionHeader) Layout() format.Layout {
	return format.Layout{Fields: []format.Field{{Name: "master version id", Prefix: 1, Min: 1,
		Max: MaxMasterVersionIDLen}}}
}

func (masterVersionHeader) Size(k KeyID) int { return 1 + len(k.MasterVersion) }

func (masterVersionHeader) Append(dst []byte, k KeyID) ([]byte, error) {
	if !ValidMasterVersionID(k.MasterVersion) {
		return nil, fmt.Errorf("cipheron: %q is not a master key version id", k.MasterVersion)
	}
	return append(append(dst, byte(len(k.MasterVersion))), k.MasterVersion...), nil
}

func (masterVersionHeader) Parse(b []byte) (KeyID, int, bool) {
	id, _, ok := readVersionID(b)
	if !ok {
		return KeyID{}, 0, false
	}
	return KeyID{MasterVersion: string(id)}, 1 + len(id), true
}

func (masterVersionHeader) names() Names           { return NamesMasterVersion }
func (h masterVersionHeader) associatedData() bool { return h.aad }

func (masterVersionHeader) info(ns format.Namespace, profile, tenant string, k KeyID, salt []byte) string {
	return format.VersionedMessageInfo(ns, profile, k.MasterVersion, tenant, salt)
}

// ----- the tenant key blob ("CPT1")

// tenantKeyCodec is a tenant key blob scheme's codec: its header's fields, and the info a blob's own wrap key is
// derived under (the suite's namespace ns first, behind a length).
type tenantKeyCodec interface {
	format.Codec[TenantKeyHeader]
	info(ns format.Namespace, h *TenantKeyHeader, salt []byte) string
}

// tenantKeys is the tenant key blob kind: its magic, and its refusal (ErrTenantKey) of anything that is not one of its
// layouts — another magic, a version it does not read, a malformed header.
var tenantKeys = format.NewStoredKind[tenantKeyCodec]("tenant key blob", TenantKeyMagic, format.Sealed, ErrTenantKey,
	func(uint32, uint32) error { return ErrTenantKey })

// TenantKeys is the tenant key blob kind.
func TenantKeys() *format.Kind[tenantKeyCodec] { return tenantKeys }

// HasTenantKeyMagic reports whether b begins with the tenant key blob's magic, whatever follows it.
func HasTenantKeyMagic(b []byte) bool {
	return len(b) >= len(TenantKeyMagic) && string(b[:len(TenantKeyMagic)]) == TenantKeyMagic
}

// tenantKeyBlobV1 is version 1's fields (tenant.go): key id (16), lp(profile), lp(tenant), signing public key (32),
// the wrapping master version id behind one length byte, created (8). Its Parse reads them; the frame reads the salt
// and exactly the sealed part after it.
type tenantKeyBlobV1 struct{}

func (tenantKeyBlobV1) Layout() format.Layout {
	return format.Layout{Fields: []format.Field{
		{Name: "key id", Min: TenantKeyIDLen, Max: TenantKeyIDLen},
		{Name: "profile", Prefix: 4, Min: 1, Max: MaxProfileLen},
		{Name: "tenant", Prefix: 4, Min: 1, Max: MaxTenantLen},
		{Name: "signing public key", Min: ed25519.PublicKeySize, Max: ed25519.PublicKeySize},
		{Name: "wrapping master version id", Prefix: 1, Min: 1, Max: MaxMasterVersionIDLen},
		{Name: "created", Min: 8, Max: 8},
	}, Plaintext: TenantPrivateLen}
}

func (tenantKeyBlobV1) Size(h TenantKeyHeader) int {
	return TenantKeyIDLen + 4 + len(h.Profile) + 4 + len(h.Tenant) + ed25519.PublicKeySize + tenantWrapFieldsLen +
		len(h.WrappingVersion)
}

func (tenantKeyBlobV1) Append(dst []byte, h TenantKeyHeader) ([]byte, error) {
	if h.Created.IsZero() || h.Created.Unix() <= 0 {
		return nil, fmt.Errorf("%w: no creation time, or one not after 1970", ErrTenantKey)
	}
	created := h.Created.Unix()
	switch {
	case len(h.KeyID) != TenantKeyIDLen, !ValidProfile(h.Profile), !ValidTenant(h.Tenant),
		len(h.SigningPublicKey) != ed25519.PublicKeySize, !ValidMasterVersionID(h.WrappingVersion):
		return nil, ErrTenantKey
	}
	dst = append(dst, h.KeyID...)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(h.Profile)))
	dst = append(dst, h.Profile...)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(h.Tenant)))
	dst = append(dst, h.Tenant...)
	dst = append(dst, h.SigningPublicKey...)
	dst = append(dst, byte(len(h.WrappingVersion)))
	dst = append(dst, h.WrappingVersion...)
	return binary.BigEndian.AppendUint64(dst, uint64(created)), nil
}

func (tenantKeyBlobV1) Parse(b []byte) (TenantKeyHeader, int, bool) {
	all := len(b)
	if len(b) < TenantKeyIDLen {
		return TenantKeyHeader{}, 0, false
	}
	h := TenantKeyHeader{KeyID: b[:TenantKeyIDLen]}
	b = b[TenantKeyIDLen:]
	profile, b, ok := readLP(b, MaxProfileLen)
	if !ok || !ValidProfile(string(profile)) {
		return TenantKeyHeader{}, 0, false
	}
	tenant, b, ok := readLP(b, MaxTenantLen)
	if !ok || !ValidTenant(string(tenant)) {
		return TenantKeyHeader{}, 0, false
	}
	if len(b) < ed25519.PublicKeySize {
		return TenantKeyHeader{}, 0, false
	}
	h.SigningPublicKey, b = b[:ed25519.PublicKeySize], b[ed25519.PublicKeySize:]
	var wv []byte
	if wv, b, ok = readVersionID(b); !ok || len(b) < 8 {
		return TenantKeyHeader{}, 0, false
	}
	created := int64(binary.BigEndian.Uint64(b[:8]))
	if created <= 0 {
		return TenantKeyHeader{}, 0, false
	}
	h.WrappingVersion = string(wv)
	h.Created = time.Unix(created, 0).UTC()
	h.Profile, h.Tenant = string(profile), string(tenant)
	return h, all - len(b) + 8, true
}

func (tenantKeyBlobV1) info(ns format.Namespace, h *TenantKeyHeader, salt []byte) string {
	return format.TenantBlobWrapInfo(ns, h.Profile, h.Tenant, h.WrappingVersion, salt)
}

// ----- the segmented object ("CPS1")

// objects is the segmented object kind: its magic, and its refusal (ErrSegmented) of anything that is not one of its
// layouts. A container: its header names no key, and it encrypts nothing itself (its segments are ciphertexts made
// with associated data, each naming its own key).
var objects = format.NewStoredKind[format.Codec[SegmentedHeader]]("segmented object", SegmentedMagic,
	format.Unsealed, ErrSegmented, func(uint32, uint32) error { return ErrSegmented })

// segmentedV1 is version 1's fields: object id (16) | segment size (4) | count (4). Its Parse reads the header alone
// (a streaming reader has nothing more), and refuses a header that is not valid.
type segmentedV1 struct{}

func (segmentedV1) Layout() format.Layout {
	return format.Layout{Fields: []format.Field{
		{Name: "object id", Min: ObjectIDLen, Max: ObjectIDLen},
		{Name: "segment size", Min: 4, Max: 4},
		{Name: "count", Min: 4, Max: 4},
	}}
}

func (segmentedV1) Size(SegmentedHeader) int { return ObjectIDLen + 4 + 4 }

func (segmentedV1) Append(dst []byte, h SegmentedHeader) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	dst = append(dst, h.ObjectID...)
	dst = binary.BigEndian.AppendUint32(dst, h.SegmentSize)
	return binary.BigEndian.AppendUint32(dst, h.Count), nil
}

func (segmentedV1) Parse(b []byte) (SegmentedHeader, int, bool) {
	if len(b) < ObjectIDLen+4+4 {
		return SegmentedHeader{}, 0, false
	}
	h := SegmentedHeader{ObjectID: append([]byte(nil), b[:ObjectIDLen]...)}
	h.SegmentSize = binary.BigEndian.Uint32(b[ObjectIDLen:])
	h.Count = binary.BigEndian.Uint32(b[ObjectIDLen+4:])
	if h.validate() != nil {
		return SegmentedHeader{}, 0, false
	}
	return h, ObjectIDLen + 4 + 4, true
}

// ----- the transcripts and seal infos

// transcriptCodec is one transcript version's builders, each binding the version it is given: what signs and seals
// under that version, and what verifies and opens under it.
type transcriptCodec interface {
	request(v uint32, profile string, op Operation, timestampMS int64, nonce []byte, digest [sha256.Size]byte) []byte
	response(v uint32, profile, contextDigest string, op Operation, requestNonce, requester []byte,
		requestDigest, responseDigest [sha256.Size]byte) []byte
	signingKeys(v uint32, profile string, tenancy Tenancy, contextDigest string, nonce []byte,
		sorted []ReceivedSigningKey) []byte
	requestSealInfo(v uint32, profile string, op Operation, tenant string, requester []byte) []byte
	responseSealInfo(v uint32, profile string, op Operation, tenant string) []byte
}

// transcripts is the transcript kind: every transcript and seal info binds its version as a field, and travels in no
// message (a verifier rebuilds it under each version read).
var transcripts = format.NewKind[transcriptCodec]("transcripts and seal infos", format.Unmarked, format.Unsealed, nil,
	func(got, writes uint32) error {
		return fmt.Errorf("cipheron: transcript version %d; this cipheron writes version %d", got, writes)
	})

// transcriptV1 is the transcripts' version 1 (TranscriptVersion).
type transcriptV1 struct{}

func (transcriptV1) request(v uint32, profile string, op Operation, timestampMS int64, nonce []byte,
	digest [sha256.Size]byte,
) []byte {
	return requestTranscriptV1(v, profile, op, timestampMS, nonce, digest)
}

func (transcriptV1) response(v uint32, profile, contextDigest string, op Operation, requestNonce, requester []byte,
	requestDigest, responseDigest [sha256.Size]byte,
) []byte {
	return responseTranscriptV1(v, profile, contextDigest, op, requestNonce, requester, requestDigest, responseDigest)
}

func (transcriptV1) signingKeys(v uint32, profile string, tenancy Tenancy, contextDigest string, nonce []byte,
	sorted []ReceivedSigningKey,
) []byte {
	return signingKeysTranscriptV1(v, profile, tenancy, contextDigest, nonce, sorted)
}

func (transcriptV1) requestSealInfo(v uint32, profile string, op Operation, tenant string, requester []byte) []byte {
	return requestSealInfoV1(v, profile, op, tenant, requester)
}

func (transcriptV1) responseSealInfo(v uint32, profile string, op Operation, tenant string) []byte {
	return responseSealInfoV1(v, profile, op, tenant)
}

// ----- the key statement and its export

// statementCodec is one key statement version's layout: what appends a statement's fields after the head, and what
// reads them back. The head — the statement's label and its version — is the kind's (statementHead): Marshal writes
// it and ParseKeyStatement reads it before a codec is chosen, so no codec writes, moves or retypes it.
type statementCodec interface {
	marshal(head transcript, s *KeyStatement) (transcript, error)
	// parse reads the fields after the version into a statement; r.err records a malformed field.
	parse(r *reader) *KeyStatement
}

// keyStatements is the key statement kind: its version is its second field. A statement of a version not read — or
// bytes that do not open with the statement's label — is refused (refuseKeyStatement).
var keyStatements = format.NewKind[statementCodec]("key statement", format.Numbered, format.Unsealed, nil,
	refuseKeyStatement)

type statementV1 struct{}

func (statementV1) marshal(head transcript, s *KeyStatement) (transcript, error) {
	return appendStatementV1(head, s)
}
func (statementV1) parse(r *reader) *KeyStatement { return parseStatementV1(r) }

// statementExportCodec is one exported key statement layout: the JSON document, written and read.
type statementExportCodec interface {
	marshal(token, profile, fingerprint string, raw, signature []byte) ([]byte, error)
	// unmarshal reads a document of the layout named token: ok false when it is not one, err a statement or signature
	// that is not base64.
	unmarshal(token string, b []byte) (raw, signature []byte, ok bool, err error)
}

// statementExports is the exported key statement kind: a document names its layout by its "format", exactly a
// scheme's token.
var statementExports = format.NewKind[statementExportCodec]("key statement export", format.Tokened,
	format.Unsealed, ErrKeyStatementExport, nil)

// formatMember is an exported key statement's top-level "format" member: the kind's, declared here once.
// ReadKeyStatementExport reads it alone, before a layout is chosen, and every layout's document embeds it as its first
// field and declares none of its own, so no layout can name, move or retype the member its layout is found by.
type formatMember struct {
	Format string `json:"format"`
}

// statementExportV1 is the export's layout 1: {"format", "profile", "fingerprint", "statement": base64, "signature":
// base64}, indented by two spaces; read strictly (no other field).
type statementExportV1 struct{}

type exportedStatementV1 struct {
	formatMember

	Profile     string `json:"profile"`
	Fingerprint string `json:"fingerprint"`
	Statement   string `json:"statement"`
	Signature   string `json:"signature"`
}

func (statementExportV1) marshal(token, profile, fingerprint string, raw, signature []byte) ([]byte, error) {
	return json.MarshalIndent(exportedStatementV1{formatMember: formatMember{Format: token}, Profile: profile, Fingerprint: fingerprint,
		Statement: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(signature)},
		"", "  ")
}

func (statementExportV1) unmarshal(token string, b []byte) (raw, signature []byte, ok bool, err error) {
	var e exportedStatementV1
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil || e.Format != token {
		return nil, nil, false, nil
	}
	raw, err1 := base64.StdEncoding.DecodeString(e.Statement)
	sig, err2 := base64.StdEncoding.DecodeString(e.Signature)
	if err := errors.Join(err1, err2); err != nil {
		return nil, nil, true, err
	}
	return raw, sig, true, nil
}

// ----- the encrypted JSON field

// jsonFieldCodec is one encrypted JSON field encoding: what follows the prefix, written and read.
type jsonFieldCodec interface {
	encode(ciphertext []byte) string
	decode(body string) ([]byte, bool)
}

// jsonFields is the encrypted JSON field kind: a value names its encoding by its prefix (JSONFieldPrefix). A value
// of no prefix read is refused with ErrJSONField.
var jsonFields = format.NewKind[jsonFieldCodec]("encrypted JSON field", format.Prefixed, format.Unsealed, ErrJSONField,
	nil)

// jsonFieldV1 is version 1: the ciphertext's standard base64, read strictly.
type jsonFieldV1 struct{}

func (jsonFieldV1) encode(ciphertext []byte) string {
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func (jsonFieldV1) decode(body string) ([]byte, bool) {
	ct, err := base64.StdEncoding.Strict().DecodeString(body)
	return ct, err == nil
}

// ----- the release

// Schemes are the protocol's schemes, a new slice on each call.
func Schemes() []format.Entry {
	suite := format.HKDFSHA256AESGCM()
	return []format.Entry{
		ciphertextScheme(FormatTenantKey, "format 3", "storage key", tenantKeyIDHeader{}),
		ciphertextScheme(FormatVersioned, "format 4", "data key", masterVersionHeader{}),
		ciphertextScheme(FormatVersionedAAD, "format 5", "data key", masterVersionHeader{aad: true}),
		ciphertextScheme(FormatTenantKeyAAD, "format 6", "storage key", tenantKeyIDHeader{aad: true}),
		tenantKeys.Scheme(TenantKeyVersion, "version 1", tenantKeyBlobV1{},
			format.SealedBy(suite, "tenant-wrapping key")),
		objects.Scheme(uint32(SegmentedVersion), "version 1", segmentedV1{}),
		transcripts.Scheme(TranscriptVersion, "version 1", transcriptV1{}),
		keyStatements.Scheme(KeyStatementVersion, "version 1", statementV1{}),
		statementExports.Scheme(keyStatementExportVersion, "version 1", statementExportV1{},
			format.Marker(KeyStatementExportFormat)),
		jsonFields.Scheme(jsonFieldVersion, "version 1", jsonFieldV1{}, format.Marker(JSONFieldPrefix)),
	}
}

// release is what this release of the protocol reads and writes.
var release = must(format.NewPolicy(must(format.NewCatalog(Schemes()...)),
	ciphertexts.Reads(uint32(FormatTenantKey), uint32(FormatVersioned), uint32(FormatVersionedAAD),
		uint32(FormatTenantKeyAAD)).
		Writes(slotTenantKey, uint32(FormatTenantKey)).Writes(slotTenantKeyAAD, uint32(FormatTenantKeyAAD)).
		Writes(slotMasterVersion, uint32(FormatVersioned)).Writes(slotMasterVersionAAD, uint32(FormatVersionedAAD)),
	tenantKeys.Reads(TenantKeyVersion).Writes(0, TenantKeyVersion),
	objects.Reads(uint32(SegmentedVersion)).Writes(0, uint32(SegmentedVersion)),
	transcripts.Reads(TranscriptVersion).Writes(0, TranscriptVersion),
	keyStatements.Reads(KeyStatementVersion).Writes(0, KeyStatementVersion),
	statementExports.Reads(keyStatementExportVersion).Writes(0, keyStatementExportVersion),
	jsonFields.Reads(jsonFieldVersion).Writes(0, jsonFieldVersion)))

// Release is what this release of the protocol reads and writes: every kind its version 1, the ciphertext its formats
// 3 to 6, each written for its slot.
func Release() *format.Policy { return release }
