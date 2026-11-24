package transport

// v2layouts_test.go — for every kind but the ciphertext (extend_test.go's), a version 2 that exists only in this test
// and is a real new layout: its own codec, writing other bytes than version 1's, and for the sealed tenant key blob
// another suite (another hash, salt length and label namespace). Each is walked through the lifecycle (walk) and
// proves what a release adding it relies on: version 2 is written in its own layout, both versions are read where both
// are, and version 1 is refused once it is dropped. lifecycle_test.go proves the lifecycle with version 1's codec
// re-registered; this file proves the framework carries a layout of a version's own.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nnicora/cipheron/wire/format"
)

// ----- the tenant key blob: reordered fields, other length prefixes, another suite

// tenantKeyBlobV2 is created (8) | lp1(wrapping version) | lp1(profile) | lp4(tenant) | key id (16) | signing key (32).
type tenantKeyBlobV2 struct{}

func (tenantKeyBlobV2) Layout() format.Layout {
	return format.Layout{Fields: []format.Field{
		{Name: "created", Min: 8, Max: 8},
		{Name: "wrapping master version id", Prefix: 1, Min: 1, Max: MaxMasterVersionIDLen},
		{Name: "profile", Prefix: 1, Min: 1, Max: MaxProfileLen},
		{Name: "tenant", Prefix: 4, Min: 1, Max: MaxTenantLen},
		{Name: "key id", Min: TenantKeyIDLen, Max: TenantKeyIDLen},
		{Name: "signing public key", Min: ed25519.PublicKeySize, Max: ed25519.PublicKeySize},
	}, Plaintext: TenantPrivateLen}
}

func (tenantKeyBlobV2) Size(h TenantKeyHeader) int {
	return 8 + 1 + len(h.WrappingVersion) + 1 + len(h.Profile) + 4 + len(h.Tenant) + TenantKeyIDLen + ed25519.PublicKeySize
}

func (tenantKeyBlobV2) Append(dst []byte, h TenantKeyHeader) ([]byte, error) {
	if h.Created.Unix() <= 0 || len(h.KeyID) != TenantKeyIDLen || !ValidProfile(h.Profile) || !ValidTenant(h.Tenant) ||
		len(h.SigningPublicKey) != ed25519.PublicKeySize || !ValidMasterVersionID(h.WrappingVersion) {
		return nil, ErrTenantKey
	}
	dst = binary.BigEndian.AppendUint64(dst, uint64(h.Created.Unix()))
	dst = append(append(dst, byte(len(h.WrappingVersion))), h.WrappingVersion...)
	dst = append(append(dst, byte(len(h.Profile))), h.Profile...)
	dst = append(binary.BigEndian.AppendUint32(dst, uint32(len(h.Tenant))), h.Tenant...)
	dst = append(dst, h.KeyID...)
	return append(dst, h.SigningPublicKey...), nil
}

func (tenantKeyBlobV2) Parse(b []byte) (TenantKeyHeader, int, bool) {
	all := len(b)
	if len(b) < 8 {
		return TenantKeyHeader{}, 0, false
	}
	created := int64(binary.BigEndian.Uint64(b))
	b = b[8:]
	lp1 := func() ([]byte, bool) {
		if len(b) < 1 || int(b[0]) > len(b)-1 {
			return nil, false
		}
		f := b[1 : 1+b[0]]
		b = b[1+b[0]:]
		return f, true
	}
	wv, ok1 := lp1()
	profile, ok2 := lp1()
	tenant, rest, ok3 := readLP(b, MaxTenantLen)
	if !ok1 || !ok2 || !ok3 || created <= 0 || !ValidMasterVersionID(string(wv)) || !ValidProfile(string(profile)) ||
		!ValidTenant(string(tenant)) || len(rest) < TenantKeyIDLen+ed25519.PublicKeySize {
		return TenantKeyHeader{}, 0, false
	}
	h := TenantKeyHeader{Created: time.Unix(created, 0).UTC(), WrappingVersion: string(wv), Profile: string(profile),
		Tenant: string(tenant), KeyID: rest[:TenantKeyIDLen], SigningPublicKey: rest[TenantKeyIDLen : TenantKeyIDLen+ed25519.PublicKeySize]}
	return h, all - len(rest) + TenantKeyIDLen + ed25519.PublicKeySize, true
}

func (tenantKeyBlobV2) info(ns format.Namespace, h *TenantKeyHeader, salt []byte) string {
	return format.TenantBlobWrapInfo(ns, h.Profile, h.Tenant, h.WrappingVersion, salt)
}

// suiteV2 is a suite of the test's own: HKDF-SHA512, a 32-byte salt, AES-256-GCM, its own namespace.
func suiteV2() format.Suite {
	return format.TestSuite("HKDF-SHA512-Expand/AES-256-GCM (test)", format.TestNamespace("tkv2"), 32, 32, 12, 16,
		sha512.New, func(key []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCMWithRandomNonce(b)
		})
}

func TestATenantKeyBlobVersionOfItsOwnLayoutAndSuite(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t,
		tenantKeys.Scheme(2, "a test layout", tenantKeyBlobV2{}, format.SealedBy(suiteV2(), "tenant-wrapping key")),
		func(w uint32, r ...uint32) format.Rule { return tenantKeys.Reads(r...).Writes(0, w) })
	wrapKey, private := bytes.Repeat([]byte{3}, CiphertextKeyLen), bytes.Repeat([]byte{7}, TenantPrivateLen)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h := &TenantKeyHeader{KeyID: bytes.Repeat([]byte{1}, TenantKeyIDLen), Profile: "files", Tenant: "t_1",
		SigningPublicKey: pub, WrappingVersion: "v3", Created: time.Unix(1_700_000_000, 0)}
	old, err1 := SealTenantKey(Release(), wrapKey, h, private)
	blob, err2 := SealTenantKey(writes, wrapKey, h, private)
	if err := errors.Join(err1, err2); err != nil {
		t.Fatal(err)
	}
	// Version 2's bytes are its own layout: created right after the marker, a 32-byte salt.
	if blob[len(TenantKeyMagic)] != 2 || int64(binary.BigEndian.Uint64(blob[len(TenantKeyMagic)+1:])) != 1_700_000_000 {
		t.Fatalf("version 2 is not written in its own layout: %x", blob[:16])
	}
	for _, c := range []struct {
		p    *format.Policy
		blob []byte
		ok   bool
	}{
		{released, blob, false}, {reads, blob, true}, {writes, blob, true}, {dropped, blob, true},
		{reads, old, true}, {writes, old, true}, {dropped, old, false},
	} {
		got, err := ParseTenantKey(c.p, c.blob)
		if c.ok != (err == nil) {
			t.Fatalf("version %d: %v", c.blob[len(TenantKeyMagic)], err)
		}
		if !c.ok {
			continue
		}
		if got.Profile != h.Profile || got.Tenant != h.Tenant || got.WrappingVersion != h.WrappingVersion ||
			!bytes.Equal(got.KeyID, h.KeyID) || !bytes.Equal(got.SigningPublicKey, h.SigningPublicKey) || !got.Created.Equal(h.Created) {
			t.Fatalf("version %d reads back another header: %+v", got.Version, got)
		}
		key, err := TenantKeyItemKey(c.p, wrapKey, got)
		if err != nil {
			t.Fatal(err)
		}
		if pt, ok := key.Open(nil, got.Sealed, got.AAD); !ok || !bytes.Equal(pt, private) {
			t.Fatalf("version %d does not open", got.Version)
		}
	}
}

// ----- the segmented object: count before segment size, the size widened to 8 bytes

type segmentedV2 struct{}

func (segmentedV2) Layout() format.Layout {
	return format.Layout{Fields: []format.Field{
		{Name: "object id", Min: ObjectIDLen, Max: ObjectIDLen},
		{Name: "count", Min: 4, Max: 4},
		{Name: "segment size", Min: 8, Max: 8},
	}}
}

func (segmentedV2) Size(SegmentedHeader) int { return ObjectIDLen + 4 + 8 }

func (segmentedV2) Append(dst []byte, h SegmentedHeader) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	dst = append(dst, h.ObjectID...)
	dst = binary.BigEndian.AppendUint32(dst, h.Count)
	return binary.BigEndian.AppendUint64(dst, uint64(h.SegmentSize)), nil
}

func (segmentedV2) Parse(b []byte) (SegmentedHeader, int, bool) {
	if len(b) < ObjectIDLen+4+8 {
		return SegmentedHeader{}, 0, false
	}
	size := binary.BigEndian.Uint64(b[ObjectIDLen+4:])
	if size > 1<<32-1 {
		return SegmentedHeader{}, 0, false
	}
	h := SegmentedHeader{ObjectID: append([]byte(nil), b[:ObjectIDLen]...), Count: binary.BigEndian.Uint32(b[ObjectIDLen:]),
		SegmentSize: uint32(size)}
	if h.validate() != nil {
		return SegmentedHeader{}, 0, false
	}
	return h, ObjectIDLen + 4 + 8, true
}

func TestASegmentedObjectVersionOfItsOwnLayout(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t, objects.Scheme(2, "a test layout", segmentedV2{}),
		func(w uint32, r ...uint32) format.Rule { return objects.Reads(r...).Writes(0, w) })
	segs := [][]byte{bytes.Repeat([]byte{1}, 40), bytes.Repeat([]byte{2}, 40)}
	h := SegmentedHeader{ObjectID: bytes.Repeat([]byte{9}, ObjectIDLen), SegmentSize: 1 << 16, Count: uint32(len(segs))}
	old, err1 := MarshalSegmented(Release(), h, segs)
	obj, err2 := MarshalSegmented(writes, h, segs)
	if err := errors.Join(err1, err2); err != nil {
		t.Fatal(err)
	}
	m := len(SegmentedMagic) + 1
	if obj[m-1] != 2 || binary.BigEndian.Uint32(obj[m+ObjectIDLen:]) != 2 || binary.BigEndian.Uint64(obj[m+ObjectIDLen+4:]) != 1<<16 {
		t.Fatalf("version 2 is not written in its own layout: %x", obj[:m+ObjectIDLen+12])
	}
	for _, c := range []struct {
		p   *format.Policy
		obj []byte
		ok  bool
	}{{released, obj, false}, {reads, obj, true}, {dropped, obj, true}, {reads, old, true}, {dropped, old, false}} {
		got, gotSegs, err := ParseSegmented(c.p, c.obj)
		if c.ok != (err == nil) {
			t.Fatalf("version %d: %v", c.obj[m-1], err)
		}
		if c.ok && (!bytes.Equal(got.ObjectID, h.ObjectID) || got.SegmentSize != h.SegmentSize || got.Count != h.Count ||
			len(gotSegs) != 2 || !bytes.Equal(gotSegs[1], segs[1])) {
			t.Fatalf("version %d reads back another object: %+v", c.obj[m-1], got)
		}
	}
}

// ----- the encrypted JSON field: URL-safe base64 without padding

type jsonFieldV2 struct{}

func (jsonFieldV2) encode(ct []byte) string { return base64.RawURLEncoding.EncodeToString(ct) }

func (jsonFieldV2) decode(body string) ([]byte, bool) {
	ct, err := base64.RawURLEncoding.Strict().DecodeString(body)
	return ct, err == nil
}

func TestAJSONFieldVersionOfItsOwnEncoding(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t,
		jsonFields.Scheme(2, "a test encoding", jsonFieldV2{}, format.Marker("cipheron:v2:")),
		func(w uint32, r ...uint32) format.Rule { return jsonFields.Reads(r...).Writes(0, w) })
	ct := []byte{0xfb, 0xff, 0xfe, 0x01} // standard and URL-safe base64 differ on these bytes
	v1, v2 := EncodeJSONField(Release(), ct), EncodeJSONField(writes, ct)
	if v2 != "cipheron:v2:"+base64.RawURLEncoding.EncodeToString(ct) || v1[len(JSONFieldPrefix):] == v2[12:] {
		t.Fatalf("version 2 is not written in its own encoding: %q (version 1 %q)", v2, v1)
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {dropped, false, true}} {
		got1, err1 := DecodeJSONField(c.p, v1)
		got2, err2 := DecodeJSONField(c.p, v2)
		if (err1 == nil) != c.v1 || (err2 == nil) != c.v2 || c.v1 && !bytes.Equal(got1, ct) || c.v2 && !bytes.Equal(got2, ct) {
			t.Fatalf("%v: %v, %v", c, err1, err2)
		}
	}
	// Version 1's encoding under version 2's marker is not version 2's.
	if _, err := DecodeJSONField(reads, "cipheron:v2:"+base64.StdEncoding.EncodeToString(ct)); err == nil {
		t.Fatal("standard base64 read as version 2")
	}
}

// ----- the key statement export: other member names but "format", which is the kind's (ReadKeyStatementExport)

type statementExportV2 struct{}

type exportedStatementV2 struct {
	formatMember

	D   string `json:"d"`
	FP  string `json:"fp"`
	S   []byte `json:"s"`
	Sig []byte `json:"sig"`
}

func (statementExportV2) marshal(token, profile, fp string, raw, sig []byte) ([]byte, error) {
	return json.Marshal(exportedStatementV2{formatMember: formatMember{Format: token}, D: profile, FP: fp, S: raw, Sig: sig})
}

func (statementExportV2) unmarshal(token string, b []byte) (raw, sig []byte, ok bool, err error) {
	var e exportedStatementV2
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || e.Format != token {
		return nil, nil, false, nil
	}
	return e.S, e.Sig, true, nil
}

func TestAKeyStatementExportVersionOfItsOwnDocument(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t,
		statementExports.Scheme(2, "a test document", statementExportV2{}, format.Marker("cipheron-key-statement/2")),
		func(w uint32, r ...uint32) format.Rule { return statementExports.Reads(r...).Writes(0, w) })
	raw, sig := []byte("statement"), []byte("signature")
	v1, err1 := ExportKeyStatement(Release(), "docs", "sha256:x", raw, sig)
	v2, err2 := ExportKeyStatement(writes, "docs", "sha256:x", raw, sig)
	if err := errors.Join(err1, err2); err != nil || !bytes.Contains(v2, []byte(`{"format":"cipheron-key-statement/2","d":"docs","fp":`)) {
		t.Fatalf("version 2 is not written in its own document: %s (%v)", v2, err)
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {dropped, false, true}} {
		r1, s1, e1 := ReadKeyStatementExport(c.p, v1)
		r2, s2, e2 := ReadKeyStatementExport(c.p, v2)
		if (e1 == nil) != c.v1 || (e2 == nil) != c.v2 || c.v1 && (!bytes.Equal(r1, raw) || !bytes.Equal(s1, sig)) ||
			c.v2 && (!bytes.Equal(r2, raw) || !bytes.Equal(s2, sig)) {
			t.Fatalf("%v: %v, %v", c, e1, e2)
		}
	}
}

// ----- the key statement: a field version 1 does not have

// statementV2 is version 1's fields and then one more: a field naming the test version.
type statementV2 struct{}

const statementV2Field = "a field of version 2"

func (statementV2) marshal(head transcript, s *KeyStatement) (transcript, error) {
	t, err := appendStatementV1(head, s)
	if err != nil {
		return nil, err
	}
	return t.addString(statementV2Field), nil
}

func (statementV2) parse(r *reader) *KeyStatement {
	s := parseStatementV1(r)
	if string(r.field()) != statementV2Field {
		r.err = true
	}
	return s
}

func TestAKeyStatementVersionOfItsOwnLayout(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t, keyStatements.Scheme(2, "a test layout", statementV2{}),
		func(w uint32, r ...uint32) format.Rule { return keyStatements.Reads(r...).Writes(0, w) })
	st := testStatement(t)
	v1, err1 := MarshalKeyStatement(Release(), st)
	v2, err2 := MarshalKeyStatement(writes, st)
	if err := errors.Join(err1, err2); err != nil || !bytes.HasSuffix(v2, []byte(statementV2Field)) || len(v2) <= len(v1) {
		t.Fatalf("version 2 is not written in its own layout (%v)", err)
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {dropped, false, true}} {
		_, e1 := ParseKeyStatement(c.p, v1)
		got, e2 := ParseKeyStatement(c.p, v2)
		if (e1 == nil) != c.v1 || (e2 == nil) != c.v2 || c.v2 && got.Profile != st.Profile {
			t.Fatalf("%v: %v, %v", c, e1, e2)
		}
	}
	// Version 2's layout under version 1's number is not a statement: the codec is the version's.
	if _, err := ParseKeyStatement(reads, marshalAs(t, st, 2)); err == nil {
		t.Fatal("version 1's layout read as version 2")
	}
}

// ----- the transcripts: another layout

// transcriptV2 is a test layout: its own label first, then version 1's bytes for the same version.
type transcriptV2 struct{ transcriptV1 }

const transcriptV2Label = "a test transcript layout"

func (transcriptV2) request(v uint32, profile string, op Operation, ts int64, nonce []byte, d [sha256.Size]byte) []byte {
	return transcript(nil).addString(transcriptV2Label).add(requestTranscriptV1(v, profile, op, ts, nonce, d))
}

func TestATranscriptVersionOfItsOwnLayout(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t, transcripts.Scheme(2, "a test layout", transcriptV2{}),
		func(w uint32, r ...uint32) format.Rule { return transcripts.Reads(r...).Writes(0, w) })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var digest [sha256.Size]byte
	nonce := bytes.Repeat([]byte{9}, NonceLen)
	tr2 := RequestTranscript(writes, "docs", OpEncrypt, 1, nonce, digest)
	if !bytes.Contains(tr2, []byte(transcriptV2Label)) {
		t.Fatal("version 2's request transcript is not its own layout")
	}
	v1 := ed25519.Sign(priv, RequestTranscript(Release(), "docs", OpEncrypt, 1, nonce, digest))
	v2 := ed25519.Sign(priv, tr2)
	verifies := func(p *format.Policy, sig []byte) bool {
		return EachRequestTranscript(p, "docs", OpEncrypt, 1, nonce, digest, func(tr []byte) bool {
			return ed25519.Verify(pub, tr, sig)
		})
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {writes, true, true}, {dropped, false, true}} {
		if verifies(c.p, v1) != c.v1 || verifies(c.p, v2) != c.v2 {
			t.Fatalf("%v: version 1 %v, version 2 %v", c, verifies(c.p, v1), verifies(c.p, v2))
		}
	}
}

// THE EXPORT'S LAYOUT 1 IS THESE BYTES: "format" first (formatMember), then its own members, indented by two spaces.
func TestTheExportLayout1Bytes(t *testing.T) {
	t.Parallel()
	got, err := ExportKeyStatement(Release(), "docs", "sha256:ab", []byte{1, 2}, []byte{3})
	want := "{\n  \"format\": \"cipheron-key-statement/1\",\n  \"profile\": \"docs\",\n  \"fingerprint\": \"sha256:ab\",\n" +
		"  \"statement\": \"AQI=\",\n  \"signature\": \"Aw==\"\n}"
	if err != nil || string(got) != want {
		t.Fatalf("layout 1:\n%s\nwant:\n%s (%v)", got, want, err)
	}
}

// misnamedExport is layout 2 but for its token, which it writes as another one's.
type misnamedExport struct{ statementExportV2 }

func (m misnamedExport) marshal(_, profile, fp string, raw, sig []byte) ([]byte, error) {
	return m.statementExportV2.marshal("cipheron-key-statement/1", profile, fp, raw, sig)
}

// AN EXPORT LAYOUT MUST NAME ITSELF IN "format": a layout writing another token is refused at export, as a
// programming error, instead of writing a document no reader would find its layout of.
func TestAnExportLayoutMustNameItself(t *testing.T) {
	t.Parallel()
	_, _, writes, _ := walk(t,
		statementExports.Scheme(2, "a test document", misnamedExport{}, format.Marker("cipheron-key-statement/2")),
		func(w uint32, r ...uint32) format.Rule { return statementExports.Reads(r...).Writes(0, w) })
	if _, err := ExportKeyStatement(writes, "docs", "sha256:x", []byte("s"), []byte("g")); err == nil ||
		err.Error() != `cipheron: layout a test document of the exported key statement does not name itself in "format"` {
		t.Fatalf("a layout naming another token: %v", err)
	}
}
