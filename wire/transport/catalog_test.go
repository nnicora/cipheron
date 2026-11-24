package transport

// catalog_test.go — the protocol's catalog and release as the package declares them: the kinds and their magics, every
// scheme's declaration (what its header names, its associated data, its suite, the key a refusal names, its slot),
// the one suite, and the bounds the release computes from the schemes' layouts.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/nnicora/cipheron/wire/format"
)

func TestTheProductionSchemes(t *testing.T) {
	type decl struct {
		names   Names
		aad     bool
		keyName string
		slot    format.Slot
	}
	want := map[uint32]decl{
		uint32(FormatTenantKey):    {NamesTenantKey, false, "storage key", slotTenantKey},
		uint32(FormatVersioned):    {NamesMasterVersion, false, "data key", slotMasterVersion},
		uint32(FormatVersionedAAD): {NamesMasterVersion, true, "data key", slotMasterVersionAAD},
		uint32(FormatTenantKeyAAD): {NamesTenantKey, true, "storage key", slotTenantKeyAAD},
	}
	suite := format.HKDFSHA256AESGCM()
	n := 0
	for s := range format.Each(Release(), ciphertexts) {
		n++
		d, ok := want[s.Version()]
		slot, _ := ciphertextSlot(d.names, d.aad)
		if !ok || s.Codec().names() != d.names || s.Codec().associatedData() != d.aad || s.Suite() != suite ||
			s.Slot() != d.slot || slot != d.slot || format.Write(Release(), ciphertexts, d.slot) != s ||
			s.Marker() != CiphertextMagic+string([]byte{byte(s.Version())}) {
			t.Errorf("format %d (%s) is not declared as specified", s.Version(), s.Name())
		}
		for i := range Release().Schemes() {
			if i.Kind == "ciphertext" && i.Version == s.Version() && (i.KeyName != d.keyName || !i.Written) {
				t.Errorf("format %d: key name %q, written %v", s.Version(), i.KeyName, i.Written)
			}
		}
	}
	if _, maxOverhead, maxItem := format.Bounds(Release(), ciphertexts); n != len(want) ||
		maxOverhead != VersionedMaxOverhead || maxItem != 0 {
		t.Fatalf("the ciphertext kind: %d formats, max overhead %d, longest item %d", n, maxOverhead, maxItem)
	}
	for f, b := range map[byte][3]int{
		FormatTenantKey: {TenantKeyHeaderLen, TenantKeyHeaderLen}, FormatTenantKeyAAD: {TenantKeyHeaderLen, TenantKeyHeaderLen},
		FormatVersioned:    {VersionedMinOverhead - CiphertextNonceLen - CiphertextTagLen, VersionedMaxOverhead - CiphertextNonceLen - CiphertextTagLen},
		FormatVersionedAAD: {VersionedMinOverhead - CiphertextNonceLen - CiphertextTagLen, VersionedMaxOverhead - CiphertextNonceLen - CiphertextTagLen},
	} {
		s, _ := format.Read(Release(), ciphertexts, uint32(f))
		if lo, hi, item := s.Bounds(); lo != b[0] || hi != b[1] || item != b[2] {
			t.Errorf("format %d: bounds %d, %d, %d; want %v", f, lo, hi, item, b)
		}
	}
	if _, ok := ciphertextSlot(NamesNoKey, false); ok {
		t.Error("a ciphertext format is written for no key")
	}
	blob := format.Write(Release(), tenantKeys, 0)
	if lo, hi, item := blob.Bounds(); blob.Version() != TenantKeyVersion || blob.Suite() != suite || lo != 105 ||
		hi != MaxTenantKeyLen-TenantSealedLen || item != MaxTenantKeyLen || blob.Marker() != "CPT1\x01" {
		t.Errorf("the tenant key blob: version %d, bounds %d, %d, %d", blob.Version(), lo, hi, item)
	}
	obj := format.Write(Release(), objects, 0)
	if lo, hi, item := obj.Bounds(); obj.Version() != uint32(SegmentedVersion) || obj.Suite() != (format.Suite{}) ||
		lo != SegmentedHeaderLen || hi != SegmentedHeaderLen || item != 0 || obj.Marker() != "CPS1\x01" {
		t.Errorf("the segmented object: version %d, bounds %d, %d, %d", obj.Version(), lo, hi, item)
	}
	if suite.Namespace().String() != "cipheron/v1|" || suite.KeyLen() != CiphertextKeyLen ||
		suite.SaltLen() != CiphertextSaltLen || suite.SaltLen() != TenantKeySaltLen ||
		suite.Overhead() != CiphertextNonceLen+CiphertextTagLen || suite.Name() != "HKDF-SHA256-Expand/AES-256-GCM" {
		t.Errorf("the stored layouts' suite: %s", suite.Name())
	}
}

// TestEveryKindOfTheReleaseIsServed: every protocol kind a caller uses is in the release, each written for its slots
// and read: a writer, a lookup by version and Each find it (a missing kind would panic).
func TestEveryKindOfTheReleaseIsServed(t *testing.T) {
	p := Release()
	for _, slot := range []format.Slot{slotTenantKey, slotTenantKeyAAD, slotMasterVersion, slotMasterVersionAAD} {
		if format.Write(p, ciphertexts, slot) == nil {
			t.Fatalf("slot %d", slot)
		}
	}
	_ = format.Write(p, tenantKeys, 0)
	_ = format.Write(p, objects, 0)
	_ = format.Write(p, statementExports, 0)
	_ = format.Write(p, jsonFields, 0)
	if format.Write(p, transcripts, 0).Version() != TranscriptVersion || WrittenTranscriptVersion(p) != 1 {
		t.Fatal("the transcript version")
	}
	if s, err := format.Read(p, keyStatements, KeyStatementVersion); err != nil || s.Version() != 1 {
		t.Fatal(err)
	}
	var kinds []string
	for i := range p.Schemes() {
		if len(kinds) == 0 || kinds[len(kinds)-1] != i.Kind {
			kinds = append(kinds, i.Kind)
		}
	}
	want := []string{"ciphertext", "tenant key blob", "segmented object", "transcripts and seal infos", "key statement",
		"key statement export", "encrypted JSON field"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("the release's kinds: %q", kinds)
	}
}

// TestEveryJSONFieldMarkerFitsTheProbe: no JSON field marker the release reads is longer than what a value is probed
// for (jsonFieldMarkerProbe), so no value is ever copied whole to find its scheme.
func TestEveryJSONFieldMarkerFitsTheProbe(t *testing.T) {
	for i := range Release().Schemes() {
		if i.Kind == "encrypted JSON field" && len(i.Marker) > jsonFieldMarkerProbe {
			t.Fatalf("the marker %q is longer than the probe", i.Marker)
		}
	}
}

// TestAKindRefusesAsItAlwaysHas: a kind's refusals of what is not one of its schemes, read through the release —
// ErrCiphertext for another magic or too few bytes, ErrCiphertextFormat naming the byte for a format not read,
// ErrTenantKey and ErrSegmented — are the values the parsers always returned.
func TestAKindRefusesAsItAlwaysHas(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want error
	}{{nil, ErrCiphertext}, {[]byte("CPH1"), ErrCiphertext}, {[]byte("CPT1\x01"), ErrCiphertext}} {
		if _, err := format.Marked(Release(), ciphertexts, c.b); err != c.want { //nolint:errorlint // the very value
			t.Errorf("%q: %v", c.b, err)
		}
	}
	if _, err := format.Marked(Release(), ciphertexts, []byte("CPH1\x07")); !errors.Is(err, ErrCiphertextFormat) ||
		err.Error() != ErrCiphertextFormat.Error()+" (format 7)" {
		t.Errorf("format 7: %v", err)
	}
	for _, b := range [][]byte{nil, []byte("CPT1"), []byte("CPT1\x02"), []byte("CPH1\x01")} {
		if _, err := format.Marked(Release(), tenantKeys, b); err != ErrTenantKey { //nolint:errorlint // the very value
			t.Errorf("blob %q: %v", b, err)
		}
	}
	for _, b := range [][]byte{nil, []byte("CPS1"), []byte("CPS1\x02"), []byte("CPH1\x01")} {
		if _, err := format.Marked(Release(), objects, b); err != ErrSegmented { //nolint:errorlint // the very value
			t.Errorf("object %q: %v", b, err)
		}
	}
	if _, err := format.Read(Release(), transcripts, 2); err == nil ||
		err.Error() != "cipheron: transcript version 2; this cipheron writes version 1" {
		t.Errorf("transcript version 2: %v", err)
	}
}

// TestKeyIDMethodsAnswerFromTheRelease: a KeyID's methods answer from the release for every format byte, a hand-built
// KeyID included: what NamesOf and OverheadOf answer under the release.
func TestKeyIDMethodsAnswerFromTheRelease(t *testing.T) {
	for b := 0; b < 256; b++ {
		k := KeyID{Format: byte(b), HeaderLen: 53, MasterVersion: "v1", TenantKeyID: make([]byte, TenantKeyIDLen)}
		names, over := NamesTenantKey, 53+28
		switch byte(b) {
		case FormatVersioned, FormatVersionedAAD:
			names = NamesMasterVersion
		case FormatTenantKey, FormatTenantKeyAAD:
		default:
			names, over = NamesNoKey, 0
		}
		if NamesOf(Release(), k) != names || k.Versioned() != (names == NamesMasterVersion) ||
			k.TenantKey() != (names == NamesTenantKey) || k.Overhead() != over || OverheadOf(Release(), k) != over {
			t.Fatalf("format %d: names %s, overhead %d", b, NamesOf(Release(), k), k.Overhead())
		}
	}
	_ = sha256.Size
}

// TestARefusedHeaderWritesNothing: a header the codec refuses is never begun in the caller's buffer — its spare
// capacity is as it was — and the refusals keep their order and words: the master version id first, then the salt.
func TestARefusedHeaderWritesNothing(t *testing.T) {
	salt := make([]byte, CiphertextSaltLen)
	for _, c := range []struct {
		version string
		salt    []byte
		want    string
	}{
		{"v1", salt[:31], "cipheron: a salt is 32 bytes, not 31"},
		{"v|1", salt[:31], `cipheron: "v|1" is not a master key version id`},
		{"v|1", salt, `cipheron: "v|1" is not a master key version id`},
	} {
		buf := bytes.Repeat([]byte{0xAA}, 128)
		out, err := AppendVersionedHeader(Release(), buf[:3], c.version, c.salt)
		if out != nil || err == nil || err.Error() != c.want {
			t.Fatalf("%q, %d-byte salt: %x, %v; want the refusal %q", c.version, len(c.salt), out, err, c.want)
		}
		if !bytes.Equal(buf, bytes.Repeat([]byte{0xAA}, 128)) {
			t.Fatalf("%q, %d-byte salt: the refused header was written into the caller's buffer: %x", c.version,
				len(c.salt), buf)
		}
	}
}

// TestParseKeyIDCopiesAndReadKeyIDDoesNot: ParseKeyID's tenant key id is a copy, which a change to the ciphertext
// leaves as it was; ReadKeyID's is the ciphertext's own header bytes, read without an allocation.
func TestParseKeyIDCopiesAndReadKeyIDDoesNot(t *testing.T) {
	id := bytes.Repeat([]byte{7}, TenantKeyIDLen)
	ct := append(append(append([]byte(CiphertextMagic), FormatTenantKey), id...), make([]byte, CiphertextSaltLen+28)...)
	parsed, err := ParseKeyID(Release(), ct)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadKeyID(Release(), ct)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(CiphertextMagic)+1] = 8
	if !bytes.Equal(parsed.TenantKeyID, id) || read.TenantKeyID[0] != 8 || len(read.TenantKeyID) != TenantKeyIDLen ||
		cap(read.TenantKeyID) != TenantKeyIDLen {
		t.Fatalf("ParseKeyID's id %x (want a copy), ReadKeyID's %x (want the ciphertext's, capped)", parsed.TenantKeyID,
			read.TenantKeyID)
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = ReadKeyID(Release(), ct) }); n != 0 {
		t.Fatalf("ReadKeyID of a format-3 ciphertext allocates %v times", n)
	}
}

// TestReadKeyIDNamingReadsOnlyItsNames: ReadKeyIDNaming reads a ciphertext of a format whose header names what it is
// asked for — as ReadKeyID reads it — and refuses (ErrCiphertext) one whose format names the other key; what is not a
// ciphertext is ReadKeyID's refusal.
func TestReadKeyIDNamingReadsOnlyItsNames(t *testing.T) {
	tail := make([]byte, CiphertextSaltLen+CiphertextNonceLen+CiphertextTagLen)
	v4, err := AppendVersionedHeaderFormat(Release(), nil, FormatVersionedAAD, "v1", tail[:CiphertextSaltLen])
	if err != nil {
		t.Fatal(err)
	}
	v4 = append(v4, tail[CiphertextSaltLen:]...)
	t3 := append(append([]byte(CiphertextMagic), FormatTenantKeyAAD), bytes.Repeat([]byte{7}, TenantKeyIDLen)...)
	t3 = append(t3, tail...)
	for _, c := range []struct {
		ct    []byte
		names Names
		ok    bool
	}{
		{v4, NamesMasterVersion, true}, {t3, NamesTenantKey, true},
		{v4, NamesTenantKey, false}, {t3, NamesMasterVersion, false}, {v4, NamesNoKey, false},
	} {
		got, err := ReadKeyIDNaming(Release(), c.ct, c.names)
		read, _ := ReadKeyID(Release(), c.ct)
		switch {
		case c.ok && (err != nil || got.Format != read.Format || got.MasterVersion != read.MasterVersion ||
			!bytes.Equal(got.TenantKeyID, read.TenantKeyID) || got.HeaderLen != read.HeaderLen ||
			got.AssociatedData != read.AssociatedData):
			t.Errorf("format %d as %s: %+v, %v; want %+v", c.ct[4], c.names, got, err, read)
		case !c.ok && err != ErrCiphertext: //nolint:errorlint // the very value
			t.Errorf("format %d as %s: %+v, %v; want ErrCiphertext", c.ct[4], c.names, got, err)
		}
	}
	for _, b := range [][]byte{nil, []byte("CPH1\x07"), []byte("CPT1\x01")} {
		_, want := ReadKeyID(Release(), b)
		if _, err := ReadKeyIDNaming(Release(), b, NamesMasterVersion); err == nil || err.Error() != want.Error() {
			t.Errorf("%q: %v; want %v", b, err, want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = ReadKeyIDNaming(Release(), t3, NamesTenantKey) }); n != 0 {
		t.Fatalf("ReadKeyIDNaming of a format-6 ciphertext allocates %v times", n)
	}
}

// TestAnOpenerHoldsWhatOpenReadsAndNoMore: an opener is the AEAD, the item's body and the additional data — 64 bytes,
// one allocation size class below one more field, which every request that opens a ciphertext pays — and an item that
// does not decrypt is ErrNotDecrypted: its own refusal, which is not ErrCiphertext (the bytes are a ciphertext) and
// not ErrOpen (a sealed payload's).
func TestAnOpenerHoldsWhatOpenReadsAndNoMore(t *testing.T) {
	if n := reflect.TypeFor[Opener]().Size(); n > 64 {
		t.Fatalf("an Opener is %d bytes, more than 64", n)
	}
	key := bytes.Repeat([]byte{1}, CiphertextKeyLen)
	s, err := NewCiphertextSealer(Release(), NamesMasterVersion, key, KeyID{MasterVersion: "v1"}, "docs", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ct := s.Seal([]byte("a row"))
	ct[len(ct)-1] ^= 1
	k, err := ParseKeyID(Release(), ct)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewCiphertextOpener(Release(), key, k, "docs", "", ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(); err != ErrNotDecrypted || errors.Is(err, ErrCiphertext) || errors.Is(err, ErrOpen) || //nolint:errorlint // the very value
		err.Error() != "cipheron: the ciphertext could not be decrypted" {
		t.Fatalf("a modified ciphertext: %v", err)
	}
}
