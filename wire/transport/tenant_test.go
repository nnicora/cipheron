package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidTenant(t *testing.T) {
	var everyPrintable []byte
	for c := byte('!'); c <= '~'; c++ {
		everyPrintable = append(everyPrintable, c)
	}
	for _, ok := range []string{"a", "!", "~", "t_01HVZ6Q8", "550e8400-e29b-41d4-a716-446655440000", "eu:acme.prod",
		"A-Z_a.z:0-9", "a|b", "a/b", "a*", "%41", "user@example.com", "https://example.com/tenants/42?region=eu#x",
		"arn:aws:organizations::123456789012:account/o-a1b2c3d4e5/123456789012", "spiffe://example.org/ns/acme",
		"SGVsbG8+/w==", "x|message", string(everyPrintable), strings.Repeat("x", MaxTenantLen)} {
		if !ValidTenant(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", MaxTenantLen+1), "a b", " a", "a ", "ä", "a\x00", "a\n",
		"a\t", "a\x7f", "a\x80", "a\xff", "a\xe2\x80\x8b", "a\xe2\x80\xae", "\xef\xbb\xbfa"} {
		if ValidTenant(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	// Every byte value: only 0x21 to 0x7E is a tenant id's.
	for b := 0; b < 256; b++ {
		if got, want := ValidTenant(string([]byte{byte(b)})), b >= 0x21 && b <= 0x7e; got != want {
			t.Errorf("byte 0x%02x: ValidTenant %v, want %v", b, got, want)
		}
	}
	if MaxTenantLen != 2048 {
		t.Fatalf("MaxTenantLen %d, the documented limit is 2048", MaxTenantLen)
	}
}

// A tenant id may contain "|" (ValidTenant), and the "|"-joined HPKE info strings still name one
// (profile, operation, tenant): a profile name holds no "|", the operations are fixed words, and the tenant is the
// rest of the context string. Tenant ids built to look like another field are here.
func TestInfoStringsWithBarInTenant(t *testing.T) {
	type in struct {
		profile, tenant string
		op              Operation
	}
	ins := []in{
		{"docs", "", OpEncrypt}, {"docs", "a", OpEncrypt}, {"docs", "a|", OpEncrypt}, {"docs", "|a", OpEncrypt},
		{"docs", "a|b", OpEncrypt}, {"docs", "encrypt", OpEncrypt}, {"docs", "encrypt|a", OpEncrypt},
		{"docs", "a", OpDecrypt}, {"docs", "a|decrypt", OpEncrypt}, {"docs", "x|docs|encrypt|a", OpEncrypt},
		{"doc", "s|encrypt|a", OpEncrypt},
	}
	seen := map[string]in{}
	for _, x := range ins {
		for _, info := range [][]byte{
			RequestInfoTenant(x.profile, x.op, x.tenant),
			ResponseInfoTenant(Release(), x.profile, x.op, x.tenant),
			RequestSealInfo(Release(), x.profile, x.op, x.tenant, nil),
		} {
			if prev, dup := seen[string(info)]; dup {
				t.Fatalf("%+v and %+v share the info string %q", prev, x, info)
			}
			seen[string(info)] = x
		}
	}
}

var testCreated = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func testHeader(t *testing.T, profile, tenant string) *TenantKeyHeader {
	t.Helper()
	keyID := make([]byte, TenantKeyIDLen)
	_, _ = rand.Read(keyID)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return &TenantKeyHeader{Version: TenantKeyVersion, KeyID: keyID, Profile: profile, Tenant: tenant, SigningPublicKey: pub,
		WrappingVersion: "v2", Created: testCreated, Salt: bytes.Repeat([]byte{0x5a}, TenantKeySaltLen)}
}

// testBlob is a blob of a random key, with random bytes for the sealed part.
func testBlob(t *testing.T, profile, tenant string) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	h := testHeader(t, profile, tenant)
	blob, err := AppendTenantKeyHeader(Release(), nil, h)
	if err != nil {
		t.Fatal(err)
	}
	sealed := make([]byte, TenantSealedLen)
	_, _ = rand.Read(sealed)
	return append(blob, sealed...), h.KeyID, h.SigningPublicKey
}

func mustHeader(t *testing.T, h *TenantKeyHeader) []byte {
	t.Helper()
	b, err := AppendTenantKeyHeader(Release(), nil, h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTheTenantKeyLayout: a header reads back as written, AAD is exactly what precedes the nonce, and every
// truncation, extension, malformed field, other version byte or other layout is refused.
func TestTheTenantKeyLayout(t *testing.T) {
	h0 := testHeader(t, "docs", "t_1")
	blob := append(mustHeader(t, h0), make([]byte, TenantSealedLen)...)
	h, err := ParseTenantKey(Release(), blob)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 1 || h.Profile != "docs" || h.Tenant != "t_1" || !bytes.Equal(h.KeyID, h0.KeyID) ||
		!bytes.Equal(h.SigningPublicKey, h0.SigningPublicKey) || h.WrappingVersion != "v2" ||
		!h.Created.Equal(testCreated) || len(h.Sealed) != TenantSealedLen ||
		!bytes.Equal(h.AAD, blob[:len(blob)-TenantSealedLen]) {
		t.Fatalf("header = %+v", h)
	}
	// "CPT1" 1 | id 16 | lp(docs) | lp(t_1) | pub 32 | 2 "v2" | created 8 | salt 32 | sealed
	if len(blob) != 4+1+16+4+4+4+3+32+1+2+8+TenantKeySaltLen+TenantSealedLen || string(blob[:4]) != "CPT1" || blob[4] != 1 {
		t.Fatalf("layout: %d bytes %x", len(blob), blob[:5])
	}
	tail := blob[4+1+16+4+4+4+3+32 : len(blob)-TenantSealedLen-TenantKeySaltLen]
	if !bytes.Equal(tail, append([]byte{2, 'v', '2'}, binary.BigEndian.AppendUint64(nil, uint64(testCreated.Unix()))...)) {
		t.Fatalf("wrap fields: %x", tail)
	}
	for n := 0; n < len(blob); n++ {
		if _, err := ParseTenantKey(Release(), blob[:n]); !errors.Is(err, ErrTenantKey) {
			t.Fatalf("truncated to %d bytes: %v", n, err)
		}
	}
	with := func(f func(h *TenantKeyHeader)) *TenantKeyHeader {
		c := *h0
		f(&c)
		return &c
	}
	mod := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), blob...)) }
	verOff := 4 + 1 + 16 + 4 + 4 + 4 + 3 + 32
	for name, b := range map[string][]byte{
		"one byte more":           append(append([]byte(nil), blob...), 0),
		"another magic":           mod(func(b []byte) []byte { b[0] = 'X'; return b }),
		"version 2":               mod(func(b []byte) []byte { b[4] = 2; return b }),
		"version 3":               mod(func(b []byte) []byte { b[4] = 3; return b }),
		"version 255":             mod(func(b []byte) []byte { b[4] = 255; return b }),
		"version 0":               mod(func(b []byte) []byte { b[4] = 0; return b }),
		"a huge length":           mod(func(b []byte) []byte { b[21] = 0xff; return b }),
		"a zero-length version":   mod(func(b []byte) []byte { b[verOff] = 0; return b }),
		"a 33-byte version":       mod(func(b []byte) []byte { b[verOff] = 33; return b }),
		"a version over the blob": mod(func(b []byte) []byte { b[verOff] = 3; return b }),
		"a bad version char":      mod(func(b []byte) []byte { b[verOff+1] = '|'; return b }),
		"a negative creation":     mod(func(b []byte) []byte { b[verOff+3] = 0x80; return b }),
		"a creation time of 0": mod(func(b []byte) []byte {
			copy(b[verOff+3:verOff+3+8], make([]byte, 8))
			return b
		}),
		"over the maximum": make([]byte, MaxTenantKeyLen+1),
		// Other layouts under this version byte — no wrapping fields and no salt; no salt —: refused.
		"no wrapping fields, no salt": append(append([]byte("CPT1\x01"), blob[5:4+1+16+4+4+4+3+32]...),
			make([]byte, TenantSealedLen)...),
		"no salt": append(append(append([]byte("CPT1\x01"), blob[5:4+1+16+4+4+4+3+32]...), tail...),
			make([]byte, TenantSealedLen)...),
	} {
		if _, err := ParseTenantKey(Release(), b); !errors.Is(err, ErrTenantKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]*TenantKeyHeader{
		"an empty profile":       with(func(h *TenantKeyHeader) { h.Profile = "" }),
		"a 64-byte profile":      with(func(h *TenantKeyHeader) { h.Profile = strings.Repeat("d", 64) }),
		"a bad tenant":           with(func(h *TenantKeyHeader) { h.Tenant = "t 1" }),
		"no tenant":              with(func(h *TenantKeyHeader) { h.Tenant = "" }),
		"a short public key":     with(func(h *TenantKeyHeader) { h.SigningPublicKey = h.SigningPublicKey[:31] }),
		"a short key id":         with(func(h *TenantKeyHeader) { h.KeyID = h.KeyID[:15] }),
		"no wrapping version":    with(func(h *TenantKeyHeader) { h.WrappingVersion = "" }),
		"a bad wrapping ver":     with(func(h *TenantKeyHeader) { h.WrappingVersion = "v/2" }),
		"a creation before 1970": with(func(h *TenantKeyHeader) { h.Created = time.Unix(-1, 0) }),
		"no creation time":       with(func(h *TenantKeyHeader) { h.Created = time.Time{} }),
		"a creation at 1970":     with(func(h *TenantKeyHeader) { h.Created = time.Unix(0, 0) }),
		"version 0 (unset)":      with(func(h *TenantKeyHeader) { h.Version = 0 }),
		"version 2":              with(func(h *TenantKeyHeader) { h.Version = 2 }),
		"version 2, no salt":     with(func(h *TenantKeyHeader) { h.Version, h.Salt = 2, nil }),
		"version 3":              with(func(h *TenantKeyHeader) { h.Version = 3 }),
		"no salt":                with(func(h *TenantKeyHeader) { h.Salt = nil }),
	} {
		if _, err := AppendTenantKeyHeader(Release(), nil, bad); !errors.Is(err, ErrTenantKey) {
			t.Errorf("AppendTenantKeyHeader with %s: %v", name, err)
		}
	}
	if _, err := CheckTenantKey(Release(), blob, "docs", "t_2"); !errors.Is(err, ErrTenantKey) {
		t.Fatalf("another tenant: %v", err)
	}
	if _, err := CheckTenantKey(Release(), blob, "docs2", "t_1"); !errors.Is(err, ErrTenantKey) {
		t.Fatalf("another profile: %v", err)
	}
}

// TestTheTenantKeyLayoutOffsets: the blob has the 32-byte salt after the creation time, in the header (the AAD):
// every offset as specified, 226 bytes plus the profile, the tenant and the version id, the longest exactly
// MaxTenantKeyLen (2369); every truncation and extension, a salt of the wrong length, a creation time of 0 and a
// version byte changed to 0, 2 or 3 are refused.
func TestTheTenantKeyLayoutOffsets(t *testing.T) {
	h0 := testHeader(t, "docs", "t_1")
	sealed := bytes.Repeat([]byte{0xc3}, TenantSealedLen)
	blob := append(mustHeader(t, h0), sealed...)
	if len(blob) != 226+len("docs")+len("t_1")+len("v2") {
		t.Fatalf("%d bytes", len(blob))
	}
	// Every field at its offset.
	for name, f := range map[string]struct {
		from, to int
		want     []byte
	}{
		"magic":          {0, 4, []byte("CPT1")},
		"version":        {4, 5, []byte{1}},
		"key id":         {5, 21, h0.KeyID},
		"profile length": {21, 25, u32(4)},
		"profile":        {25, 29, []byte("docs")},
		"tenant length":  {29, 33, u32(3)},
		"tenant":         {33, 36, []byte("t_1")},
		"public key":     {36, 68, h0.SigningPublicKey},
		"version length": {68, 69, []byte{2}},
		"version id":     {69, 71, []byte("v2")},
		"created":        {71, 79, binary.BigEndian.AppendUint64(nil, uint64(testCreated.Unix()))},
		"salt":           {79, 111, bytes.Repeat([]byte{0x5a}, TenantKeySaltLen)},
		"sealed":         {111, 235, sealed},
	} {
		if !bytes.Equal(blob[f.from:f.to], f.want) {
			t.Errorf("%s at [%d:%d]: %x", name, f.from, f.to, blob[f.from:f.to])
		}
	}
	h, err := CheckTenantKey(Release(), blob, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != TenantKeyVersion || h.Profile != "docs" || h.Tenant != "t_1" || !bytes.Equal(h.KeyID, h0.KeyID) ||
		!bytes.Equal(h.SigningPublicKey, h0.SigningPublicKey) || h.WrappingVersion != "v2" ||
		!h.Created.Equal(testCreated) || !bytes.Equal(h.Salt, h0.Salt) || !bytes.Equal(h.AAD, blob[:111]) ||
		!bytes.Equal(h.Sealed, sealed) {
		t.Fatalf("header = %+v", h)
	}
	// The salt aliases the blob, and cannot be appended into the sealed part.
	if &h.Salt[0] != &blob[79] || cap(h.Salt) != TenantKeySaltLen {
		t.Fatal("the salt does not alias the blob, or reaches past it")
	}
	for n := 0; n < len(blob); n++ {
		if _, err := ParseTenantKey(Release(), blob[:n]); !errors.Is(err, ErrTenantKey) {
			t.Fatalf("truncated to %d bytes: %v", n, err)
		}
	}
	mod := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), blob...)) }
	for name, b := range map[string][]byte{
		"one byte more":       append(append([]byte(nil), blob...), 0),
		"read as version 0":   mod(func(b []byte) []byte { b[4] = 0; return b }),
		"read as version 2":   mod(func(b []byte) []byte { b[4] = 2; return b }),
		"read as version 3":   mod(func(b []byte) []byte { b[4] = 3; return b }),
		"no creation time":    mod(func(b []byte) []byte { copy(b[71:79], make([]byte, 8)); return b }),
		"no salt":             append(append([]byte(nil), blob[:79]...), sealed...),
		"a short salt":        append(append([]byte(nil), blob[:79+31]...), sealed...),
		"a negative creation": mod(func(b []byte) []byte { b[71] = 0x80; return b }),
	} {
		if _, err := ParseTenantKey(Release(), b); !errors.Is(err, ErrTenantKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A changed salt is another header (the AAD): the blob does not open.
	other := mod(func(b []byte) []byte { b[96] ^= 1; return b })
	if ho, err := ParseTenantKey(Release(), other); err != nil || bytes.Equal(ho.AAD, h.AAD) || bytes.Equal(ho.Salt, h.Salt) {
		t.Fatalf("a changed salt: %+v %v", ho, err)
	}
	for name, salt := range map[string][]byte{"no salt": nil, "31 bytes": make([]byte, 31), "33 bytes": make([]byte, 33)} {
		c := *h0
		c.Salt = salt
		if _, err := AppendTenantKeyHeader(Release(), nil, &c); !errors.Is(err, ErrTenantKey) {
			t.Errorf("AppendTenantKeyHeader with %s: %v", name, err)
		}
	}
	// The longest blob, MaxTenantKeyLen = 2369 bytes, parses; one byte more is refused before anything is read.
	longest := *h0
	longest.Profile, longest.Tenant, longest.WrappingVersion = strings.Repeat("d", 63), strings.Repeat("t", MaxTenantLen), strings.Repeat("v", 32)
	long := append(mustHeader(t, &longest), sealed...)
	if MaxTenantKeyLen != 2369 || len(long) != MaxTenantKeyLen {
		t.Fatalf("MaxTenantKeyLen %d, the longest blob %d bytes", MaxTenantKeyLen, len(long))
	}
	if _, err := ParseTenantKey(Release(), long); err != nil {
		t.Fatalf("the longest blob: %v", err)
	}
	if _, err := ParseTenantKey(Release(), append(long, 0)); !errors.Is(err, ErrTenantKey) {
		t.Fatal("a blob over the maximum parsed")
	}
	if TenantKeyVersion != 1 || TenantKeySaltLen != 32 {
		t.Fatal("the version constants")
	}
}

// TestTheTenantFingerprintBindsEveryField: profile, tenant, key id and public key each change it.
func TestTheTenantFingerprintBindsEveryField(t *testing.T) {
	_, keyID, pub := testBlob(t, "docs", "t_1")
	fp := TenantFingerprint("docs", "t_1", keyID, pub)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherID := bytes.Clone(keyID)
	otherID[0] ^= 1
	if !ValidFingerprint(fp) {
		t.Fatalf("%q", fp)
	}
	for name, o := range map[string]string{
		"profile":    TenantFingerprint("docs2", "t_1", keyID, pub),
		"tenant":     TenantFingerprint("docs", "t_2", keyID, pub),
		"key id":     TenantFingerprint("docs", "t_1", otherID, pub),
		"public key": TenantFingerprint("docs", "t_1", keyID, other),
		"split":      TenantFingerprint("doc", "st_1", keyID, pub),
		"profile fp": Fingerprint("docs", Identity{Tenancy: TenancyPerTenantWrapped, HPKE: keyID, Response: pub}),
	} {
		if o == fp {
			t.Errorf("%s: the same fingerprint", name)
		}
	}
}

// TestTenantInfoAndDigests: the tenant is in the info strings and the digests; a shared profile's are unchanged
// in form and distinct from every tenant's.
func TestTenantInfoAndDigests(t *testing.T) {
	if string(RequestInfoTenant("docs", OpEncrypt, "")) != "cipheron/v1|request|docs|encrypt" ||
		string(RequestInfoTenant("docs", OpEncrypt, "t_1")) != "cipheron/v1|request|docs|encrypt|t_1" ||
		string(ResponseInfoTenant(Release(), "docs", OpDecrypt, "t_1")) != "cipheron/v1|response|docs|decrypt|t_1\x00\x00\x00\x04\x00\x00\x00\x01" {
		t.Fatal("the info strings are not the specified ones")
	}
	server, _ := NewOneTimeKey()
	enc, ct, _ := Seal(server.PublicKey(), RequestInfoTenant("docs", OpEncrypt, "t_1"), []byte("p"))
	for _, info := range [][]byte{RequestInfoTenant("docs", OpEncrypt, ""), RequestInfoTenant("docs", OpEncrypt, "t_2"),
		RequestInfoTenant("docs", OpSign, "t_1")} {
		if _, err := Open(server, info, enc, ct); !errors.Is(err, ErrOpen) {
			t.Fatalf("a payload sealed for tenant t_1 opened under %q", info)
		}
	}
	blob, _, _ := testBlob(t, "docs", "t_1")
	other, _, _ := testBlob(t, "docs", "t_1")
	e, s := []byte("enc"), []byte("sealed")
	all := map[string][32]byte{
		"shared":       EncryptDigest(e, s, "", nil),
		"tenant":       EncryptDigest(e, s, "t_1", blob),
		"other tenant": EncryptDigest(e, s, "t_2", blob),
		"other blob":   EncryptDigest(e, s, "t_1", other),
		"no blob":      EncryptDigest(e, s, "t_1", nil),
		"old form":     Digest(e, s),
	}
	seen := map[[32]byte]string{}
	for name, d := range all {
		if prev, dup := seen[d]; dup {
			t.Fatalf("%s and %s have one digest", name, prev)
		}
		seen[d] = name
	}
	// Encrypt and Sign share a field list; the operation in the transcript tells them apart.
	if EncryptDigest(e, s, "t_1", blob) != SignDigest(e, s, "t_1", blob) {
		t.Fatal("encrypt and sign digests differ in form")
	}
	if ProvisionDigest("t_1") != RewrapTenantKeyDigest("t_1", nil) || ProvisionDigest("t_1") == ProvisionDigest("t_2") ||
		ProvisionDigest("t_1") == RewrapTenantKeyDigest("t_1", blob) {
		t.Fatal("the provision digest is not tenant and an empty key")
	}
}
