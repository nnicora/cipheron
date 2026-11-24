package transport

// lifecycle_test.go — a version that exists only in a test, walked through the compatibility policy's lifecycle with
// no global state: each test builds its own policies from the release (Release().With), checks each step with
// format.Check, and reads and writes under each. Nothing is registered, so every test runs in parallel with every
// other.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nnicora/cipheron/wire/format"
)

// policyOf is With's policy, or the test's failure.
func policyOf(t *testing.T) func(*format.Policy, error) *format.Policy {
	t.Helper()
	return func(p *format.Policy, err error) *format.Policy {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
}

// walk is a kind's lifecycle for its test version 2 of entry v2: the release over a catalog that has it, then reads
// {1, 2}, then writes 2, then reads only 2. It checks every step with format.Check, and that the two steps out of
// order are refused.
func walk(t *testing.T, v2 format.Entry, rule func(write uint32, read ...uint32) format.Rule,
) (released, reads, writes, dropped *format.Policy) {
	t.Helper()
	with := func(write uint32, read ...uint32) *format.Policy {
		return policyOf(t)(Release().With([]format.Entry{v2}, rule(write, read...)))
	}
	released = policyOf(t)(Release().With([]format.Entry{v2}))
	reads, writes, dropped = with(1, 1, 2), with(2, 1, 2), with(2, 2)
	for i, step := range [][2]*format.Policy{{released, reads}, {reads, writes}, {writes, dropped}} {
		if err := format.Check(step[0], step[1]); err != nil {
			t.Fatalf("step %d: %v", i+1, err)
		}
	}
	if format.Check(released, writes) == nil {
		t.Fatal("a writer before its readers is allowed")
	}
	if format.Check(reads, dropped) == nil {
		t.Fatal("a written version dropped is allowed")
	}
	return released, reads, writes, dropped
}

func TestTheTenantKeyBlobVersionLifecycle(t *testing.T) {
	t.Parallel()
	v2 := tenantKeys.Scheme(2, "a test version", tenantKeyBlobV1{},
		format.SealedBy(format.HKDFSHA256AESGCM(), "tenant-wrapping key"))
	released, reads, writes, dropped := walk(t, v2, func(w uint32, r ...uint32) format.Rule {
		return tenantKeys.Reads(r...).Writes(0, w)
	})
	wrapKey, private := bytes.Repeat([]byte{3}, CiphertextKeyLen), make([]byte, TenantPrivateLen)
	pub, ok := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("not an Ed25519 public key")
	}
	h := &TenantKeyHeader{KeyID: bytes.Repeat([]byte{1}, TenantKeyIDLen), Profile: "files", Tenant: "t_1",
		SigningPublicKey: pub, WrappingVersion: "v1", Created: time.Unix(1_700_000_000, 0)}
	old, err := SealTenantKey(Release(), wrapKey, h, private)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := SealTenantKey(writes, wrapKey, h, private)
	if err != nil || blob[len(TenantKeyMagic)] != 2 {
		t.Fatalf("written under version 2: %x, %v", blob[:5], err)
	}
	for _, c := range []struct {
		p    *format.Policy
		blob []byte
		ok   bool
	}{
		{released, blob, false}, {reads, blob, true}, {writes, blob, true}, {dropped, blob, true},
		{released, old, true}, {reads, old, true}, {dropped, old, false},
	} {
		got, err := ParseTenantKey(c.p, c.blob)
		if c.ok != (err == nil) || !c.ok && err != ErrTenantKey { //nolint:errorlint // the very value
			t.Fatalf("version %d: %v, %v", c.blob[4], got, err)
		}
		if !c.ok {
			continue
		}
		key, err := TenantKeyItemKey(c.p, wrapKey, got)
		if err != nil {
			t.Fatal(err)
		}
		if pt, ok := key.Open(nil, got.Sealed, got.AAD); !ok || !bytes.Equal(pt, private) {
			t.Fatalf("version %d does not open", c.blob[4])
		}
	}
	if _, err := TenantKeyItemKey(released, wrapKey, &TenantKeyHeader{Version: 2, Salt: make([]byte, 32)}); err == nil ||
		err.Error() != "cipheron: a tenant key blob of version 2; this cipheron reads version 1" {
		t.Fatalf("version 2 under the release: %v", err)
	}
	if _, err := AppendTenantKeyHeader(writes, nil, &TenantKeyHeader{Version: 1}); err == nil ||
		err.Error() != "cipheron: not a tenant key of this tenant in this profile: a header of version 1 is not written (only 2)" {
		t.Fatalf("version 1 under a policy writing 2: %v", err)
	}
}

func TestTheTranscriptVersionLifecycle(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t, transcripts.Scheme(2, "a test version", transcriptV1{}),
		func(w uint32, r ...uint32) format.Rule { return transcripts.Reads(r...).Writes(0, w) })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var digest [sha256.Size]byte
	nonce := bytes.Repeat([]byte{9}, NonceLen)
	sign := func(p *format.Policy) []byte {
		return ed25519.Sign(priv, RequestTranscript(p, "docs", OpEncrypt, 1, nonce, digest))
	}
	verifies := func(p *format.Policy, sig []byte) bool {
		return EachRequestTranscript(p, "docs", OpEncrypt, 1, nonce, digest, func(tr []byte) bool {
			return ed25519.Verify(pub, tr, sig)
		})
	}
	v1, v2 := sign(Release()), sign(writes)
	if bytes.Equal(RequestTranscript(Release(), "docs", OpEncrypt, 1, nonce, digest),
		RequestTranscript(writes, "docs", OpEncrypt, 1, nonce, digest)) {
		t.Fatal("version 2's transcript is version 1's")
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {writes, true, true}, {dropped, false, true}} {
		if verifies(c.p, v1) != c.v1 || verifies(c.p, v2) != c.v2 {
			t.Fatalf("a policy reading %v: version 1 %v, version 2 %v", c, verifies(c.p, v1), verifies(c.p, v2))
		}
	}
	// The seal infos: a payload sealed under version 2's info opens only where version 2 is read.
	sk, _ := NewOneTimeKey()
	enc, sealed, err := Seal(sk.PublicKey(), ResponseInfoTenant(writes, "docs", OpDecrypt, ""), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenResponsePayload(released, sk, "docs", OpDecrypt, "", enc, sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("version 2's seal under the release: %v", err)
	}
	if pt, err := OpenResponsePayload(reads, sk, "docs", OpDecrypt, "", enc, sealed); err != nil || string(pt) != "x" {
		t.Fatalf("version 2's seal where it is read: %v", err)
	}
	if WrittenTranscriptVersion(writes) != 2 || WrittenTranscriptVersion(reads) != 1 {
		t.Fatal("the written transcript version")
	}
}

func TestTheKeyStatementReadsTheVersionInItsBytes(t *testing.T) {
	t.Parallel()
	st := testStatement(t)
	b, err := MarshalKeyStatement(Release(), st)
	if err != nil {
		t.Fatal(err)
	}
	released, reads, _, dropped := walk(t, keyStatements.Scheme(2, "a test version", statementV1{}),
		func(w uint32, r ...uint32) format.Rule { return keyStatements.Reads(r...).Writes(0, w) })
	v2 := marshalAs(t, st, 2)
	if _, err := ParseKeyStatement(released, v2); err == nil ||
		err.Error() != "cipheron: not a valid key statement: not a key statement of version 1" {
		t.Fatalf("a version-2 statement: %v", err)
	}
	if _, err := ParseKeyStatement(reads, v2); err != nil {
		t.Fatalf("a version-2 statement once version 2 is read: %v", err)
	}
	if _, err := ParseKeyStatement(reads, b); err != nil {
		t.Fatalf("a version-1 statement: %v", err)
	}
	if _, err := ParseKeyStatement(dropped, b); err == nil ||
		err.Error() != "cipheron: not a valid key statement: not a key statement of version 2" {
		t.Fatalf("a version-1 statement once only 2 is read: %v", err)
	}
}

func TestTheJSONFieldVersionLifecycle(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t,
		jsonFields.Scheme(2, "a test version", jsonFieldV1{}, format.Marker("cipheron:v2:")),
		func(w uint32, r ...uint32) format.Rule { return jsonFields.Reads(r...).Writes(0, w) })
	ct := []byte("a ciphertext")
	v1, v2 := EncodeJSONField(Release(), ct), EncodeJSONField(writes, ct)
	if v1[:len(JSONFieldPrefix)] != JSONFieldPrefix || v2[:12] != "cipheron:v2:" {
		t.Fatalf("the values %q, %q", v1, v2)
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {dropped, false, true}} {
		got1, err1 := DecodeJSONField(c.p, v1)
		got2, err2 := DecodeJSONField(c.p, v2)
		if (err1 == nil) != c.v1 || (err2 == nil) != c.v2 || IsJSONField(c.p, v1) != c.v1 || IsJSONField(c.p, v2) != c.v2 ||
			err1 != nil && err1 != ErrJSONField || err2 != nil && err2 != ErrJSONField || //nolint:errorlint // the very value
			c.v1 && !bytes.Equal(got1, ct) || c.v2 && !bytes.Equal(got2, ct) {
			t.Fatalf("%v: %v, %v", c, err1, err2)
		}
	}
	for _, v := range []string{"cipheron:v01:AAAA", "cipheron:v1", "cipheron:v1:", "cipheron:v3:AAAA", "x"} {
		if _, err := DecodeJSONField(reads, v); err != ErrJSONField { //nolint:errorlint // the very value
			t.Fatalf("%q: %v", v, err)
		}
	}
}

func TestTheKeyStatementExportVersionLifecycle(t *testing.T) {
	t.Parallel()
	released, reads, writes, dropped := walk(t,
		statementExports.Scheme(2, "a test version", statementExportV1{}, format.Marker("cipheron-key-statement/2")),
		func(w uint32, r ...uint32) format.Rule { return statementExports.Reads(r...).Writes(0, w) })
	raw, sig := []byte("statement"), []byte("signature")
	v1, err1 := ExportKeyStatement(Release(), "docs", "sha256:x", raw, sig)
	v2, err2 := ExportKeyStatement(writes, "docs", "sha256:x", raw, sig)
	if err := errors.Join(err1, err2); err != nil || !bytes.Contains(v2, []byte(`"cipheron-key-statement/2"`)) {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p      *format.Policy
		v1, v2 bool
	}{{released, true, false}, {reads, true, true}, {dropped, false, true}} {
		r1, s1, e1 := ReadKeyStatementExport(c.p, v1)
		_, _, e2 := ReadKeyStatementExport(c.p, v2)
		if (e1 == nil) != c.v1 || (e2 == nil) != c.v2 || e1 != nil && e1 != ErrKeyStatementExport || //nolint:errorlint // the very value
			e2 != nil && e2 != ErrKeyStatementExport || c.v1 && (!bytes.Equal(r1, raw) || !bytes.Equal(s1, sig)) { //nolint:errorlint // the very value
			t.Fatalf("%v: %v, %v", c, e1, e2)
		}
	}
	// The token is matched exactly, never as a prefix; a statement that is not base64 is the join of the fields' errors.
	for _, doc := range []string{
		`{"format":"cipheron-key-statement/12","profile":"","fingerprint":"","statement":"","signature":""}`,
		`{"format":"cipheron-key-statement/1","extra":1}`, `{"format":1}`, `[`,
	} {
		if _, _, err := ReadKeyStatementExport(Release(), []byte(doc)); err != ErrKeyStatementExport { //nolint:errorlint // the very value
			t.Fatalf("%s: %v", doc, err)
		}
	}
	bad := `{"format":"cipheron-key-statement/1","profile":"","fingerprint":"","statement":"!","signature":"?"}`
	if _, _, err := ReadKeyStatementExport(Release(), []byte(bad)); err == nil || errors.Is(err, ErrKeyStatementExport) {
		t.Fatalf("not base64: %v", err)
	}
}

// testStatement is a valid statement of a shared profile with one active signing key.
func testStatement(t *testing.T) *KeyStatement {
	t.Helper()
	hk, err := NewOneTimeKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, _, _ := ed25519.GenerateKey(rand.Reader)
	sign, _, _ := ed25519.GenerateKey(rand.Reader)
	return &KeyStatement{Profile: "cards", IssuedAtMS: 1_700_000_000_000,
		ContextDigest: "sha256:" + fmt.Sprintf("%064x", 0),
		Identity:      Identity{Tenancy: TenancyShared, HPKE: hk.PublicKey().Bytes(), Response: resp},
		SigningKeys:   []SigningKey{{KeyID: SigningKeyID(sign), State: SigningKeyActive, PublicKey: sign}}}
}

// marshalAs is st's statement layout binding version v.
func marshalAs(t *testing.T, st *KeyStatement, v uint32) []byte {
	t.Helper()
	b, err := marshalStatement(statementV1{}, v, st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTheFingerprintDerivationsAreChosenByTheIdentity: derivation 1 for a classical identity, 2 for any other; a
// third is refused with its words (no code asks for one).
func TestTheFingerprintDerivationsAreChosenByTheIdentity(t *testing.T) {
	if _, err := fingerprintDerivationOf(3); err == nil || err.Error() != "cipheron: no profile fingerprint of version 3" {
		t.Fatalf("derivation 3: %v", err)
	}
	for v := 1; v <= 2; v++ {
		if d, err := fingerprintDerivationOf(v); err != nil || d == nil {
			t.Fatalf("derivation %d: %v", v, err)
		}
	}
}
