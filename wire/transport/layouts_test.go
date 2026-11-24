package transport

// layouts_test.go — the extensible identity (suites, algorithms, added keys, fingerprint version 2), the signing-key
// id that binds its algorithm, caller associated data (formats 5 and 6, the digests), the key statement, the batch
// digests and the segmented object's associated data, each held to the specification: spec* below are the layouts
// written out independently of the functions under test. frozen_test.go holds the frozen set to the same
// specification.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// specSeed derives a fixed input: SHA-256 of label|a, label|b, …, cut to n bytes.
func specSeed(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		s := sha256.Sum256([]byte(label + "|" + string(rune('a'+i))))
		out = append(out, s[:]...)
	}
	return out[:n]
}

// publicOf is key's public half.
func publicOf(t *testing.T, key ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("an Ed25519 private key's public half: got %T", key.Public())
	}
	return pub
}

// specIdentity is a fixed classical identity (its HPKE key a real P-256 point: SerializePublicKey of a fixed scalar).
func specIdentity(t *testing.T) Identity {
	t.Helper()
	sk, err := KEM().NewPrivateKey(specSeed("hpke", 32))
	if err != nil {
		t.Fatal(err)
	}
	resp := publicOf(t, ed25519.NewKeyFromSeed(specSeed("response", 32)))
	return Identity{Tenancy: TenancyShared, HPKE: sk.PublicKey().Bytes(), Response: resp}
}

func specSigningKeys(t *testing.T) []SigningKey {
	t.Helper()
	a := publicOf(t, ed25519.NewKeyFromSeed(specSeed("signing-a", 32)))
	b := publicOf(t, ed25519.NewKeyFromSeed(specSeed("signing-b", 32)))
	keys := []SigningKey{{KeyID: SigningKeyID(a), State: SigningKeyActive, PublicKey: a},
		{KeyID: SigningKeyID(b), State: SigningKeyRevoked, PublicKey: b}}
	SortSigningKeys(keys)
	return keys
}

func TestFingerprintVersions(t *testing.T) {
	id := specIdentity(t)
	explicit := id
	explicit.HPKESuite, explicit.ResponseAlgorithm = ClassicalSuite, AlgorithmEd25519
	// A classical identity — written with or without its suite and algorithm — keeps version 1, byte for byte.
	v1 := specJoin(fingerprintLabel, "credentials", string(id.Tenancy), string(id.HPKE), string(id.Response))
	want := FingerprintPrefix + hex.EncodeToString(specSum(v1))
	if Fingerprint("credentials", id) != want || Fingerprint("credentials", explicit) != want || FingerprintVersion(id) != 1 ||
		!id.Classical() || !id.Equal(explicit) {
		t.Fatalf("a classical identity's fingerprint is not version 1's: %s", Fingerprint("credentials", id))
	}
	// Another suite, another response algorithm, an added key: version 2, each a value of its own.
	suite := id
	suite.HPKESuite = HPKESuite{KEM: 0x0647, KDF: 1, AEAD: 2}
	alg := id
	alg.ResponseAlgorithm = 9
	added := id
	added.Additional = []IdentityKey{{Role: RoleHPKE, Suite: HPKESuite{KEM: 0x0647, KDF: 1, AEAD: 2}, PublicKey: specSeed("pq", 1184)}}
	seen := map[string]bool{want: true}
	for name, k := range map[string]Identity{"suite": suite, "algorithm": alg, "added key": added} {
		fp := Fingerprint("credentials", k)
		if FingerprintVersion(k) != 2 || k.Classical() || seen[fp] || k.Equal(id) || !ValidFingerprint(fp) {
			t.Errorf("%s: fingerprint %s (version %d) is not a version-2 fingerprint of its own", name, fp, FingerprintVersion(k))
		}
		seen[fp] = true
	}
	// Version 2, written out: the suite, the algorithm and every key.
	v2 := append(specJoin(fingerprint2Label, "credentials", string(id.Tenancy), string([]byte{0x06, 0x47, 0, 1, 0, 2}),
		string(id.HPKE), string(specU32(1)), string(id.Response), string(specU32(1))),
		specJoin(string(specU32(uint32(RoleHPKE))), string([]byte{0x06, 0x47, 0, 1, 0, 2}), string(added.Additional[0].PublicKey))...)
	added.HPKESuite = suite.HPKESuite
	if got := Fingerprint("credentials", added); got != FingerprintPrefix+hex.EncodeToString(specSum(v2)) {
		t.Fatalf("fingerprint version 2 is not the specification's: %s", got)
	}
	// The order of the added keys is not the identity: canonical.
	two := id
	two.Additional = []IdentityKey{{Role: RoleResponse, Algorithm: 9, PublicKey: []byte("x")}, {Role: RoleHPKE, Suite: ClassicalSuite, PublicKey: []byte("y")}}
	swapped := two
	swapped.Additional = []IdentityKey{two.Additional[1], two.Additional[0]}
	if Fingerprint("d", two) != Fingerprint("d", swapped) {
		t.Fatal("the added keys' order changes the fingerprint")
	}
}

func TestIdentityAgility(t *testing.T) {
	id := specIdentity(t)
	other := id
	other.HPKESuite = HPKESuite{KEM: 0x0647, KDF: 1, AEAD: 2}
	other.HPKE = specSeed("x-wing", 1216)
	// Strict (cipheron) refuses what it does not make; a client tolerates it, and refuses to use it.
	if err := other.Validate(); err == nil {
		t.Fatal("strict validation accepted an unknown suite")
	}
	if err := other.ValidateReceived(); err != nil {
		t.Fatalf("a received identity of an unknown suite: %v", err)
	}
	if err := other.Usable(); err == nil {
		t.Fatal("an identity of an unknown suite is usable")
	}
	if err := id.Usable(); err != nil || id.Validate() != nil {
		t.Fatalf("a classical identity: %v %v", err, id.Validate())
	}
	bad := id
	bad.Additional = []IdentityKey{{Role: 0, PublicKey: []byte("k")}}
	if bad.ValidateReceived() == nil {
		t.Fatal("an added key without a role was accepted")
	}
	dup := id
	dup.Additional = []IdentityKey{{Role: 7, PublicKey: []byte("k")}, {Role: 7, PublicKey: []byte("k")}}
	if dup.ValidateReceived() == nil {
		t.Fatal("an added key listed twice was accepted")
	}
	// An unknown role is tolerated.
	odd := id
	odd.Additional = []IdentityKey{{Role: 7, Algorithm: 3, PublicKey: []byte("k")}}
	if err := odd.ValidateReceived(); err != nil {
		t.Fatalf("an added key of an unknown role: %v", err)
	}
}

func TestSigningKeyAlgorithm(t *testing.T) {
	id := specIdentity(t)
	keys := specSigningKeys(t)
	pub := specSeed("ml-dsa", 1952)
	if !bytes.Equal(SigningKeyIDOf(AlgorithmEd25519, keys[0].PublicKey), SigningKeyID(keys[0].PublicKey)) ||
		!bytes.Equal(SigningKeyIDOf(0, keys[0].PublicKey), SigningKeyID(keys[0].PublicKey)) {
		t.Fatal("an Ed25519 key's id is not SigningKeyID")
	}
	want := specSum(specJoin(signingKeyID2Label, string(specU32(5)), string(pub)))[:SigningKeyIDLen]
	if !bytes.Equal(SigningKeyIDOf(5, pub), want) || bytes.Equal(SigningKeyIDOf(5, pub), SigningKeyIDOf(6, pub)) {
		t.Fatal("another algorithm's key id does not bind the algorithm")
	}
	newKey := SigningKey{KeyID: SigningKeyIDOf(5, pub), State: SigningKeyVerifyOnly, PublicKey: pub, Algorithm: 5}
	list := append(append([]SigningKey(nil), keys...), newKey)
	if err := ValidateReceivedSigningKeys(id, list); err != nil {
		t.Fatalf("a received list with a key of an unknown algorithm: %v", err)
	}
	if ValidateSigningKeys(id, list) == nil {
		t.Fatal("cipheron's strict check accepted an algorithm it does not make")
	}
	for _, k := range keys {
		if k.Usable() != (k.State == SigningKeyActive) {
			t.Fatalf("Usable of a %s Ed25519 key: %v", k.State, k.Usable())
		}
	}
	if newKey.Usable() {
		t.Fatal("Usable does not judge the algorithm and the state")
	}
	// The algorithm claimed must be the one the id binds: an id of algorithm 5 under 6 is refused.
	lie := newKey
	lie.Algorithm = 6
	if ValidateReceivedSigningKeys(id, append(append([]SigningKey(nil), keys...), lie)) == nil {
		t.Fatal("a key whose id is not its algorithm's was accepted")
	}
	// The signing-keys transcript covers the id, so the algorithm too: naming Ed25519 explicitly is the same layout.
	a, err := SigningKeysTranscript(Release(), "d", TenancyShared, "sha256:"+hex.EncodeToString(make([]byte, 32)), nil, keys)
	if err != nil {
		t.Fatal(err)
	}
	withAlg := append([]SigningKey(nil), keys...)
	for i := range withAlg {
		withAlg[i].Algorithm = AlgorithmEd25519
	}
	b, _ := SigningKeysTranscript(Release(), "d", TenancyShared, "sha256:"+hex.EncodeToString(make([]byte, 32)), nil, withAlg)
	if !bytes.Equal(a, b) {
		t.Fatal("naming Ed25519 changed the signing-keys transcript")
	}
}

func TestAssociatedDataDigests(t *testing.T) {
	enc, sealed, tk := []byte("enc"), []byte("sealed"), []byte("blob")
	if EncryptDigestAAD(enc, sealed, "t", tk, nil) != EncryptDigest(enc, sealed, "t", tk) ||
		DecryptDigestAAD(enc, sealed, "t", tk, nil) != DecryptDigest(enc, sealed, "t", tk) ||
		ReEncryptDigestExt(sealed, "t", tk, enc, ReEncryptExt{}) != ReEncryptDigest(sealed, "t", tk, enc) {
		t.Fatal("a request without the new fields is not digested as before")
	}
	if EncryptDigestAAD(enc, sealed, "t", tk, []byte("a")) == EncryptDigest(enc, sealed, "t", tk) ||
		EncryptDigestAAD(enc, sealed, "t", tk, []byte("a")) != Digest(enc, sealed, []byte("t"), tk, []byte("a")) {
		t.Fatal("the associated data is not the digest's fifth field")
	}
	seen := map[[32]byte]string{}
	for name, e := range map[string]ReEncryptExt{
		"none": {}, "aad": {AssociatedData: []byte("x")}, "to aad": {ToAssociatedData: []byte("x")},
		"to profile": {ToProfile: "x"}, "to tenant": {ToTenant: "x"}, "both aad": {AssociatedData: []byte("x"), ToAssociatedData: []byte("x")},
	} {
		d := ReEncryptDigestExt(sealed, "t", tk, enc, e)
		if other, dup := seen[d]; dup {
			t.Fatalf("%s and %s have one digest", name, other)
		}
		seen[d] = name
	}
}

func TestAssociatedDataFormats(t *testing.T) {
	salt := make([]byte, CiphertextSaltLen)
	tail := make([]byte, CiphertextNonceLen+CiphertextTagLen)
	v5, err := AppendVersionedHeaderFormat(Release(), nil, FormatVersionedAAD, "v2", salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendVersionedHeaderFormat(Release(), nil, FormatTenantKey, "v2", salt); err == nil {
		t.Fatal("a format-3 versioned header was written")
	}
	k, err := ParseKeyID(Release(), append(v5, tail...))
	if err != nil || k.Format != FormatVersionedAAD || !k.AssociatedData || !k.Versioned() || k.MasterVersion != "v2" || k.String() != "v2" {
		t.Fatalf("format 5: %+v %v", k, err)
	}
	six := append(append(append([]byte(CiphertextMagic), FormatTenantKeyAAD), make([]byte, TenantKeyIDLen)...), salt...)
	k6, err := ParseKeyID(Release(), append(six, tail...))
	if err != nil || !k6.AssociatedData || !k6.TenantKey() || k6.String() != "tenant-key:"+hex.EncodeToString(make([]byte, 16)) {
		t.Fatalf("format 6: %+v %v", k6, err)
	}
	v4, _ := AppendVersionedHeader(Release(), nil, "v2", salt)
	k4, _ := ParseKeyID(Release(), append(v4, tail...))
	for _, c := range []struct {
		k   KeyID
		aad []byte
		ok  bool
	}{{k, []byte("a"), true}, {k, nil, false}, {k4, nil, true}, {k4, []byte("a"), false},
		{k, make([]byte, MaxAssociatedDataLen), true}, {k, make([]byte, MaxAssociatedDataLen+1), false}} {
		if err := CheckAssociatedData(c.k, c.aad); (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrAssociatedData)) {
			t.Errorf("format %d with %d bytes of associated data: %v", c.k.Format, len(c.aad), err)
		}
	}
}

func specStatement(t *testing.T) *KeyStatement {
	t.Helper()
	return &KeyStatement{Profile: "credentials", IssuedAtMS: 1_800_000_000_000,
		ContextDigest: "sha256:" + hex.EncodeToString(specSeed("context", 32)), Identity: specIdentity(t), SigningKeys: specSigningKeys(t)}
}

// statementSpec is a key statement's bytes from the specification (statement.go): lp(label) lp(version: 4)
// lp(profile) lp(tenancy) lp(issued at: 8) lp(context digest) lp(hpke suite: 6) lp(hpke key) lp(response algorithm: 4)
// lp(response key) lp(n: 4) and the n added keys, lp(k: 4) and k × (lp(key id) lp(state number: 4) lp(algorithm: 4)
// lp(public key)) in ascending key id. st's identity has no added key.
func statementSpec(st *KeyStatement) []byte {
	suite := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, KEMID), KDFID), AEADID)
	b := specJoin("cipheron/v1|key_statement", string(specU32(1)), st.Profile, string(st.Identity.Tenancy),
		string(binary.BigEndian.AppendUint64(nil, uint64(st.IssuedAtMS))), st.ContextDigest, string(suite),
		string(st.Identity.HPKE), string(specU32(1)), string(st.Identity.Response), string(specU32(0)),
		string(specU32(uint32(len(st.SigningKeys)))))
	keys := append([]SigningKey(nil), st.SigningKeys...)
	SortSigningKeys(keys)
	for _, k := range keys {
		b = append(b, specJoin(string(k.KeyID), string(specU32(k.State.Code())), string(specU32(1)), string(k.PublicKey))...)
	}
	return b
}

func TestKeyStatement(t *testing.T) {
	st := specStatement(t)
	raw, err := MarshalKeyStatement(Release(), st)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Identity.Additional) != 0 || !bytes.Equal(raw, statementSpec(st)) {
		t.Fatal("the statement's bytes are not the specification's")
	}
	respPriv := ed25519.NewKeyFromSeed(specSeed("response", 32))
	sig := ed25519.Sign(respPriv, raw)
	fp := Fingerprint("credentials", st.Identity)
	got, err := VerifyKeyStatement(Release(), raw, sig, "credentials", fp)
	if err != nil || got.IssuedAtMS != st.IssuedAtMS || got.ContextDigest != st.ContextDigest || len(got.SigningKeys) != 2 ||
		got.SigningKeys[1].State != specSigningKeys(t)[1].State || !got.Identity.Equal(st.Identity) {
		t.Fatalf("the statement does not verify as itself: %+v %v", got, err)
	}
	other := Fingerprint("credentials", Identity{Tenancy: TenancyShared, HPKE: st.Identity.HPKE, Response: make([]byte, 32)})
	for name, f := range map[string]func() ([]byte, []byte, string, string){
		"another profile":     func() ([]byte, []byte, string, string) { return raw, sig, "people", fp },
		"another fingerprint": func() ([]byte, []byte, string, string) { return raw, sig, "credentials", other },
		"a forged signature": func() ([]byte, []byte, string, string) {
			_, foreign, _ := ed25519.GenerateKey(nil)
			return raw, ed25519.Sign(foreign, raw), "credentials", fp
		},
		"a byte more": func() ([]byte, []byte, string, string) {
			b := append(bytes.Clone(raw), 0)
			return b, ed25519.Sign(respPriv, b), "credentials", fp
		},
	} {
		r, s, d, p := f()
		if _, err := VerifyKeyStatement(Release(), r, s, d, p); !errors.Is(err, ErrKeyStatement) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Every single byte flipped: refused (a parse failure, a non-canonical form or a signature that fails).
	for i := range raw {
		b := bytes.Clone(raw)
		b[i] ^= 0x01
		if _, err := VerifyKeyStatement(Release(), b, sig, "credentials", fp); err == nil {
			t.Fatalf("byte %d flipped: accepted", i)
		}
	}
	// No field between the HPKE key and the response algorithm: a statement carrying one (an empty field there) is
	// refused, even validly signed.
	at := bytes.Index(raw, st.Identity.HPKE) + len(st.Identity.HPKE)
	extra := append(append(bytes.Clone(raw[:at]), 0, 0, 0, 0), raw[at:]...)
	if _, err := VerifyKeyStatement(Release(), extra, ed25519.Sign(respPriv, extra), "credentials", fp); !errors.Is(err, ErrKeyStatement) {
		t.Fatalf("a statement with a field after the HPKE key: %v", err)
	}
	// Keys out of canonical order are not a statement (one statement, one encoding).
	swapped := specSwapKeys(t, bytes.Clone(raw), st)
	if _, err := ParseKeyStatement(Release(), swapped); !errors.Is(err, ErrKeyStatement) {
		t.Fatalf("a statement with its keys out of order: %v", err)
	}
	// A key of an algorithm this package does not implement (the extension point): parsed, kept, unusable.
	pub := specSeed("ml-dsa", 1952)
	odd := *st
	odd.SigningKeys = append(append([]SigningKey(nil), st.SigningKeys...),
		SigningKey{KeyID: SigningKeyIDOf(5, pub), State: SigningKeyVerifyOnly, PublicKey: pub, Algorithm: 5})
	SortSigningKeys(odd.SigningKeys)
	oraw, err := MarshalKeyStatement(Release(), &odd)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseKeyStatement(Release(), oraw)
	if err != nil {
		t.Fatalf("a statement with a key of another algorithm: %v", err)
	}
	for _, k := range p.SigningKeys {
		if k.Algorithm == 5 && (k.Usable() || k.State != SigningKeyVerifyOnly) {
			t.Fatalf("the key of another algorithm: %+v", k)
		}
	}
	// The same key in a state that is none of the three (its number 2 written 9), validly signed: refused.
	at = bytes.Index(oraw, specJoin(string(SigningKeyIDOf(5, pub)), string(specU32(SigningKeyVerifyOnly.Code()))))
	if at < 0 {
		t.Fatal("the key's encoding is not in the statement")
	}
	unknown := bytes.Clone(oraw)
	unknown[at+4+SigningKeyIDLen+4+3] = 9
	if _, err := VerifyKeyStatement(Release(), unknown, ed25519.Sign(respPriv, unknown), "credentials", fp); !errors.Is(err, ErrKeyStatement) {
		t.Fatalf("a statement with a key in an unknown state: %v", err)
	}
}

// specSwapKeys is raw with its two signing keys' encodings swapped.
func specSwapKeys(t *testing.T, raw []byte, st *KeyStatement) []byte {
	t.Helper()
	enc := func(k SigningKey) []byte {
		return specJoin(string(k.KeyID), string(specU32(k.State.Code())), string(specU32(1)), string(k.PublicKey))
	}
	a, b := enc(st.SigningKeys[0]), enc(st.SigningKeys[1])
	i := bytes.Index(raw, a)
	if i < 0 || !bytes.Equal(raw[i+len(a):i+len(a)+len(b)], b) {
		t.Fatal("the keys' encoding is not the specification's")
	}
	out := bytes.Clone(raw[:i])
	out = append(append(out, b...), a...)
	return append(out, raw[i+len(a)+len(b):]...)
}

func TestBatchDigests(t *testing.T) {
	a, b := EncryptDigest([]byte("1"), nil, "", nil), EncryptDigest([]byte("2"), nil, "", nil)
	if BatchDigest([][32]byte{a, b}) == BatchDigest([][32]byte{b, a}) || BatchDigest([][32]byte{a}) == BatchDigest([][32]byte{a, a}) ||
		BatchDigest([][32]byte{a}) == a {
		t.Fatal("a batch digest does not bind its items' order and count")
	}
	if ItemResultDigest([]byte("x")) == ItemErrorDigest(3, "", "x") || ItemResultDigest([]byte("x")) == Digest([]byte("x")) {
		t.Fatal("a result digest is another digest")
	}
	for _, op := range []Operation{OpEncryptBatch, OpDecryptBatch, OpReEncryptBatch, OpRewrapTenantKeyBatch} {
		if !op.Batch() || op.Grantable() || op.Grant() == "" || op.Grant() == op {
			t.Errorf("%s: batch %v grantable %v grant %q", op, op.Batch(), op.Grantable(), op.Grant())
		}
	}
	if OpRewrapTenantKeyBatch.Grant() != OpProvision || OpReEncryptBatch.Grant() != OpReEncrypt {
		t.Fatal("a batch is not authorized as its single operation")
	}
}

func TestSegmentedFormat(t *testing.T) {
	id := specSeed("object", ObjectIDLen)
	seen := map[string]bool{}
	for _, c := range []struct {
		i     uint32
		final bool
		aad   string
	}{{0, false, ""}, {1, false, ""}, {1, true, ""}, {0, true, ""}, {0, false, "x"}} {
		s := string(SegmentAssociatedData(id, c.i, c.final, []byte(c.aad)))
		if seen[s] {
			t.Fatalf("two segments share associated data: %+v", c)
		}
		seen[s] = true
	}
	if !bytes.Equal(SegmentAssociatedData(id, 3, true, []byte("z")),
		specJoin(segmentLabel, string(id), string(specU32(3)), "\x01", "z")) {
		t.Fatal("a segment's associated data is not the specification's")
	}
	h := SegmentedHeader{ObjectID: id, SegmentSize: MinSegmentSize, Count: 2}
	b, err := MarshalSegmented(Release(), h, [][]byte{[]byte("one"), []byte("two")})
	if err != nil {
		t.Fatal(err)
	}
	got, segs, err := ParseSegmented(Release(), b)
	if err != nil || !bytes.Equal(got.ObjectID, id) || got.Count != 2 || string(segs[1]) != "two" {
		t.Fatalf("round trip: %+v %q %v", got, segs, err)
	}
	for name, bad := range map[string][]byte{
		"a byte more": append(bytes.Clone(b), 0), "a byte less": b[:len(b)-1], "nothing": nil,
		"count 0":    append(bytes.Clone(b[:SegmentedHeaderLen-4]), 0, 0, 0, 0),
		"count huge": append(append(bytes.Clone(b[:SegmentedHeaderLen-4]), 0, 0, 0xff, 0xff), b[SegmentedHeaderLen:]...),
	} {
		if _, _, err := ParseSegmented(Release(), bad); !errors.Is(err, ErrSegmented) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := MarshalSegmented(Release(), h, [][]byte{[]byte("one")}); err == nil {
		t.Fatal("a count that is not the segments' was written")
	}
}

// specJoin is lp(each field), the strings as bytes.
func specJoin(fields ...string) []byte {
	var b []byte
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

func specU32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// specDigest is Digest's specification: the SHA-256 of lp("cipheron/v1|digest") and each field, length-prefixed.
func specDigest(fields ...[]byte) [sha256.Size]byte {
	b := specJoin("cipheron/v1|digest")
	for _, f := range fields {
		b = append(b, specJoin(string(f))...)
	}
	return sha256.Sum256(b)
}

func specSum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
