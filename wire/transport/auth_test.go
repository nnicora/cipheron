package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func nonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, NonceLen)
	if _, err := rand.Read(n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRequestTranscriptsDiffer: a signature over one request verifies for that request only — any other profile,
// operation, timestamp, nonce or payload is a different transcript, and a response transcript is never a
// request transcript.
func TestRequestTranscriptsDiffer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := nonce(t)
	d := Digest([]byte("enc"), []byte("sealed"))
	tr := RequestTranscript(Release(), "cards", OpEncrypt, 1700000000000, n, d)
	sig := ed25519.Sign(priv, tr)
	if err := VerifyRequest(pub, tr, sig); err != nil {
		t.Fatal(err)
	}
	ts := binary.BigEndian.AppendUint64(nil, 1700000000000)
	others := map[string][]byte{
		"profile":   RequestTranscript(Release(), "cards2", OpEncrypt, 1700000000000, n, d),
		"operation": RequestTranscript(Release(), "cards", OpSign, 1700000000000, n, d),
		"timestamp": RequestTranscript(Release(), "cards", OpEncrypt, 1700000000001, n, d),
		"nonce":     RequestTranscript(Release(), "cards", OpEncrypt, 1700000000000, nonce(t), d),
		"payload":   RequestTranscript(Release(), "cards", OpEncrypt, 1700000000000, n, Digest([]byte("enc"), []byte("sealeD"))),
		// The same bytes split differently between the fields is another digest: the fields are length-prefixed.
		"field split": RequestTranscript(Release(), "cards", OpEncrypt, 1700000000000, n, Digest([]byte("encs"), []byte("ealed"))),
		"response":    ResponseTranscript(Release(), "cards", testContext, OpEncrypt, n, sig, d, d),
		// The version is a field under the label: the layout without it, or with another value, is another transcript.
		"no version": transcript(nil).addString(requestLabel).addString("cards").addString(string(OpEncrypt)).
			add(ts).add(n).add(d[:]),
		"another version": transcript(nil).addString(requestLabel).addUint32(TranscriptVersion + 1).addString("cards").
			addString(string(OpEncrypt)).add(ts).add(n).add(d[:]),
		"version 0": transcript(nil).addString(requestLabel).addUint32(0).addString("cards").addString(string(OpEncrypt)).
			add(ts).add(n).add(d[:]),
	}
	for name, other := range others {
		if bytes.Equal(other, tr) {
			t.Fatalf("%s: the same transcript", name)
		}
		if !errors.Is(VerifyRequest(pub, other, sig), ErrAuth) {
			t.Fatalf("%s: the signature verifies over another transcript", name)
		}
	}
	if !errors.Is(VerifyRequest(pub, tr, sig[:63]), ErrAuth) || !errors.Is(VerifyRequest(pub[:31], tr, sig), ErrAuth) {
		t.Fatal("a short signature or key verified")
	}
}

// TestResponseTranscriptBindsTheRequest: a response signature verifies for the request it answers only — the
// same nonce and answer with another request digest (another payload, as a party in the path substituting its
// own request would send), another requester (the same request signed by another key, or carrying no
// signature), another profile, operation or nonce, another transcript version (or none) — and for the key context of
// the replica that made it only: under another key-context digest (a replica on a drifted or stale context), or with
// none, it does not verify.
func TestResponseTranscriptBindsTheRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := nonce(t)
	req := Digest([]byte("recipient"), []byte("victim's ciphertext"))
	resp := Digest([]byte("recipient"), []byte("enc"), []byte("sealed"))
	victimSig := bytes.Repeat([]byte{0x5a}, SignatureLen)
	tr := ResponseTranscript(Release(), "cards", testContext, OpDecrypt, n, victimSig, req, resp)
	sig := ed25519.Sign(priv, tr)
	if err := VerifyResponse(pub, tr, sig); err != nil {
		t.Fatal(err)
	}
	noVersion := transcript(nil).addString(responseLabel).addString("cards").addString(testContext).
		addString(string(OpDecrypt)).add(n).add(Requester(victimSig)).add(req[:]).add(resp[:])
	anotherVersion := transcript(nil).addString(responseLabel).addUint32(TranscriptVersion + 1).addString("cards").
		addString(testContext).addString(string(OpDecrypt)).add(n).add(Requester(victimSig)).add(req[:]).add(resp[:])
	noContext := transcript(nil).addString(responseLabel).addUint32(TranscriptVersion).addString("cards").
		addString(string(OpDecrypt)).add(n).add(Requester(victimSig)).add(req[:]).add(resp[:])
	otherContext := "sha256:" + strings.Repeat("e", 64)
	insiderSig := bytes.Repeat([]byte{0xa5}, SignatureLen)
	others := map[string][]byte{
		"request digest":  ResponseTranscript(Release(), "cards", testContext, OpDecrypt, n, victimSig, Digest([]byte("recipient"), []byte("insider's ciphertext")), resp),
		"response digest": ResponseTranscript(Release(), "cards", testContext, OpDecrypt, n, victimSig, req, Digest([]byte("other"))),
		"swapped digests": ResponseTranscript(Release(), "cards", testContext, OpDecrypt, n, victimSig, resp, req),
		"profile":         ResponseTranscript(Release(), "cards2", testContext, OpDecrypt, n, victimSig, req, resp),
		"context digest":  ResponseTranscript(Release(), "cards", otherContext, OpDecrypt, n, victimSig, req, resp),
		"empty context":   ResponseTranscript(Release(), "cards", "", OpDecrypt, n, victimSig, req, resp),
		"no context":      noContext,
		"operation":       ResponseTranscript(Release(), "cards", testContext, OpEncrypt, n, victimSig, req, resp),
		"nonce":           ResponseTranscript(Release(), "cards", testContext, OpDecrypt, nonce(t), victimSig, req, resp),
		"requester":       ResponseTranscript(Release(), "cards", testContext, OpDecrypt, n, insiderSig, req, resp),
		"no requester":    ResponseTranscript(Release(), "cards", testContext, OpDecrypt, n, nil, req, resp),
		"no version":      noVersion,
		"another version": anotherVersion,
		"the request transcript's label": transcript(nil).addString(requestLabel).addUint32(TranscriptVersion).
			addString("cards").addString(testContext).addString(string(OpDecrypt)).add(n).add(Requester(victimSig)).
			add(req[:]).add(resp[:]),
	}
	for name, other := range others {
		if bytes.Equal(other, tr) {
			t.Fatalf("%s: the same transcript", name)
		}
		if !errors.Is(VerifyResponse(pub, other, sig), ErrAuth) {
			t.Fatalf("%s: the signature verifies over another transcript", name)
		}
	}
	// A signature over the layout under another version, or without one, does not verify over this transcript.
	if !errors.Is(VerifyResponse(pub, tr, ed25519.Sign(priv, noVersion)), ErrAuth) ||
		!errors.Is(VerifyResponse(pub, tr, ed25519.Sign(priv, anotherVersion)), ErrAuth) {
		t.Fatal("a response signature of another version verifies as this one")
	}
}

// TestRequester: the SHA-256 of a signature, and EMPTY — not 32 zero bytes — for none, so a request that carried
// no signature never shares a requester with one that did (not even one whose signature hashes to zeros).
func TestRequester(t *testing.T) {
	sig := bytes.Repeat([]byte{1}, SignatureLen)
	want := sha256.Sum256(sig)
	if !bytes.Equal(Requester(sig), want[:]) || len(Requester(nil)) != 0 || len(Requester([]byte{})) != 0 {
		t.Fatal("Requester")
	}
	d := Digest()
	if bytes.Equal(ResponseTranscript(Release(), "d", testContext, OpEncrypt, nil, nil, d, d),
		transcript(nil).addString(responseLabel).addUint32(TranscriptVersion).addString("d").addString(testContext).
			addString(string(OpEncrypt)).add(nil).add(make([]byte, sha256.Size)).add(d[:]).add(d[:])) {
		t.Fatal("no signature encodes as 32 zero bytes")
	}
}

// TestFingerprint: deterministic, written as ValidFingerprint reads it, and different for another profile, another
// tenancy or any other key.
func TestFingerprint(t *testing.T) {
	hp, err := NewOneTimeKey()
	if err != nil {
		t.Fatal(err)
	}
	hpub := hp.PublicKey().Bytes()
	hp2, err := NewOneTimeKey()
	if err != nil {
		t.Fatal(err)
	}
	s1, _, _ := ed25519.GenerateKey(rand.Reader)
	s2, _, _ := ed25519.GenerateKey(rand.Reader)
	k := Identity{Tenancy: TenancyShared, HPKE: hpub, Response: s2}
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint("cards", k)
	if !ValidFingerprint(fp) || fp != Fingerprint("cards", k) || !MatchesFingerprint("cards", k, fp) {
		t.Fatalf("fingerprint %q", fp)
	}
	otherResponse := Identity{Tenancy: TenancyShared, HPKE: hpub, Response: s1}
	otherHPKE := Identity{Tenancy: TenancyShared, HPKE: hp2.PublicKey().Bytes(), Response: s2}
	if MatchesFingerprint("cards", otherResponse, fp) || MatchesFingerprint("cards", otherHPKE, fp) ||
		MatchesFingerprint("other", k, fp) {
		t.Fatal("another identity or profile matches the fingerprint")
	}
	if !k.Equal(Identity{Tenancy: TenancyShared, HPKE: bytes.Clone(hpub), Response: bytes.Clone(s2)}) ||
		k.Equal(otherResponse) || k.Equal(otherHPKE) {
		t.Fatal("Equal")
	}
	// The tenancy is in the fingerprint and in Equal: the same keys of another tenancy are another identity.
	for _, ten := range []Tenancy{TenancyPerTenantWrapped, TenancyPerTenantDerived} {
		other := k
		other.Tenancy = ten
		if err := other.Validate(); err != nil {
			t.Fatalf("%s: %v", ten, err)
		}
		if MatchesFingerprint("cards", other, fp) || k.Equal(other) {
			t.Fatalf("%s: the tenancy is not bound", ten)
		}
	}
	if Fingerprint("cards", Identity{Tenancy: TenancyPerTenantWrapped, HPKE: hpub, Response: s2}) ==
		Fingerprint("cards", Identity{Tenancy: TenancyPerTenantDerived, HPKE: hpub, Response: s2}) {
		t.Fatal("wrapped and derived share a fingerprint")
	}
	// An unknown tenancy is refused; lengths are checked.
	for name, bad := range map[string]Identity{
		"no tenancy":      {HPKE: hpub, Response: s2},
		"tenancy both":    {Tenancy: "both", HPKE: hpub, Response: s2},
		"short HPKE":      {Tenancy: TenancyShared, HPKE: hpub[:64], Response: s2},
		"short response":  {Tenancy: TenancyShared, HPKE: hpub, Response: s2[:31]},
		"no response key": {Tenancy: TenancyShared, HPKE: hpub},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s: validated", name)
		}
	}
	for _, bad := range []string{"", "sha256:", strings.ToUpper(fp), fp[:len(fp)-1], "sha512:" + fp[7:], fp + "00"} {
		if ValidFingerprint(bad) {
			t.Fatalf("%q is valid", bad)
		}
	}
}

// TestFingerprintFormulaIsTheSpecifiedOne: the formula, written out field by field — the label, the profile, the
// tenancy, the HPKE key and the response key, each length-prefixed — is the one Fingerprint computes.
func TestFingerprintFormulaIsTheSpecifiedOne(t *testing.T) {
	hp, _ := NewOneTimeKey()
	s2, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, k := range []Identity{
		{Tenancy: TenancyShared, HPKE: hp.PublicKey().Bytes(), Response: s2},
		{Tenancy: TenancyPerTenantWrapped, HPKE: hp.PublicKey().Bytes(), Response: s2},
	} {
		var b []byte
		for _, f := range [][]byte{[]byte("cipheron/v1|fingerprint"), []byte("cards"), []byte(k.Tenancy), k.HPKE, k.Response} {
			b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
			b = append(b, f...)
		}
		sum := sha256.Sum256(b)
		if Fingerprint("cards", k) != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: not the specified formula", k.Tenancy)
		}
	}
}

// TestRequestKeyPEM: the pair keygen writes reads back; anything else — another key type, two blocks, trailing
// data, headers — is refused.
func TestRequestKeyPEM(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, pubPEM, err := MarshalRequestKeys(priv)
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, err := ParseRequestPrivateKey(privPEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private: %v", err)
	}
	gotPub, err := ParseRequestPublicKey(pubPEM)
	if err != nil || !gotPub.Equal(priv.Public()) {
		t.Fatalf("public: %v", err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})
	headered := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	for name, bad := range map[string][]byte{
		"an ECDSA key":  ecPEM,
		"two blocks":    append(append([]byte{}, pubPEM...), pubPEM...),
		"trailing data": append(append([]byte{}, pubPEM...), "x"...),
		"a private key": privPEM,
		"a header":      headered,
		"not PEM":       []byte("hello"),
	} {
		if _, err := ParseRequestPublicKey(bad); err == nil {
			t.Errorf("public key from %s accepted", name)
		}
	}
	if _, err := ParseRequestPrivateKey(pubPEM); err == nil {
		t.Error("a public key read as a private key")
	}
}

// pemOfRaw is raw (32 bytes) as a PEM PKIX Ed25519 public key: what a request key file holds, whatever the bytes.
func pemOfRaw(t *testing.T, raw []byte) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// TestDegenerateRequestKeysRefused (security review AZ-3): a request key under which ed25519.Verify accepts forgeries
// — each of the eight small-order points, among them the identity (R = B, S = 1 verifies over every message) and the
// all-zero key — and a non-canonical encoding (y ≥ p, the sign bit on x = 0) is refused by ParseRequestPublicKey;
// every key ed25519.GenerateKey makes passes.
func TestDegenerateRequestKeysRefused(t *testing.T) {
	hexKey := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("vector %s: %v", s, err)
		}
		return b
	}
	identity := hexKey("0100000000000000000000000000000000000000000000000000000000000000")
	smallOrder := []struct {
		name string
		raw  []byte
	}{
		{"the identity (order 1)", identity},
		{"order 2", hexKey("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")},
		{"the all-zero key (order 4)", hexKey("0000000000000000000000000000000000000000000000000000000000000000")},
		{"order 4, sign bit set", hexKey("0000000000000000000000000000000000000000000000000000000000000080")},
		{"order 8 (a)", hexKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")},
		{"order 8 (b)", hexKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")},
		{"order 8 (c)", hexKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")},
		{"order 8 (d)", hexKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")},
	}
	for _, v := range smallOrder {
		// The vector is a small-order point: it decodes, and [8]P is the identity (a typo here would fail loudly).
		p, err := new(edwards25519.Point).SetBytes(v.raw)
		if err != nil || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1 {
			t.Fatalf("%s: not a small-order point (%v)", v.name, err)
		}
		if _, err := ParseRequestPublicKey(pemOfRaw(t, v.raw)); !errors.Is(err, ErrWeakRequestKey) {
			t.Errorf("%s: %v, want ErrWeakRequestKey", v.name, err)
		}
	}
	// The identity's forgery verifies under ed25519.Verify: what the refusal keeps out of a keyring.
	forged := append(edwards25519.NewGeneratorPoint().Bytes(), append([]byte{1}, make([]byte, 31)...)...)
	if !ed25519.Verify(identity, []byte("any message"), forged) {
		t.Fatal("the identity key's forgery does not verify: the vector does not show what it is meant to")
	}

	// Non-canonical encodings: y ≥ p of a point that is otherwise fine (y + p, for a small y that decodes to a point of
	// large order), and x = 0 with the sign bit set (y = 1 with the bit: the identity again, encoded twice).
	var nonCanonical [][]byte
	for y := byte(2); y < 19; y++ {
		enc := make([]byte, 32)
		enc[0] = y
		p, err := new(edwards25519.Point).SetBytes(enc)
		if err != nil || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
			continue
		}
		if err := CheckRequestPublicKey(enc); err != nil {
			t.Fatalf("y = %d: the canonical encoding of a point of large order is refused: %v", y, err)
		}
		// y + p, p = 2^255 - 19: the low byte is y - 19 + 256 with a borrow, the middle bytes 0xff, the top 0x7f.
		big := make([]byte, 32)
		big[0] = y - 19
		for i := 1; i < 31; i++ {
			big[i] = 0xff
		}
		big[31] = 0x7f
		if _, err := new(edwards25519.Point).SetBytes(big); err != nil {
			t.Fatalf("y + p for y = %d does not decode: %v", y, err)
		}
		nonCanonical = append(nonCanonical, big)
		break
	}
	if len(nonCanonical) == 0 {
		t.Fatal("no small y decodes to a point of large order: the test cannot build its y ≥ p vector")
	}
	nonCanonical = append(nonCanonical, hexKey("0100000000000000000000000000000000000000000000000000000000000080"))
	for _, raw := range nonCanonical {
		if _, err := ParseRequestPublicKey(pemOfRaw(t, raw)); !errors.Is(err, ErrWeakRequestKey) {
			t.Errorf("non-canonical %x: %v, want ErrWeakRequestKey", raw, err)
		}
	}

	for range 64 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ParseRequestPublicKey(pemOfRaw(t, pub)); err != nil || !got.Equal(pub) {
			t.Fatalf("a generated key %x is refused: %v", pub, err)
		}
	}
}
