package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

// TestOperations: the grantable operations are the eight the plan names (export and import: the cross-profile
// ReEncrypt's grants, D-A; retenant: the grant of a cross-profile move that changes the tenant); RewrapTenantKey's
// transcript label is authorized as provision and is not itself grantable; nothing else is.
func TestOperations(t *testing.T) {
	want := []Operation{"encrypt", "decrypt", "sign", "reencrypt", "provision", "export", "import", "retenant"}
	got := GrantableOperations()
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i, op := range want {
		if got[i] != op || !op.Grantable() || op.Grant() != op {
			t.Fatalf("%q", op)
		}
	}
	if OpRewrapTenantKey.Grantable() || OpRewrapTenantKey.Grant() != OpProvision || OpRewrapTenantKey == OpProvision {
		t.Fatal("rewrap-tenant-key")
	}
	for _, op := range []Operation{"", "tenant-public-key", "Encrypt", "provision ", "verify", "Retenant", "re-tenant"} {
		if op.Grantable() || op.Grant() != "" {
			t.Fatalf("%q is granted", op)
		}
	}
}

// TestEveryTranscriptIsDistinct: for one profile, nonce and requester, the request and response transcripts of
// every operation — with the digests the operation really uses, including the pairs that share a digest form
// (encrypt and sign; provision and rewrap-tenant-key; the encrypt and reencrypt responses) — the signing-key list
// transcript and the tenant-bound message are pairwise different, and a signature over one verifies over no
// other. The labels keep them apart even where the fields agree.
func TestEveryTranscriptIsDistinct(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	n := bytes.Repeat([]byte{7}, NonceLen)
	reqSig := bytes.Repeat([]byte{1}, SignatureLen)
	enc, sealed, ct, blob, blob2 := []byte("enc"), []byte("sealed"), []byte("ciphertext"), []byte("blob"), []byte("blob2")
	const ts = 1700000000000

	type pair struct {
		op            Operation
		req, response [32]byte
	}
	pairs := []pair{
		{OpEncrypt, EncryptDigest(enc, sealed, "t_1", blob), CiphertextResponseDigest(ct)},
		{OpSign, SignDigest(enc, sealed, "t_1", blob), SignResponseDigest(bytes.Repeat([]byte{2}, SignatureLen), blob)},
		{OpDecrypt, DecryptDigest(enc, ct, "t_1", blob), Digest(enc, enc, sealed)},
		{OpReEncrypt, ReEncryptDigest(ct, "t_1", blob, blob2), CiphertextResponseDigest(ct)},
		{OpProvision, ProvisionDigest("t_1"), TenantKeyResponseDigest(blob, pub, "sha256:x")},
		{OpRewrapTenantKey, RewrapTenantKeyDigest("t_1", nil), TenantKeyResponseDigest(blob, pub, "sha256:x")},
	}
	if EncryptDigest(enc, sealed, "t_1", blob) != SignDigest(enc, sealed, "t_1", blob) ||
		ProvisionDigest("t_1") != RewrapTenantKeyDigest("t_1", nil) {
		t.Fatal("the shared digest forms changed: this test no longer covers them")
	}
	all := map[string][]byte{
		"signing keys": keysTx("docs", TenancyShared, testContext, n, nil),
		"tenant sig":   TenantSignedMessage("docs", "t_1", ct),
	}
	for _, p := range pairs {
		all["request "+string(p.op)] = RequestTranscript(Release(), "docs", p.op, ts, n, p.req)
		all["response "+string(p.op)] = ResponseTranscript(Release(), "docs", testContext, p.op, n, reqSig, p.req, p.response)
	}
	sigs := map[string][]byte{}
	for name, tr := range all {
		sigs[name] = ed25519.Sign(priv, tr)
	}
	for a, ta := range all {
		for b, tb := range all {
			if a == b {
				continue
			}
			if bytes.Equal(ta, tb) {
				t.Fatalf("%s and %s are one transcript", a, b)
			}
			if !errors.Is(verify(pub, tb, sigs[a]), ErrAuth) {
				t.Fatalf("a signature over %s verifies over %s", a, b)
			}
		}
	}
}

// TestNewDigestsBindEveryField: each field of the new request and response digests changes them, and moving
// bytes between adjacent fields does too.
func TestNewDigestsBindEveryField(t *testing.T) {
	ct, b1, b2 := []byte("ciphertext"), []byte("blob1"), []byte("blob2")
	base := ReEncryptDigest(ct, "t_1", b1, b2)
	for name, d := range map[string][32]byte{
		"ciphertext":        ReEncryptDigest([]byte("ciphertexT"), "t_1", b1, b2),
		"tenant":            ReEncryptDigest(ct, "t_2", b1, b2),
		"tenant key":        ReEncryptDigest(ct, "t_1", b2, b2),
		"to tenant key":     ReEncryptDigest(ct, "t_1", b1, b1),
		"keys swapped":      ReEncryptDigest(ct, "t_1", b2, b1),
		"no to tenant key":  ReEncryptDigest(ct, "t_1", b1, nil),
		"split":             ReEncryptDigest(ct, "t_1b", []byte("lob1"), b2),
		"the decrypt form":  DecryptDigest(nil, ct, "t_1", b1),
		"shared, all empty": ReEncryptDigest(ct, "", nil, nil),
	} {
		if d == base {
			t.Errorf("reencrypt %s: the same digest", name)
		}
	}
	sig, kid := bytes.Repeat([]byte{3}, SignatureLen), bytes.Repeat([]byte{4}, SigningKeyIDLen)
	sbase := SignResponseDigest(sig, kid)
	for name, d := range map[string][32]byte{
		"signature":   SignResponseDigest(append(bytes.Clone(sig[:63]), 0), kid),
		"key id":      SignResponseDigest(sig, append(bytes.Clone(kid[:15]), 0)),
		"no key id":   SignResponseDigest(sig, nil),
		"split":       SignResponseDigest(sig[:63], append([]byte{3}, kid...)),
		"ciphertext":  CiphertextResponseDigest(sig),
		"the old one": Digest(sig),
	} {
		if d == sbase {
			t.Errorf("sign response %s: the same digest", name)
		}
	}
	if RewrapTenantKeyDigest("t_1", b1) == RewrapTenantKeyDigest("t_2", b1) ||
		RewrapTenantKeyDigest("t_1", b1) == RewrapTenantKeyDigest("t_1", b2) {
		t.Fatal("the rewrap digest does not bind its fields")
	}
}

// TestTranscriptLayouts holds every transcript this protocol signs or seals to its written layout, rebuilt here
// field by field from the documentation (auth.go, keys.go, transport.go), not from the code: the transcript version is
// the constant 1, a 4-byte field at a fixed position — right after the label of the request, response and
// signing-key transcripts, right after the context string of a request payload's seal info and of a Decrypt answer's.
// (The signing-key transcript's own field-by-field layout is TestSigningKeysTranscript's; the frozen set's
// transcripts are held to these layouts by TestTheFrozenTranscripts.)
func TestTranscriptLayouts(t *testing.T) {
	if TranscriptVersion != 1 {
		t.Fatalf("the transcript version is %d: this protocol's one version is numbered 1", TranscriptVersion)
	}
	n := bytes.Repeat([]byte{7}, NonceLen)
	reqSig := bytes.Repeat([]byte{1}, SignatureLen)
	reqDigest, respDigest := Digest([]byte("request")), Digest([]byte("response"))
	const ts = 1700000000123
	tsField := []byte{0, 0, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x7b} // 1700000000123, 8 bytes big-endian
	requester := sha256.Sum256(reqSig)
	for _, op := range []Operation{OpEncrypt, OpDecrypt, OpSign, OpReEncrypt, OpProvision, OpRewrapTenantKey,
		OpEncryptBatch, OpDecryptBatch, OpReEncryptBatch, OpRewrapTenantKeyBatch} {
		// lp("cipheron/v1|signed_request") lp(version: 4) lp(profile) lp(operation) lp(timestamp: 8) lp(nonce) lp(digest)
		want := lpJoin([]byte("cipheron/v1|signed_request"), []byte{0, 0, 0, 1}, []byte("docs"), []byte(op), tsField, n,
			reqDigest[:])
		if got := RequestTranscript(Release(), "docs", op, ts, n, reqDigest); !bytes.Equal(got, want) {
			t.Errorf("request %s: %x, want %x", op, got, want)
		}
		// lp("cipheron/v1|signed_response") lp(version: 4) lp(profile) lp(context digest) lp(operation) lp(request nonce)
		// lp(requester: SHA-256 of the request's signature, or empty) lp(request digest) lp(response digest)
		want = lpJoin([]byte("cipheron/v1|signed_response"), []byte{0, 0, 0, 1}, []byte("docs"), []byte(testContext),
			[]byte(op), n, requester[:], reqDigest[:], respDigest[:])
		if got := ResponseTranscript(Release(), "docs", testContext, op, n, reqSig, reqDigest, respDigest); !bytes.Equal(got, want) {
			t.Errorf("response %s: %x, want %x", op, got, want)
		}
		want = lpJoin([]byte("cipheron/v1|signed_response"), []byte{0, 0, 0, 1}, []byte("docs"), []byte(testContext),
			[]byte(op), n, nil, reqDigest[:], respDigest[:])
		if got := ResponseTranscript(Release(), "docs", testContext, op, n, nil, reqDigest, respDigest); !bytes.Equal(got, want) {
			t.Errorf("response %s without a request signature: %x, want %x", op, got, want)
		}
	}
	// "cipheron/v1|request|<profile>|<op>[|<tenant>]" lp(version: 4) lp(requester: SHA-256 of the request key, or empty)
	key := ed25519.PublicKey(bytes.Repeat([]byte{9}, ed25519.PublicKeySize))
	keyHash := sha256.Sum256(key)
	for _, c := range []struct {
		op           Operation
		tenant       string
		key          ed25519.PublicKey
		context      string
		requesterLen int
	}{
		{OpEncrypt, "", key, "cipheron/v1|request|docs|encrypt", 32},
		{OpSign, "t_1", key, "cipheron/v1|request|docs|sign|t_1", 32},
		{OpEncrypt, "t_1", nil, "cipheron/v1|request|docs|encrypt|t_1", 0},
	} {
		requesterField := keyHash[:c.requesterLen]
		want := append([]byte(c.context), lpJoin([]byte{0, 0, 0, 1}, requesterField)...)
		if got := RequestSealInfo(Release(), "docs", c.op, c.tenant, c.key); !bytes.Equal(got, want) {
			t.Errorf("seal info %s %q: %x, want %x", c.op, c.tenant, got, want)
		}
		if got := RequestInfoTenant("docs", c.op, c.tenant); !bytes.Equal(got, []byte(c.context)) {
			t.Errorf("seal info context %s %q: %q", c.op, c.tenant, got)
		}
	}
	// A Decrypt answer's: "cipheron/v1|response|<profile>|<op>[|<tenant>]" lp(version: 4)
	for _, c := range []struct {
		tenant, context string
	}{
		{"", "cipheron/v1|response|docs|decrypt"},
		{"t_1", "cipheron/v1|response|docs|decrypt|t_1"},
	} {
		want := append([]byte(c.context), lpJoin([]byte{0, 0, 0, 1})...)
		if got := ResponseInfoTenant(Release(), "docs", OpDecrypt, c.tenant); !bytes.Equal(got, want) {
			t.Errorf("response seal info %q: %x, want %x", c.tenant, got, want)
		}
	}
	if !bytes.Equal(ResponseInfo(Release(), "docs", OpDecrypt), ResponseInfoTenant(Release(), "docs", OpDecrypt, "")) {
		t.Error("a shared profile's response seal info is not the tenant form with no tenant")
	}
}

// TestTheResponseSealInfoBindsTheVersion: a Decrypt answer sealed under this protocol's info opens under that info
// only — not the bare context string, not the same context under another transcript version, not another tenant's,
// operation's or direction's.
func TestTheResponseSealInfoBindsTheVersion(t *testing.T) {
	client, err := NewOneTimeKey()
	if err != nil {
		t.Fatal(err)
	}
	info := ResponseInfoTenant(Release(), "docs", OpDecrypt, "t_1")
	enc, sealed, err := Seal(client.PublicKey(), info, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(client, info, enc, sealed); err != nil || string(pt) != "p" {
		t.Fatalf("its own info: %q %v", pt, err)
	}
	context := []byte("cipheron/v1|response|docs|decrypt|t_1")
	for name, other := range map[string][]byte{
		"the bare context string": context,
		"another version":         append(bytes.Clone(context), lpJoin(u32(TranscriptVersion+1))...),
		"version 0":               append(bytes.Clone(context), lpJoin(u32(0))...),
		"another tenant":          ResponseInfoTenant(Release(), "docs", OpDecrypt, "t_2"),
		"no tenant":               ResponseInfoTenant(Release(), "docs", OpDecrypt, ""),
		"another operation":       ResponseInfoTenant(Release(), "docs", OpSign, "t_1"),
		"the request direction":   RequestSealInfo(Release(), "docs", OpDecrypt, "t_1", nil),
	} {
		if _, err := Open(client, other, enc, sealed); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
}

// TestRequestSealInfoBindsTheRequester (gap review S4): a payload one requester sealed opens only under that
// requester's seal info — not another request key's, not a requester without a key, not the bare context string, not
// the same info under another transcript version (or none). An info that named only the profile, operation and tenant
// would let a second caller send another's sealed payload under its own key.
func TestRequestSealInfoBindsTheRequester(t *testing.T) {
	server, err := KEM().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := ed25519.GenerateKey(nil)
	b, _, _ := ed25519.GenerateKey(nil)
	infoA := RequestSealInfo(Release(), "docs", OpEncrypt, "t_1", a)
	enc, ct, err := Seal(server.PublicKey(), infoA, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(server, infoA, enc, ct); err != nil || string(pt) != "p" {
		t.Fatalf("the requester's own info: %q %v", pt, err)
	}
	context := RequestInfoTenant("docs", OpEncrypt, "t_1")
	for name, info := range map[string][]byte{
		"another requester":         RequestSealInfo(Release(), "docs", OpEncrypt, "t_1", b),
		"a requester without a key": RequestSealInfo(Release(), "docs", OpEncrypt, "t_1", nil),
		"the bare context string":   context,
		"another version":           append(bytes.Clone(context), lpJoin(u32(TranscriptVersion+1), RequesterKeyHash(a))...),
		"no version":                append(bytes.Clone(context), lpJoin(RequesterKeyHash(a))...),
	} {
		if _, err := Open(server, info, enc, ct); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	if !bytes.Equal(infoA, append(bytes.Clone(context), lpJoin(u32(1), RequesterKeyHash(a))...)) {
		t.Fatal("the seal info is not the context string, lp(version 1) and lp(requester)")
	}
	if got := RequesterKeyHash(nil); len(got) != 0 {
		t.Fatalf("no key: %x", got)
	}
}
