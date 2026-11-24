package transport

// frozen_test.go — spec/frozen is the FROZEN SET: what cipheron writes for fixed inputs under published test
// masters (ILLUSTRATIVE TEST KEYS ONLY), written once by TestWriteTheFrozenSet (the server's keyring, under
// -update-frozen) and committed by the owner. the server's keyring's frozen_test.go opens it as cipheron does;
// here, at the contract, every deterministic value of it is held byte for byte both to the function that computes it
// and to the specification written out below (spec*, and layouts_test.go's) — never to the file alone:
//
//   - every profile's fingerprint, from its keyset's public keys; the published signing keys and their ids; the
//     key-context digest from the serving inputs; the signing-keys transcript and the keys signature under the
//     response key; the key statement;
//   - fingerprint version 2 and a signing-key id of another algorithm (the extension points);
//   - every ciphertext's key id, header and length; every tenant key blob's header, size and fingerprint; the
//     segmented object's header and its segments' associated data; the encrypted JSON fields' encoding;
//   - every signature: under its listed key, a derived tenant's over its signed message only, a wrapped tenant's
//     under its blob's key;
//   - every payload digest, request transcript (signed by the request key), seal info of a request's payload and of
//     a Decrypt answer, and response transcript (signed by the profile's response key).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fzDir is the frozen set's directory.
var fzDir = filepath.Join("..", "..", "spec", "frozen")

// fzHex is bytes written as hex in the manifest.
type fzHex []byte

func (h *fzHex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

type fzCiphertext struct {
	Tenant         string `json:"tenant"`
	Plaintext      string `json:"plaintext"`
	AssociatedData fzHex  `json:"associatedData"`
	Format         byte   `json:"format"`
	Version        string `json:"version"`
	KeyID          fzHex  `json:"keyId"`
	Ciphertext     fzHex  `json:"ciphertext"`
}

type fzSignature struct {
	Tenant    string `json:"tenant"`
	Data      string `json:"data"`
	KeyID     fzHex  `json:"keyId"`
	Signature fzHex  `json:"signature"`
}

// fzManifest is the part of spec/frozen/manifest.json this package reads.
type fzManifest struct {
	Profiles []struct {
		Name       string  `json:"name"`
		Tenancy    Tenancy `json:"tenancy"`
		KeysetFile string  `json:"keysetFile"`
		Serve      struct {
			Versions []string `json:"versions"`
		} `json:"serve"`
		WrappingVersion string `json:"wrappingVersion"`
		Fingerprint     string `json:"fingerprint"`
		ContextDigest   string `json:"contextDigest"`
		SigningKeys     []struct {
			KeyID     fzHex           `json:"keyId"`
			State     SigningKeyState `json:"state"`
			PublicKey fzHex           `json:"publicKey"`
		} `json:"signingKeys"`
		KeysNonce      fzHex `json:"keysNonce"`
		KeysTranscript fzHex `json:"keysTranscript"`
		KeysSignature  fzHex `json:"keysSignature"`
		Statement      struct {
			IssuedAtMS int64 `json:"issuedAtMs"`
			Statement  fzHex `json:"statement"`
			Signature  fzHex `json:"signature"`
		} `json:"statement"`
		Ciphertexts []fzCiphertext `json:"ciphertexts"`
		Signatures  []fzSignature  `json:"signatures"`
		Tenants     []struct {
			Tenant           string         `json:"tenant"`
			Blob             fzHex          `json:"blob"`
			WrappingVersion  string         `json:"wrappingVersion"`
			Created          string         `json:"created"`
			KeyID            fzHex          `json:"keyId"`
			SigningPublicKey fzHex          `json:"signingPublicKey"`
			Fingerprint      string         `json:"fingerprint"`
			RewrappedFrom    fzHex          `json:"rewrappedFrom"`
			Ciphertexts      []fzCiphertext `json:"ciphertexts"`
			Signatures       []fzSignature  `json:"signatures"`
		} `json:"tenants"`
		Objects []struct {
			AssociatedData fzHex  `json:"associatedData"`
			SegmentSize    uint32 `json:"segmentSize"`
			Segments       int    `json:"segments"`
			Version        string `json:"version"`
			Object         fzHex  `json:"object"`
		} `json:"objects"`
		JSON []struct {
			RecordID       string   `json:"recordId"`
			Pointers       []string `json:"pointers"`
			AssociatedData fzHex    `json:"associatedData"`
			Encrypted      string   `json:"encrypted"`
		} `json:"json"`
	} `json:"profiles"`
	Transcripts struct {
		RequestKeySeed   fzHex `json:"requestKeySeed"`
		RequestPublicKey fzHex `json:"requestPublicKey"`
		Requests         []struct {
			Op          Operation `json:"op"`
			Profile     string    `json:"profile"`
			Tenant      string    `json:"tenant"`
			TimestampMS int64     `json:"timestampMs"`
			Nonce       fzHex     `json:"nonce"`
			Fields      []fzHex   `json:"fields"`
			Items       [][]fzHex `json:"items"`
			Digest      fzHex     `json:"digest"`
			Transcript  fzHex     `json:"transcript"`
			Signature   fzHex     `json:"signature"`
			SealInfo    fzHex     `json:"sealInfo"`
		} `json:"requests"`
		Responses []struct {
			Request          int       `json:"request"`
			Signed           bool      `json:"signed"`
			Op               Operation `json:"op"`
			Profile          string    `json:"profile"`
			ContextDigest    string    `json:"contextDigest"`
			Tenant           string    `json:"tenant"`
			RequestNonce     fzHex     `json:"requestNonce"`
			RequestSignature fzHex     `json:"requestSignature"`
			RequestDigest    fzHex     `json:"requestDigest"`
			Fields           []fzHex   `json:"fields"`
			Items            [][]fzHex `json:"items"`
			Digest           fzHex     `json:"digest"`
			Transcript       fzHex     `json:"transcript"`
			Signature        fzHex     `json:"signature"`
			SealInfo         fzHex     `json:"sealInfo"`
		} `json:"responses"`
		TenantSignedMessages []struct {
			Profile string `json:"profile"`
			Tenant  string `json:"tenant"`
			Data    string `json:"data"`
			Message fzHex  `json:"message"`
		} `json:"tenantSignedMessages"`
	} `json:"transcripts"`
	Derivations struct {
		Fingerprints []struct {
			Profile   string  `json:"profile"`
			Tenancy   Tenancy `json:"tenancy"`
			HPKESuite struct {
				KEM, KDF, AEAD uint16
			} `json:"hpkeSuite"`
			HPKEPublicKey     fzHex  `json:"hpkePublicKey"`
			ResponseAlgorithm uint32 `json:"responseAlgorithm"`
			ResponsePublicKey fzHex  `json:"responsePublicKey"`
			Additional        []struct {
				Role  uint32 `json:"role"`
				Suite struct {
					KEM, KDF, AEAD uint16
				} `json:"suite"`
				Algorithm uint32 `json:"algorithm"`
				PublicKey fzHex  `json:"publicKey"`
			} `json:"additional"`
			Version     int    `json:"version"`
			Fingerprint string `json:"fingerprint"`
		} `json:"fingerprints"`
		SigningKeyIDs []struct {
			Algorithm uint32 `json:"algorithm"`
			PublicKey fzHex  `json:"publicKey"`
			KeyID     fzHex  `json:"keyId"`
		} `json:"signingKeyIds"`
		TenantKeys []struct {
			Profile          string `json:"profile"`
			WrapKey          fzHex  `json:"wrapKey"`
			Tenant           string `json:"tenant"`
			Blob             fzHex  `json:"blob"`
			WrappingVersion  string `json:"wrappingVersion"`
			KeyID            fzHex  `json:"keyId"`
			SigningPublicKey fzHex  `json:"signingPublicKey"`
			Fingerprint      string `json:"fingerprint"`
		} `json:"tenantKeys"`
	} `json:"derivations"`
}

// fzKeyset is the public part of a keyset file ([]byte fields are base64 in JSON).
type fzKeyset struct {
	Version           int             `json:"version"`
	Kind              Tenancy         `json:"kind"`
	Profile           string          `json:"profile"`
	HPKEPublicKey     []byte          `json:"hpkePublicKey"`
	ResponsePublicKey []byte          `json:"responsePublicKey"`
	SigningKeys       []fzKeysetKey   `json:"signingKeys"`
	WrappingVersion   string          `json:"wrappingVersion"`
	MasterVersions    []fzKeysetCheck `json:"masterVersions"`
	Fingerprint       string          `json:"fingerprint"`
}

type fzKeysetKey struct {
	KeyID     []byte          `json:"keyId"`
	State     SigningKeyState `json:"state"`
	PublicKey []byte          `json:"publicKey"`
}

type fzKeysetCheck struct {
	ID  string `json:"id"`
	KCV []byte `json:"kcv"`
}

func readFrozen(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fzDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func frozenManifest(t *testing.T) *fzManifest {
	t.Helper()
	var m fzManifest
	readFrozen(t, "manifest.json", &m)
	if len(m.Profiles) != 3 || len(m.Transcripts.Requests) == 0 || len(m.Transcripts.Responses) == 0 {
		t.Fatalf("%d profiles, %d requests, %d responses", len(m.Profiles), len(m.Transcripts.Requests), len(m.Transcripts.Responses))
	}
	return &m
}

func fzBytes[T ~[]byte](fs []T) [][]byte {
	out := make([][]byte, len(fs))
	for i, f := range fs {
		out[i] = f
	}
	return out
}

// specFingerprint is a classical identity's fingerprint (version 1), from auth.go's documentation:
// "sha256:" hex(SHA-256(lp("cipheron/v1|fingerprint") lp(profile) lp(tenancy) lp(HPKE key) lp(response key))).
func specFingerprint(profile string, tenancy Tenancy, hpke, response []byte) string {
	return FingerprintPrefix + hex.EncodeToString(specSum(lpJoin([]byte("cipheron/v1|fingerprint"), []byte(profile),
		[]byte(tenancy), hpke, response)))
}

// specKeyID is an Ed25519 signing key's id: the first 16 bytes of SHA-256(lp("cipheron/v1|signing-key-id") lp(key)).
func specKeyID(pub []byte) []byte {
	return specSum(lpJoin([]byte("cipheron/v1|signing-key-id"), pub))[:SigningKeyIDLen]
}

// specContextDigest is the key-context digest from ContextDigest's documentation: lp(label) lp(profile) lp(tenancy)
// lp(n) n × (lp(id) lp(kcv)) ascending id, lp(keyset fingerprint) lp(k) k × (lp(key id) lp("published" | "revoked"))
// ascending id.
func specContextDigest(c KeyContext) string {
	versions := slices.Clone(c.MasterVersions)
	slices.SortFunc(versions, func(a, b MasterVersionCheck) int { return strings.Compare(a.ID, b.ID) })
	keys := slices.Clone(c.SigningKeys)
	slices.SortFunc(keys, func(a, b SigningKey) int { return bytes.Compare(a.KeyID, b.KeyID) })
	b := lpJoin([]byte("cipheron/v1|context"), []byte(c.Profile), []byte(c.Tenancy), u32(uint32(len(versions))))
	for _, v := range versions {
		b = append(b, lpJoin([]byte(v.ID), v.KCV)...)
	}
	b = append(b, lpJoin([]byte(c.KeysetFingerprint), u32(uint32(len(keys))))...)
	for _, k := range keys {
		state := "published"
		if k.State == SigningKeyRevoked {
			state = "revoked"
		}
		b = append(b, lpJoin(k.KeyID, []byte(state))...)
	}
	return FingerprintPrefix + hex.EncodeToString(specSum(b))
}

// specKeysTranscript is SigningKeysTranscript's documented layout: lp(label) lp(1) lp(profile) lp(tenancy)
// lp(context digest) lp(nonce) lp(k) k × (lp(key id) lp(state number) lp(public key)) ascending id; the state numbers
// active 1, verifyOnly 2, revoked 3.
func specKeysTranscript(profile string, tenancy Tenancy, digest string, nonce []byte, keys []SigningKey) []byte {
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, b SigningKey) int { return bytes.Compare(a.KeyID, b.KeyID) })
	b := lpJoin([]byte("cipheron/v1|signed_keys"), u32(1), []byte(profile), []byte(tenancy), []byte(digest), nonce,
		u32(uint32(len(keys))))
	codes := map[SigningKeyState]uint32{SigningKeyActive: 1, SigningKeyVerifyOnly: 2, SigningKeyRevoked: 3}
	for _, k := range keys {
		b = append(b, lpJoin(k.KeyID, u32(codes[k.State]), k.PublicKey)...)
	}
	return b
}

// specSealContext is a seal info's context string: "cipheron/v1|<direction>|<profile>|<op>[|<tenant>]".
func specSealContext(direction, profile string, op Operation, tenant string) []byte {
	s := "cipheron/v1|" + direction + "|" + profile + "|" + string(op)
	if tenant != "" {
		s += "|" + tenant
	}
	return []byte(s)
}

// TestTheFrozenIdentities: per profile, the fingerprint (from the keyset's public keys), the published signing keys
// (the keyset's keys, canonical, each id its key's), the key-context digest (from the serving inputs), the
// signing-keys transcript and the keys signature, and the key statement — each the function's and the
// specification's; and the extension points' derivations.
func TestTheFrozenIdentities(t *testing.T) {
	m := frozenManifest(t)
	for _, d := range m.Profiles {
		var k fzKeyset
		readFrozen(t, d.KeysetFile, &k)
		id := Identity{Tenancy: k.Kind, HPKE: k.HPKEPublicKey, Response: k.ResponsePublicKey}
		if k.Version != 1 || k.Kind != d.Tenancy || k.Profile != d.Name || k.Fingerprint != d.Fingerprint ||
			k.WrappingVersion != d.WrappingVersion || id.Validate() != nil {
			t.Fatalf("%s: %+v", d.Name, k)
		}
		if got := Fingerprint(d.Name, id); got != d.Fingerprint || got != specFingerprint(d.Name, d.Tenancy, k.HPKEPublicKey,
			k.ResponsePublicKey) || !MatchesFingerprint(d.Name, id, d.Fingerprint) || FingerprintVersion(id) != 1 {
			t.Fatalf("%s: fingerprint %s, frozen %s", d.Name, got, d.Fingerprint)
		}
		var keys []SigningKey
		for _, s := range d.SigningKeys {
			keys = append(keys, SigningKey{KeyID: s.KeyID, State: s.State, PublicKey: ed25519.PublicKey(s.PublicKey)})
			if !bytes.Equal(SigningKeyID(ed25519.PublicKey(s.PublicKey)), s.KeyID) || !bytes.Equal(specKeyID(s.PublicKey), s.KeyID) {
				t.Fatalf("%s: the key id %x is not its key's", d.Name, s.KeyID)
			}
		}
		if err := ValidateSigningKeys(id, keys); err != nil || len(keys) != len(k.SigningKeys) ||
			!slices.IsSortedFunc(keys, func(a, b SigningKey) int { return bytes.Compare(a.KeyID, b.KeyID) }) {
			t.Fatalf("%s: the published list (%d keys, the keyset %d): %v", d.Name, len(keys), len(k.SigningKeys), err)
		}
		for _, pk := range keys {
			i := slices.IndexFunc(k.SigningKeys, func(f fzKeysetKey) bool { return bytes.Equal(f.KeyID, pk.KeyID) })
			if i < 0 || !bytes.Equal(k.SigningKeys[i].PublicKey, pk.PublicKey) ||
				(k.SigningKeys[i].State == SigningKeyRevoked) != (pk.State == SigningKeyRevoked) {
				t.Fatalf("%s: the published key %x is not the keyset's", d.Name, pk.KeyID)
			}
		}
		kc := KeyContext{Profile: d.Name, Tenancy: d.Tenancy, KeysetFingerprint: k.Fingerprint, SigningKeys: keys}
		for _, v := range d.Serve.Versions {
			i := slices.IndexFunc(k.MasterVersions, func(r fzKeysetCheck) bool { return r.ID == v })
			if i < 0 {
				t.Fatalf("%s: version %s is not recorded", d.Name, v)
			}
			kc.MasterVersions = append(kc.MasterVersions, MasterVersionCheck{ID: v, KCV: k.MasterVersions[i].KCV})
		}
		if got, err := ContextDigest(kc); err != nil || got != d.ContextDigest || got != specContextDigest(kc) {
			t.Fatalf("%s: context digest %s, frozen %s: %v", d.Name, got, d.ContextDigest, err)
		}
		if got, err := SigningKeysTranscript(Release(), d.Name, d.Tenancy, d.ContextDigest, d.KeysNonce, keys); err != nil ||
			!bytes.Equal(got, d.KeysTranscript) || !bytes.Equal(got, specKeysTranscript(d.Name, d.Tenancy, d.ContextDigest, d.KeysNonce, keys)) {
			t.Fatalf("%s: the signing-keys transcript is not the frozen one: %v", d.Name, err)
		}
		// The answer as a client receives it (each state its wire number): the same transcript, and keys_signature
		// verifies over it — and over no answer whose state number was changed after it was signed.
		received := make([]ReceivedSigningKey, len(keys))
		for i, pk := range keys {
			received[i] = ReceivedSigningKey{KeyID: pk.KeyID, State: pk.State.Code(), PublicKey: pk.PublicKey}
		}
		if got := ReceivedSigningKeysTranscript(Release(), d.Name, d.Tenancy, d.ContextDigest, d.KeysNonce, received); !bytes.Equal(got, d.KeysTranscript) ||
			VerifyKeysSignature(id.Response, got, d.KeysSignature) != nil {
			t.Fatalf("%s: the received form's transcript is not the frozen one, or keys_signature does not verify over it", d.Name)
		}
		for i := range received {
			changed := slices.Clone(received)
			changed[i].State = 7
			if err := VerifyKeysSignature(id.Response, ReceivedSigningKeysTranscript(Release(), d.Name, d.Tenancy, d.ContextDigest,
				d.KeysNonce, changed), d.KeysSignature); !errors.Is(err, ErrAuth) {
				t.Fatalf("%s: keys_signature verifies with key %d's state number changed: %v", d.Name, i, err)
			}
		}
		dk := ProfileKeys{Identity: id, SigningKeys: keys, ContextDigest: d.ContextDigest, KeysSignature: d.KeysSignature}
		if err := dk.Verify(Release(), d.Name, d.KeysNonce); err != nil {
			t.Fatalf("%s: the keys signature: %v", d.Name, err)
		}
		if err := dk.Verify(Release(), d.Name, bytes.Repeat([]byte{0}, NonceLen)); !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: the keys signature verifies for another nonce: %v", d.Name, err)
		}
		st, err := VerifyKeyStatement(Release(), d.Statement.Statement, d.Statement.Signature, d.Name, d.Fingerprint)
		if err != nil || st.IssuedAtMS != d.Statement.IssuedAtMS || st.ContextDigest != d.ContextDigest || !st.Identity.Equal(id) ||
			len(st.SigningKeys) != len(keys) || !bytes.Equal(statementSpec(st), d.Statement.Statement) {
			t.Fatalf("%s: the key statement: %+v %v", d.Name, st, err)
		}
		if _, err := VerifyKeyStatement(Release(), d.Statement.Statement, d.Statement.Signature, d.Name+"x", d.Fingerprint); !errors.Is(err, ErrKeyStatement) {
			t.Fatalf("%s: the statement verifies for another profile: %v", d.Name, err)
		}
	}
	for _, f := range m.Derivations.Fingerprints {
		suite := HPKESuite{KEM: f.HPKESuite.KEM, KDF: f.HPKESuite.KDF, AEAD: f.HPKESuite.AEAD}
		id := Identity{Tenancy: f.Tenancy, HPKESuite: suite, HPKE: f.HPKEPublicKey, ResponseAlgorithm: SignatureAlgorithm(f.ResponseAlgorithm),
			Response: ed25519.PublicKey(f.ResponsePublicKey)}
		if len(f.Additional) != 1 || f.Additional[0].Role != uint32(RoleHPKE) {
			t.Fatalf("%s: the added keys %+v", f.Profile, f.Additional)
		}
		a := f.Additional[0]
		as := HPKESuite{KEM: a.Suite.KEM, KDF: a.Suite.KDF, AEAD: a.Suite.AEAD}
		id.Additional = []IdentityKey{{Role: RoleHPKE, Suite: as, PublicKey: a.PublicKey}}
		// Version 2 from the specification (TestFingerprintVersions'): the suite, the algorithm, every key.
		sb := func(s HPKESuite) string {
			return string(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, s.KEM), s.KDF), s.AEAD))
		}
		spec := append(specJoin(fingerprint2Label, f.Profile, string(f.Tenancy), sb(suite), string(f.HPKEPublicKey),
			string(specU32(f.ResponseAlgorithm)), string(f.ResponsePublicKey), string(specU32(1))),
			specJoin(string(specU32(uint32(RoleHPKE))), sb(as), string(a.PublicKey))...)
		if f.Version != 2 || FingerprintVersion(id) != 2 || Fingerprint(f.Profile, id) != f.Fingerprint ||
			f.Fingerprint != FingerprintPrefix+hex.EncodeToString(specSum(spec)) || !ValidFingerprint(f.Fingerprint) {
			t.Fatalf("%s: fingerprint version 2 %s, frozen %s", f.Profile, Fingerprint(f.Profile, id), f.Fingerprint)
		}
	}
	for _, k := range m.Derivations.SigningKeyIDs {
		spec := specSum(specJoin(signingKeyID2Label, string(specU32(k.Algorithm)), string(k.PublicKey)))[:SigningKeyIDLen]
		if !bytes.Equal(SigningKeyIDOf(SignatureAlgorithm(k.Algorithm), k.PublicKey), k.KeyID) || !bytes.Equal(spec, k.KeyID) ||
			k.Algorithm == uint32(AlgorithmEd25519) {
			t.Fatalf("the id of a key of algorithm %d is not the frozen one", k.Algorithm)
		}
	}
	if len(m.Derivations.Fingerprints) == 0 || len(m.Derivations.SigningKeyIDs) == 0 {
		t.Fatal("no extension-point derivation")
	}
}

// checkKeyIDOf: c names its key — format, master version (its text form the id alone) or tenant key id, header
// length, and the length its format adds to its plaintext.
func checkKeyIDOf(t *testing.T, profile string, c fzCiphertext, tenantKeyID []byte) {
	t.Helper()
	k, err := ParseKeyID(Release(), c.Ciphertext)
	if err != nil || k.Format != c.Format || k.AssociatedData != (len(c.AssociatedData) > 0) ||
		CheckAssociatedData(k, c.AssociatedData) != nil || (len(c.AssociatedData) > 0) != (c.Format == FormatVersionedAAD || c.Format == FormatTenantKeyAAD) {
		t.Fatalf("%s: %+v %v (frozen format %d)", profile, k, err, c.Format)
	}
	switch c.Format {
	case FormatVersioned, FormatVersionedAAD:
		if k.MasterVersion != c.Version || k.HeaderLen != VersionedHeaderLen(c.Version) ||
			k.String() != c.Version || len(c.Ciphertext) != VersionedOverhead(c.Version)+len(c.Plaintext) {
			t.Fatalf("%s: %s %+v", profile, k, k)
		}
	case FormatTenantKey, FormatTenantKeyAAD:
		if !bytes.Equal(k.TenantKeyID, tenantKeyID) || !bytes.Equal(k.TenantKeyID, c.KeyID) || k.HeaderLen != TenantKeyHeaderLen ||
			k.String() != "tenant-key:"+hex.EncodeToString(tenantKeyID) || len(c.Ciphertext) != TenantKeyOverhead+len(c.Plaintext) {
			t.Fatalf("%s: %s %+v", profile, k, k)
		}
	default:
		t.Fatalf("%s: format %d", profile, c.Format)
	}
}

// TestTheFrozenCiphertexts: every ciphertext names its key with its format's header and length; every blob's header
// is the frozen one — version 1, wrapping version, creation time, key id, signing key, fingerprint (the
// specification's), and 226 bytes plus the profile, the tenant and the version id — and the blob it was rewrapped from
// holds the same key; the object's header and segments; every encrypted JSON field's encoding.
func TestTheFrozenCiphertexts(t *testing.T) {
	m := frozenManifest(t)
	formats := map[byte]int{}
	for _, d := range m.Profiles {
		for _, c := range d.Ciphertexts {
			checkKeyIDOf(t, d.Name, c, nil)
			if (c.Tenant != "") != (d.Tenancy == TenancyPerTenantDerived) {
				t.Fatalf("%s: a ciphertext of tenant %q", d.Name, c.Tenant)
			}
			formats[c.Format]++
		}
		for _, b := range d.Tenants {
			h, err := CheckTenantKey(Release(), b.Blob, d.Name, b.Tenant)
			if err != nil || h.Version != TenantKeyVersion || b.Blob[len(TenantKeyMagic)] != 1 || h.WrappingVersion != b.WrappingVersion ||
				h.Created.UTC().Format(time.RFC3339) != b.Created || !bytes.Equal(h.KeyID, b.KeyID) ||
				!bytes.Equal(h.SigningPublicKey, b.SigningPublicKey) || h.Fingerprint() != b.Fingerprint || !MatchesTenantFingerprint(h, b.Fingerprint) ||
				len(b.Blob) != 226+len(d.Name)+len(b.Tenant)+len(b.WrappingVersion) || len(h.Salt) != TenantKeySaltLen {
				t.Fatalf("%s/%s: %+v (%d bytes) %v", d.Name, b.Tenant, h, len(b.Blob), err)
			}
			spec := FingerprintPrefix + hex.EncodeToString(specSum(lpJoin([]byte("cipheron/v1|tenant-fingerprint"), []byte(d.Name),
				[]byte(b.Tenant), b.KeyID, b.SigningPublicKey)))
			if b.Fingerprint != spec {
				t.Fatalf("%s/%s: the tenant fingerprint is not the specification's", d.Name, b.Tenant)
			}
			if _, err := CheckTenantKey(Release(), b.Blob, d.Name, b.Tenant+"x"); !errors.Is(err, ErrTenantKey) {
				t.Fatalf("%s/%s: the blob is taken for another tenant's: %v", d.Name, b.Tenant, err)
			}
			if len(b.RewrappedFrom) > 0 {
				f, err := CheckTenantKey(Release(), b.RewrappedFrom, d.Name, b.Tenant)
				if err != nil || !bytes.Equal(f.KeyID, h.KeyID) || !bytes.Equal(f.SigningPublicKey, h.SigningPublicKey) ||
					f.Fingerprint() != h.Fingerprint() || !f.Created.Equal(h.Created) || bytes.Equal(f.Salt, h.Salt) {
					t.Fatalf("%s/%s: the blob it was rewrapped from: %+v %v", d.Name, b.Tenant, f, err)
				}
			}
			for _, c := range b.Ciphertexts {
				checkKeyIDOf(t, d.Name, c, h.KeyID)
				formats[c.Format]++
			}
		}
		for _, o := range d.Objects {
			h, segs, err := ParseSegmented(Release(), o.Object)
			if err != nil || h.SegmentSize != o.SegmentSize || int(h.Count) != o.Segments || len(segs) != o.Segments || o.Segments < 2 {
				t.Fatalf("%s: the object %+v %v", d.Name, h, err)
			}
			for i, seg := range segs {
				k, err := ParseKeyID(Release(), seg)
				if err != nil || k.Format != FormatVersionedAAD || k.MasterVersion != o.Version {
					t.Fatalf("%s: segment %d: %+v %v", d.Name, i, k, err)
				}
				final := []byte{0}
				if i == len(segs)-1 {
					final[0] = 1
				}
				spec := lpJoin([]byte("cipheron/v1|segment"), h.ObjectID, u32(uint32(i)), final, o.AssociatedData)
				if !bytes.Equal(SegmentAssociatedData(h.ObjectID, uint32(i), final[0] == 1, o.AssociatedData), spec) {
					t.Fatalf("%s: segment %d's associated data is not the specification's", d.Name, i)
				}
			}
		}
		for _, j := range d.JSON {
			var doc map[string]any
			if err := json.Unmarshal([]byte(j.Encrypted), &doc); err != nil || len(j.Pointers) == 0 {
				t.Fatalf("%s: %v", d.Name, err)
			}
			for _, p := range j.Pointers {
				v := any(doc)
				for _, tok := range bytes.Split([]byte(p)[1:], []byte("/")) {
					obj, ok := v.(map[string]any)
					if !ok {
						t.Fatalf("%s: pointer %s: got %T, not an object", d.Name, p, v)
					}
					v = obj[string(tok)]
				}
				s, _ := v.(string)
				ct, err := DecodeJSONField(Release(), s)
				if err != nil || EncodeJSONField(Release(), ct) != s {
					t.Fatalf("%s %s: not an encrypted field: %v", d.Name, p, err)
				}
				if k, err := ParseKeyID(Release(), ct); err != nil || k.Format != FormatVersionedAAD || !k.AssociatedData {
					t.Fatalf("%s %s: the field is not a format-5 ciphertext: %+v %v", d.Name, p, k, err)
				}
				spec := lpJoin([]byte("cipheron/v1|json-field"), []byte(j.RecordID), []byte(p), j.AssociatedData)
				if !bytes.Equal(JSONFieldAssociatedData(j.RecordID, p, j.AssociatedData), spec) {
					t.Fatalf("%s %s: the field's associated data is not the specification's", d.Name, p)
				}
			}
		}
	}
	if formats[FormatVersioned] != 10 || formats[FormatVersionedAAD] != 5 || formats[FormatTenantKey] != 6 || formats[FormatTenantKeyAAD] != 3 {
		t.Fatalf("the set's ciphertexts by format: %v", formats)
	}
}

// TestTheFrozenTenantRuleEdges: the set holds tenants of the tenant rule's edges (ValidTenant) — a derived and a
// wrapped tenant holding '|', '"', '\', '/' and '%', and the longest id, of MaxTenantLen bytes, in both, in their
// ciphertexts, blobs, seal infos and tenant-signed messages — and a blob at MaxTenantKeyLen (the longest profile name,
// tenant id and wrapping version id), which opens under its published wrapping key and is refused a byte longer.
func TestTheFrozenTenantRuleEdges(t *testing.T) {
	m := frozenManifest(t)
	odd := func(s string) bool {
		return strings.Contains(s, "|") && strings.Contains(s, `"`) && strings.Contains(s, `\`) &&
			strings.Contains(s, "/") && strings.Contains(s, "%")
	}
	seen := map[string]bool{}
	for _, d := range m.Profiles {
		var tenants []string
		for _, c := range d.Ciphertexts {
			tenants = append(tenants, c.Tenant)
		}
		for _, b := range d.Tenants {
			tenants = append(tenants, b.Tenant)
		}
		for _, tn := range tenants {
			if tn != "" && !ValidTenant(tn) {
				t.Fatalf("%s: the tenant %q is not a tenant id", d.Name, tn)
			}
			if odd(tn) {
				seen[string(d.Tenancy)+"/odd"] = true
			}
			if len(tn) == MaxTenantLen {
				seen[string(d.Tenancy)+"/longest"] = true
			}
		}
	}
	for _, r := range m.Transcripts.Requests {
		if len(r.Tenant) == MaxTenantLen || odd(r.Tenant) {
			seen["request/"+string(r.Op)] = true
		}
	}
	for _, s := range m.Transcripts.TenantSignedMessages {
		if len(s.Tenant) == MaxTenantLen {
			seen["tenantSignedMessage"] = true
		}
	}
	derived, wrapped := string(TenancyPerTenantDerived), string(TenancyPerTenantWrapped)
	for _, k := range []string{derived + "/odd", derived + "/longest", wrapped + "/odd", wrapped + "/longest",
		"request/encrypt", "request/decrypt", "tenantSignedMessage"} {
		if !seen[k] {
			t.Errorf("the set holds no %s tenant of the rule's edges (%v)", k, seen)
		}
	}
	if len(m.Derivations.TenantKeys) != 1 {
		t.Fatalf("%d blobs at the bound", len(m.Derivations.TenantKeys))
	}
	b := m.Derivations.TenantKeys[0]
	h, err := CheckTenantKey(Release(), b.Blob, b.Profile, b.Tenant)
	if err != nil || len(b.Blob) != MaxTenantKeyLen || len(b.Profile) != MaxProfileLen || len(b.Tenant) != MaxTenantLen ||
		len(b.WrappingVersion) != MaxMasterVersionIDLen || h.WrappingVersion != b.WrappingVersion || h.Fingerprint() != b.Fingerprint ||
		!bytes.Equal(h.KeyID, b.KeyID) || !bytes.Equal(h.SigningPublicKey, b.SigningPublicKey) {
		t.Fatalf("the blob at the bound: %d bytes, %+v %v", len(b.Blob), h, err)
	}
	key, err := TenantKeyItemKey(Release(), b.WrapKey, h)
	if err != nil {
		t.Fatal(err)
	}
	private, ok := key.Open(nil, h.Sealed, h.AAD)
	if !ok || len(private) != TenantPrivateLen || !bytes.Equal(private[32+ed25519.SeedSize:], h.SigningPublicKey) {
		t.Fatalf("the blob at the bound does not open under its wrapping key: %v", err)
	}
	if _, err := ParseTenantKey(Release(), append(bytes.Clone(b.Blob), 0)); !errors.Is(err, ErrTenantKey) {
		t.Fatalf("a blob a byte over MaxTenantKeyLen: %v", err)
	}
}

// TestTheFrozenSignatures: a shared profile's signature verifies under its listed key over the data, and not as a
// tenant's; a derived one's over its tenant's signed message only (the specification's), not over the data alone or
// as another tenant's; a wrapped tenant's under its blob's key; a key the profile revoked is listed revoked.
func TestTheFrozenSignatures(t *testing.T) {
	m := frozenManifest(t)
	n, revoked := 0, 0
	for _, d := range m.Profiles {
		keys := map[string]ed25519.PublicKey{}
		states := map[string]SigningKeyState{}
		for _, k := range d.SigningKeys {
			keys[string(k.KeyID)], states[string(k.KeyID)] = ed25519.PublicKey(k.PublicKey), k.State
		}
		for _, s := range d.Signatures {
			p, ok := keys[string(s.KeyID)]
			if !ok {
				t.Fatalf("%s: a signature under an unlisted key %x", d.Name, s.KeyID)
			}
			if states[string(s.KeyID)] == SigningKeyRevoked {
				revoked++
			}
			switch d.Tenancy {
			case TenancyShared:
				if !ed25519.Verify(p, []byte(s.Data), s.Signature) || VerifyTenant(p, d.Name, "t", []byte(s.Data), s.Signature) == nil {
					t.Fatalf("%s: the signature over %q", d.Name, s.Data)
				}
			case TenancyPerTenantDerived:
				msg := lpJoin([]byte("cipheron/v1|tenant-signature"), []byte(d.Name), []byte(s.Tenant), []byte(s.Data))
				if VerifyTenant(p, d.Name, s.Tenant, []byte(s.Data), s.Signature) != nil || !ed25519.Verify(p, msg, s.Signature) ||
					VerifyTenant(p, d.Name, s.Tenant+"x", []byte(s.Data), s.Signature) == nil || ed25519.Verify(p, []byte(s.Data), s.Signature) {
					t.Fatalf("%s: the signature of %s over %q", d.Name, s.Tenant, s.Data)
				}
			default:
				t.Fatalf("%s: a profile signature in a %s profile", d.Name, d.Tenancy)
			}
			n++
		}
		for _, b := range d.Tenants {
			for _, s := range b.Signatures {
				if !bytes.Equal(s.KeyID, b.KeyID) || !ed25519.Verify(ed25519.PublicKey(b.SigningPublicKey), []byte(s.Data), s.Signature) {
					t.Fatalf("%s/%s: the signature over %q", d.Name, b.Tenant, s.Data)
				}
				n++
			}
		}
	}
	for _, s := range m.Transcripts.TenantSignedMessages {
		spec := lpJoin([]byte("cipheron/v1|tenant-signature"), []byte(s.Profile), []byte(s.Tenant), []byte(s.Data))
		if !bytes.Equal(TenantSignedMessage(s.Profile, s.Tenant, []byte(s.Data)), s.Message) || !bytes.Equal(spec, s.Message) {
			t.Fatalf("the tenant-signed message of %s/%s is not the frozen one", s.Profile, s.Tenant)
		}
	}
	if n != 11 || revoked != 1 || len(m.Transcripts.TenantSignedMessages) == 0 {
		t.Fatalf("%d signatures, %d under a revoked key", n, revoked)
	}
}

// fzDigestOf is the named digest function of op over fields (Digest's table, the batch's and the extensions').
func fzDigestOf(t *testing.T, op Operation, request bool, fields [][]byte, items [][][]byte) [sha256.Size]byte {
	t.Helper()
	f := func(i int) []byte { return fields[i] }
	switch {
	case op.Batch():
		var ds [][sha256.Size]byte
		for _, it := range items {
			ds = append(ds, Digest(it...))
		}
		return BatchDigest(ds)
	case request && op == OpEncrypt && len(fields) == 5:
		return EncryptDigestAAD(f(0), f(1), string(f(2)), f(3), f(4))
	case request && op == OpEncrypt:
		return EncryptDigest(f(0), f(1), string(f(2)), f(3))
	case request && op == OpDecrypt && len(fields) == 5:
		return DecryptDigestAAD(f(0), f(1), string(f(2)), f(3), f(4))
	case request && op == OpDecrypt:
		return DecryptDigest(f(0), f(1), string(f(2)), f(3))
	case request && op == OpSign:
		return SignDigest(f(0), f(1), string(f(2)), f(3))
	case request && op == OpReEncrypt && len(fields) == 8:
		return ReEncryptDigestExt(f(0), string(f(1)), f(2), f(3), ReEncryptExt{AssociatedData: f(4), ToAssociatedData: f(5),
			ToProfile: string(f(6)), ToTenant: string(f(7))})
	case request && op == OpReEncrypt:
		return ReEncryptDigest(f(0), string(f(1)), f(2), f(3))
	case request && op == OpProvision:
		return ProvisionDigest(string(f(0)))
	case request && op == OpRewrapTenantKey:
		return RewrapTenantKeyDigest(string(f(0)), f(1))
	case op == OpEncrypt, op == OpReEncrypt:
		return CiphertextResponseDigest(f(0))
	case op == OpDecrypt:
		return Digest(f(0), f(1), f(2))
	case op == OpSign:
		return SignResponseDigest(f(0), f(1))
	case op == OpProvision, op == OpRewrapTenantKey:
		return TenantKeyResponseDigest(f(0), f(1), string(f(2)))
	}
	t.Fatalf("op %q", op)
	return [sha256.Size]byte{}
}

// checkFrozenDigest: digest is Digest of fields, the named function's and the specification's (specDigest); a
// batch's fields are its count and its items' digests, each Digest of the item's fields.
func checkFrozenDigest(t *testing.T, name string, op Operation, request bool, fields []fzHex, items [][]fzHex, digest []byte) {
	t.Helper()
	var its [][][]byte
	if op.Batch() {
		if len(fields) != len(items)+1 || !bytes.Equal(fields[0], u32(uint32(len(items)))) {
			t.Fatalf("%s: a batch of %d items with %d fields", name, len(items), len(fields))
		}
		for i, it := range items {
			if d := specDigest(fzBytes(it)...); !bytes.Equal(d[:], fields[i+1]) {
				t.Fatalf("%s: item %d's digest is not its fields'", name, i)
			}
			its = append(its, fzBytes(it))
		}
	}
	fs := fzBytes(fields)
	named, plain, spec := fzDigestOf(t, op, request, fs, its), Digest(fs...), specDigest(fs...)
	if !bytes.Equal(named[:], digest) || !bytes.Equal(plain[:], digest) || !bytes.Equal(spec[:], digest) {
		t.Fatalf("%s: the digest is not the frozen one", name)
	}
}

// TestTheFrozenTranscripts: every payload digest; every request transcript — RequestTranscript's and the
// specification's, lp(label) lp(1) lp(profile) lp(op) lp(timestamp: 8) lp(nonce) lp(digest) — signed by the
// request key (byte for byte: Ed25519 is deterministic); every Encrypt's and Sign's seal info, and no other request's
// (RequestSealInfo: the context string, lp(1), lp(SHA-256 of the request key)); every response transcript —
// lp(label) lp(1) lp(profile) lp(op) lp(request nonce) lp(requester) lp(request digest) lp(response digest) — signed
// by its profile's response key; every Decrypt answer's seal info and no other answer's (ResponseInfoTenant: the
// context string and lp(1)).
func TestTheFrozenTranscripts(t *testing.T) {
	m := frozenManifest(t)
	tr := m.Transcripts
	priv := ed25519.NewKeyFromSeed(tr.RequestKeySeed)
	pub := publicOf(t, priv)
	if !bytes.Equal(pub, tr.RequestPublicKey) {
		t.Fatal("the request key's public key")
	}
	responseKeys := map[string]ed25519.PublicKey{}
	contextDigests := map[string]string{}
	for _, d := range m.Profiles {
		var k fzKeyset
		readFrozen(t, d.KeysetFile, &k)
		responseKeys[d.Name] = k.ResponsePublicKey
		contextDigests[d.Name] = d.ContextDigest
	}
	ops := map[Operation]bool{}
	sealed := 0
	for i, r := range tr.Requests {
		name := fmt.Sprintf("request %d (%s)", i, r.Op)
		checkFrozenDigest(t, name, r.Op, true, r.Fields, r.Items, r.Digest)
		ts := binary.BigEndian.AppendUint64(nil, uint64(r.TimestampMS))
		spec := lpJoin([]byte("cipheron/v1|signed_request"), u32(1), []byte(r.Profile), []byte(r.Op), ts, r.Nonce, r.Digest)
		if got := RequestTranscript(Release(), r.Profile, r.Op, r.TimestampMS, r.Nonce, [sha256.Size]byte(r.Digest)); !bytes.Equal(got, r.Transcript) ||
			!bytes.Equal(spec, r.Transcript) {
			t.Fatalf("%s: the transcript is not the frozen one", name)
		}
		if VerifyRequest(pub, r.Transcript, r.Signature) != nil || !bytes.Equal(ed25519.Sign(priv, r.Transcript), r.Signature) {
			t.Fatalf("%s: the signature", name)
		}
		seals := r.Op == OpEncrypt || r.Op == OpSign
		if seals != (len(r.SealInfo) > 0) {
			t.Fatalf("%s: a seal info %x", name, r.SealInfo)
		}
		if seals {
			spec := append(specSealContext("request", r.Profile, r.Op, r.Tenant), lpJoin(u32(1), specSum(pub))...)
			if !bytes.Equal(RequestSealInfo(Release(), r.Profile, r.Op, r.Tenant, pub), r.SealInfo) || !bytes.Equal(spec, r.SealInfo) {
				t.Fatalf("%s: the seal info is not the frozen one", name)
			}
			sealed++
		}
		ops[r.Op] = true
	}
	if len(ops) != 7 || sealed == 0 {
		t.Fatalf("the requests cover %d transcript labels, %d seal infos", len(ops), sealed)
	}
	unsigned, opened := 0, 0
	for i, r := range tr.Responses {
		name := fmt.Sprintf("response %d (%s)", i, r.Op)
		q := tr.Requests[r.Request]
		if q.Op != r.Op || q.Profile != r.Profile || q.Tenant != r.Tenant || !bytes.Equal(q.Nonce, r.RequestNonce) ||
			!bytes.Equal(q.Digest, r.RequestDigest) || r.Signed != bytes.Equal(q.Signature, r.RequestSignature) {
			t.Fatalf("%s: not the answer to request %d", name, r.Request)
		}
		checkFrozenDigest(t, name, r.Op, false, r.Fields, r.Items, r.Digest)
		var requester []byte
		if r.Signed {
			requester = specSum(r.RequestSignature)
		} else {
			unsigned++
		}
		// The answering cipheron's key-context digest: the profile's, as its PublicKey answer froze it.
		if r.ContextDigest == "" || r.ContextDigest != contextDigests[r.Profile] {
			t.Fatalf("%s: the context digest %q is not profile %s's %q", name, r.ContextDigest, r.Profile, contextDigests[r.Profile])
		}
		spec := lpJoin([]byte("cipheron/v1|signed_response"), u32(1), []byte(r.Profile), []byte(r.ContextDigest), []byte(r.Op),
			r.RequestNonce, requester, r.RequestDigest, r.Digest)
		got := ResponseTranscript(Release(), r.Profile, r.ContextDigest, r.Op, r.RequestNonce, r.RequestSignature,
			[sha256.Size]byte(r.RequestDigest), [sha256.Size]byte(r.Digest))
		if !bytes.Equal(got, r.Transcript) || !bytes.Equal(spec, r.Transcript) {
			t.Fatalf("%s: the transcript is not the frozen one", name)
		}
		if VerifyResponse(responseKeys[r.Profile], r.Transcript, r.Signature) != nil {
			t.Fatalf("%s: the response signature", name)
		}
		for _, other := range m.Profiles {
			if other.Name != r.Profile && VerifyResponse(responseKeys[other.Name], r.Transcript, r.Signature) == nil {
				t.Fatalf("%s: the signature verifies under %s's response key", name, other.Name)
			}
		}
		if (r.Op == OpDecrypt) != (len(r.SealInfo) > 0) {
			t.Fatalf("%s: a seal info %x", name, r.SealInfo)
		}
		if len(r.SealInfo) > 0 {
			spec := append(specSealContext("response", r.Profile, r.Op, r.Tenant), lpJoin(u32(1))...)
			if !bytes.Equal(ResponseInfoTenant(Release(), r.Profile, r.Op, r.Tenant), r.SealInfo) || !bytes.Equal(spec, r.SealInfo) {
				t.Fatalf("%s: the seal info is not the frozen one", name)
			}
			opened++
		}
	}
	if unsigned != 1 || opened == 0 {
		t.Fatalf("%d answers to unsigned requests, %d sealed answers", unsigned, opened)
	}
}

// TestTheFrozenBatchItemDigests: the frozen EncryptBatch answer's item digests are the FUNCTIONS' — ItemResultDigest
// and ItemErrorDigest, which cipheron, the client, the fake and the test client all compute them with — and the
// specification's, byte for byte: a result item is Digest(0x00, the ciphertext), an error item Digest(0x01, the
// code (4 bytes), the reason, the message). checkFrozenDigest holds the frozen item fields to the specification only,
// so without this a layout change made in the functions and the generator alike (a marker dropped, a field moved)
// would stay green.
func TestTheFrozenBatchItemDigests(t *testing.T) {
	m := frozenManifest(t)
	results, failures := 0, 0
	for i, r := range m.Transcripts.Responses {
		if r.Op != OpEncryptBatch {
			continue
		}
		if len(r.Fields) != len(r.Items)+1 {
			t.Fatalf("response %d: %d items, %d fields", i, len(r.Items), len(r.Fields))
		}
		for k, it := range r.Items {
			name := fmt.Sprintf("response %d (%s), item %d", i, r.Op, k)
			frozen := []byte(r.Fields[k+1])
			switch {
			case len(it) == 2 && bytes.Equal(it[0], []byte{0x00}):
				fn, spec := ItemResultDigest(it[1]), specDigest([]byte{0x00}, it[1])
				if !bytes.Equal(fn[:], frozen) || !bytes.Equal(spec[:], frozen) {
					t.Fatalf("%s: ItemResultDigest %x, the specification's %x, frozen %x", name, fn, spec, frozen)
				}
				results++
			case len(it) == 4 && bytes.Equal(it[0], []byte{0x01}) && len(it[1]) == 4:
				code := binary.BigEndian.Uint32(it[1])
				if string(it[2]) != ReasonAssociatedData || len(it[3]) == 0 {
					t.Fatalf("%s: the error item is code %d, reason %q, message %q", name, code, it[2], it[3])
				}
				fn := ItemErrorDigest(code, string(it[2]), string(it[3]))
				spec := specDigest([]byte{0x01}, u32(code), it[2], it[3])
				if !bytes.Equal(fn[:], frozen) || !bytes.Equal(spec[:], frozen) {
					t.Fatalf("%s: ItemErrorDigest %x, the specification's %x, frozen %x", name, fn, spec, frozen)
				}
				failures++
			default:
				t.Fatalf("%s: neither a result nor an error item: %x", name, it)
			}
		}
	}
	if results == 0 || failures == 0 {
		t.Fatalf("the frozen batch answers hold %d result items and %d error items; want both", results, failures)
	}
}
