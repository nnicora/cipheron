package conformance

// generate_test.go — the kit's vectors are DERIVED from the frozen set (spec/frozen:
// manifest.json and its keysets), and every value the kit shares with it is held to it here: a request transcript, a
// seal info, a response transcript or a signing-keys transcript the kit holds is the frozen one byte for byte, a
// digest is the set's, a response signature is the profile's response key's as the set froze it, a fingerprint the
// keyset's, a signing key's id the published one, a ciphertext's key id its master version (or its tenant key's
// id), a key statement the profile's. The associated data of a segment and of an encrypted JSON field are rebuilt from
// the specification (their values are not in the set: the set's ciphertexts open only under them, which the
// keyring's frozen reader proves). A re-encryption's associated-data rule (reEncryptAssociatedData) is written from the
// rule: it holds no bytes of the set. Every case is checked with Reference as it is added; the negative cases flip one
// bit, or are the rule's refusal.
//
// TestTheVectorsAreTheFrozenFilesDerivation rebuilds the file and requires the embedded one to be exactly it. To write
// it after the frozen set gained a value (never to make a reader pass):
//
//	go test ./conformance -run TestTheVectorsAreTheFrozenFilesDerivation -update-conformance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/wire/transport"
)

var updateConformance = flag.Bool("update-conformance", false, "write vectors/cipheron-conformance-v1.json from the frozen set")

// frozenDir is the frozen set the kit is derived from.
const frozenDir = "../spec/frozen"

// fzHex is bytes written as hex in the frozen manifest.
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
	Tenant     string `json:"tenant"`
	Format     byte   `json:"format"`
	Version    string `json:"version"`
	KeyID      fzHex  `json:"keyId"`
	Ciphertext fzHex  `json:"ciphertext"`
}

// fzBlob is a tenant key blob of the set, as its header reads.
type fzBlob struct {
	Tenant           string         `json:"tenant"`
	Blob             fzHex          `json:"blob"`
	WrappingVersion  string         `json:"wrappingVersion"`
	Created          string         `json:"created"`
	KeyID            fzHex          `json:"keyId"`
	SigningPublicKey fzHex          `json:"signingPublicKey"`
	Fingerprint      string         `json:"fingerprint"`
	RewrappedFrom    fzHex          `json:"rewrappedFrom"`
	Ciphertexts      []fzCiphertext `json:"ciphertexts"`
}

// fzSuite is an HPKE suite of the set.
type fzSuite struct {
	KEM  uint16 `json:"kem"`
	KDF  uint16 `json:"kdf"`
	AEAD uint16 `json:"aead"`
}

// fzManifest is the part of the frozen manifest the kit is derived from.
type fzManifest struct {
	Profiles []struct {
		Name          string `json:"name"`
		Tenancy       string `json:"tenancy"`
		KeysetFile    string `json:"keysetFile"`
		Fingerprint   string `json:"fingerprint"`
		ContextDigest string `json:"contextDigest"`
		SigningKeys   []struct {
			KeyID     fzHex  `json:"keyId"`
			State     string `json:"state"`
			PublicKey fzHex  `json:"publicKey"`
		} `json:"signingKeys"`
		KeysNonce      fzHex `json:"keysNonce"`
		KeysTranscript fzHex `json:"keysTranscript"`
		KeysSignature  fzHex `json:"keysSignature"`
		Statement      struct {
			Statement fzHex `json:"statement"`
			Signature fzHex `json:"signature"`
		} `json:"statement"`
		Ciphertexts []fzCiphertext `json:"ciphertexts"`
		Tenants     []fzBlob       `json:"tenants"`
		Objects     []struct {
			AssociatedData fzHex  `json:"associatedData"`
			Version        string `json:"version"`
			Object         fzHex  `json:"object"`
		} `json:"objects"`
		JSON []struct {
			RecordID       string   `json:"recordId"`
			Pointers       []string `json:"pointers"`
			AssociatedData fzHex    `json:"associatedData"`
		} `json:"json"`
	} `json:"profiles"`
	Transcripts struct {
		RequestPublicKey fzHex `json:"requestPublicKey"`
		Requests         []struct {
			Op          string    `json:"op"`
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
			Op               string    `json:"op"`
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
			Profile           string  `json:"profile"`
			Tenancy           string  `json:"tenancy"`
			HPKESuite         fzSuite `json:"hpkeSuite"`
			HPKEPublicKey     fzHex   `json:"hpkePublicKey"`
			ResponseAlgorithm uint32  `json:"responseAlgorithm"`
			ResponsePublicKey fzHex   `json:"responsePublicKey"`
			Additional        []struct {
				Role      uint32  `json:"role"`
				Suite     fzSuite `json:"suite"`
				Algorithm uint32  `json:"algorithm"`
				PublicKey fzHex   `json:"publicKey"`
			} `json:"additional"`
			Version     int    `json:"version"`
			Fingerprint string `json:"fingerprint"`
		} `json:"fingerprints"`
		TenantKeys []struct {
			fzBlob

			Profile string `json:"profile"`
		} `json:"tenantKeys"`
		SigningKeyIDs []struct {
			Algorithm uint32 `json:"algorithm"`
			PublicKey fzHex  `json:"publicKey"`
			KeyID     fzHex  `json:"keyId"`
		} `json:"signingKeyIds"`
	} `json:"derivations"`
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

func flip(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)-1] ^= 0x01
	return c
}

// hexes is fs as the kit's hex fields.
func hexes[T ~[]byte](fs ...T) []Hex {
	out := make([]Hex, len(fs))
	for i, f := range fs {
		out[i] = Hex(f)
	}
	return out
}

// lpJoin is lp(f1) lp(f2) …: each field behind its 4-byte big-endian length (the specification's encoding).
func lpJoin(fields ...[]byte) []byte {
	var out []byte
	for _, f := range fields {
		out = append(append(out, byte(len(f)>>24), byte(len(f)>>16), byte(len(f)>>8), byte(len(f))), f...)
	}
	return out
}

// builder collects cases, each checked with Reference as it is added (a case Reference fails is a generator bug).
type builder struct {
	t     *testing.T
	cases []Case
}

func (b *builder) add(id, kind, note string, in, out any) {
	b.t.Helper()
	ri, err := json.Marshal(in)
	if err != nil {
		b.t.Fatal(err)
	}
	ro, err := json.Marshal(out)
	if err != nil {
		b.t.Fatal(err)
	}
	got, err := Reference().Evaluate(b.t.Context(), kind, ri)
	if err != nil || !equalJSON(ro, got) {
		b.t.Fatalf("%s: the reference answers %s, %v; the frozen value is %s", id, got, err, ro)
	}
	b.cases = append(b.cases, Case{ID: id, Kind: kind, Note: note, Input: ri, Output: ro})
}

func buildSuite(t *testing.T) *Suite {
	t.Helper()
	var m fzManifest
	readJSON(t, filepath.Join(frozenDir, "manifest.json"), &m)
	b := &builder{t: t}
	tr := m.Transcripts
	requestKey := Hex(tr.RequestPublicKey)
	responseKeys := map[string]Hex{}
	for _, d := range m.Profiles {
		var ks struct {
			HPKEPublicKey     string `json:"hpkePublicKey"`
			ResponsePublicKey string `json:"responsePublicKey"`
		}
		readJSON(t, filepath.Join(frozenDir, d.KeysetFile), &ks)
		responseKeys[d.Name] = unb64(t, ks.ResponsePublicKey)
		b.add("fingerprint/"+d.Name, KindFingerprint, "a classical identity: fingerprint version 1",
			FingerprintInput{Profile: d.Name, Tenancy: d.Tenancy,
				HPKESuite:     HPKESuiteInput{KEM: transport.KEMID, KDF: transport.KDFID, AEAD: transport.AEADID},
				HPKEPublicKey: unb64(t, ks.HPKEPublicKey), ResponseAlgorithm: uint32(transport.AlgorithmEd25519),
				ResponsePublicKey: responseKeys[d.Name]},
			FingerprintOutput{Fingerprint: d.Fingerprint})
	}

	for i, r := range tr.Requests {
		id := fmt.Sprintf("%d-%s", i, r.Op)
		b.add("digest/request/"+id, KindDigest, "the payload digest of a "+r.Op+" request", DigestInput{Fields: hexes(r.Fields...)},
			DigestOutput{Digest: Hex(r.Digest)})
		for j, it := range r.Items {
			b.add(fmt.Sprintf("digest/request/%s/item-%d", id, j), KindDigest, "a batch item's digest: the single operation's",
				DigestInput{Fields: hexes(it...)}, DigestOutput{Digest: Hex(r.Fields[j+1])})
		}
		b.add("requestTranscript/"+id, KindRequestTranscript, "", RequestTranscriptInput{Profile: r.Profile, Operation: r.Op,
			TimestampMS: r.TimestampMS, Nonce: Hex(r.Nonce), Digest: Hex(r.Digest)}, TranscriptOutput{Transcript: Hex(r.Transcript)})
		b.add("requestSignature/"+id+"/valid", KindRequestSignature, "",
			SignatureInput{PublicKey: requestKey, Transcript: Hex(r.Transcript), Signature: Hex(r.Signature)}, ValidOutput{Valid: true})
		if i == 0 {
			b.add("requestSignature/"+id+"/signature-flipped", KindRequestSignature, "one bit of the signature flipped",
				SignatureInput{PublicKey: requestKey, Transcript: Hex(r.Transcript), Signature: flip(r.Signature)}, ValidOutput{Valid: false})
			b.add("requestSignature/"+id+"/transcript-flipped", KindRequestSignature, "one bit of the transcript (its digest) flipped",
				SignatureInput{PublicKey: requestKey, Transcript: flip(r.Transcript), Signature: Hex(r.Signature)}, ValidOutput{Valid: false})
		}
		if len(r.SealInfo) > 0 {
			b.add("requestSealInfo/"+id, KindRequestSealInfo,
				"the HPKE info of the request's sealed payload: bound to the profile, the operation, the tenant, the transcript "+
					"version and the requester's request key",
				RequestSealInfoInput{Profile: r.Profile, Operation: r.Op, Tenant: r.Tenant, RequestPublicKey: requestKey},
				InfoOutput{Info: Hex(r.SealInfo)})
		}
	}
	// A requester without a request key: its seal info's requester field is empty (derived from the specification:
	// the context string, lp(version 1), lp("")).
	r0 := tr.Requests[0]
	noKey := append(transport.RequestInfoTenant(r0.Profile, transport.Operation(r0.Op), ""), lpJoin([]byte{0, 0, 0, 1}, nil)...)
	b.add("requestSealInfo/no-request-key", KindRequestSealInfo, "a socket caller without a request key: a zero-length requester field",
		RequestSealInfoInput{Profile: r0.Profile, Operation: r0.Op, Tenant: "", RequestPublicKey: Hex{}}, InfoOutput{Info: noKey})

	for i, r := range tr.Responses {
		id := fmt.Sprintf("%d-%s", i, r.Op)
		b.add("digest/response/"+id, KindDigest, "the digest of a "+r.Op+" answer's fields", DigestInput{Fields: hexes(r.Fields...)},
			DigestOutput{Digest: Hex(r.Digest)})
		for j, it := range r.Items {
			b.add(fmt.Sprintf("digest/response/%s/item-%d", id, j), KindDigest,
				"a batch item's result digest: 0x00 and its value, or 0x01, the code (4 bytes), the reason and the message",
				DigestInput{Fields: hexes(it...)}, DigestOutput{Digest: Hex(r.Fields[j+1])})
		}
		note := "the answer is bound to the request's signature (its SHA-256 is the requester field)"
		if len(r.RequestSignature) == 0 {
			note = "an answer to a request that carried no signature: a zero-length requester field"
		}
		b.add("responseTranscript/"+id, KindResponseTranscript, note+"; the answering cipheron's key-context digest follows "+
			"the profile", ResponseTranscriptInput{Profile: r.Profile, ContextDigest: r.ContextDigest, Operation: r.Op,
			RequestNonce: Hex(r.RequestNonce), RequestSignature: Hex(r.RequestSignature), RequestDigest: Hex(r.RequestDigest),
			ResponseDigest: Hex(r.Digest)}, TranscriptOutput{Transcript: Hex(r.Transcript)})
		key := responseKeys[r.Profile]
		b.add("responseSignature/"+id+"/valid", KindResponseSignature, "signed by the profile's response key",
			SignatureInput{PublicKey: key, Transcript: Hex(r.Transcript), Signature: Hex(r.Signature)}, ValidOutput{Valid: true})
		if i == 0 {
			b.add("responseSignature/"+id+"/signature-flipped", KindResponseSignature, "",
				SignatureInput{PublicKey: key, Transcript: Hex(r.Transcript), Signature: flip(r.Signature)}, ValidOutput{Valid: false})
			b.add("responseSignature/"+id+"/answer-flipped", KindResponseSignature,
				"one bit of the response digest flipped: an answer that is not the one signed",
				SignatureInput{PublicKey: key, Transcript: flip(r.Transcript), Signature: Hex(r.Signature)}, ValidOutput{Valid: false})
			for _, other := range m.Profiles {
				if other.Name != r.Profile {
					b.add("responseSignature/"+id+"/another-key", KindResponseSignature,
						"verified under another profile's response key: an impostor's answer",
						SignatureInput{PublicKey: responseKeys[other.Name], Transcript: Hex(r.Transcript), Signature: Hex(r.Signature)},
						ValidOutput{Valid: false})
					break
				}
			}
		}
		if len(r.SealInfo) > 0 {
			b.add("responseSealInfo/"+id, KindResponseSealInfo,
				"the HPKE info of a Decrypt answer's sealed plaintext: bound to the profile, the operation, the tenant and the "+
					"transcript version", ResponseSealInfoInput{Profile: r.Profile, Operation: r.Op, Tenant: r.Tenant},
				InfoOutput{Info: Hex(r.SealInfo)})
		}
	}

	for _, d := range m.Profiles {
		keys := make([]SigningKeyInput, 0, len(d.SigningKeys))
		for _, s := range d.SigningKeys {
			keys = append(keys, SigningKeyInput{KeyID: Hex(s.KeyID), State: s.State, PublicKey: Hex(s.PublicKey)})
		}
		note := "keys are written in ascending key id order whatever the order given, each state as its number"
		if len(keys) == 0 {
			note = "a wrapped profile publishes no signing key: the count 0 still binds the version, profile, tenancy, digest and nonce"
		}
		b.add("signingKeysTranscript/"+d.Name, KindSigningKeysTranscript, note, SigningKeysTranscriptInput{Profile: d.Name,
			Tenancy: d.Tenancy, ContextDigest: d.ContextDigest, Nonce: Hex(d.KeysNonce), Keys: keys},
			TranscriptOutput{Transcript: Hex(d.KeysTranscript)})
		b.add("responseSignature/keys-"+d.Name+"/valid", KindResponseSignature,
			"a PublicKey answer's keys signature: the profile's response key over the signing-keys transcript",
			SignatureInput{PublicKey: responseKeys[d.Name], Transcript: Hex(d.KeysTranscript), Signature: Hex(d.KeysSignature)},
			ValidOutput{Valid: true})
		for i, k := range d.SigningKeys {
			b.add(fmt.Sprintf("signingKeyID/%s/%d", d.Name, i), KindSigningKeyID, "an Ed25519 signing key ("+k.State+"): its id as published",
				SigningKeyIDInput{Algorithm: uint32(transport.AlgorithmEd25519), PublicKey: Hex(k.PublicKey)}, KeyIDOutput{KeyID: Hex(k.KeyID)})
		}
		b.add("keyStatement/"+d.Name+"/valid", KindKeyStatement, "the statement's identity has this fingerprint, and its response key signed it",
			KeyStatementInput{Statement: Hex(d.Statement.Statement), Signature: Hex(d.Statement.Signature), Profile: d.Name,
				Fingerprint: d.Fingerprint}, ValidOutput{Valid: true})
	}
	st, other := m.Profiles[0], m.Profiles[1]
	b.add("keyStatement/"+st.Name+"/signature-flipped", KindKeyStatement, "", KeyStatementInput{Statement: Hex(st.Statement.Statement),
		Signature: flip(st.Statement.Signature), Profile: st.Name, Fingerprint: st.Fingerprint}, ValidOutput{Valid: false})
	b.add("keyStatement/"+st.Name+"/another-pin", KindKeyStatement, "the pin is another profile's fingerprint: refused whatever the signature",
		KeyStatementInput{Statement: Hex(st.Statement.Statement), Signature: Hex(st.Statement.Signature), Profile: st.Name,
			Fingerprint: other.Fingerprint}, ValidOutput{Valid: false})
	b.add("keyStatement/"+st.Name+"/another-profile", KindKeyStatement, "", KeyStatementInput{Statement: Hex(st.Statement.Statement),
		Signature: Hex(st.Statement.Signature), Profile: "another", Fingerprint: st.Fingerprint}, ValidOutput{Valid: false})

	for _, k := range m.Derivations.SigningKeyIDs {
		b.add(fmt.Sprintf("signingKeyID/algorithm-%d", k.Algorithm), KindSigningKeyID,
			"a signing key of an algorithm other than Ed25519's: its id names the algorithm",
			SigningKeyIDInput{Algorithm: k.Algorithm, PublicKey: Hex(k.PublicKey)}, KeyIDOutput{KeyID: Hex(k.KeyID)})
	}

	keyID := func(c fzCiphertext) string {
		if c.Format == transport.FormatTenantKey || c.Format == transport.FormatTenantKeyAAD {
			return "tenant-key:" + hex.EncodeToString(c.KeyID)
		}
		return c.Version
	}
	formatNote := func(f byte) string {
		switch f {
		case transport.FormatVersionedAAD, transport.FormatTenantKeyAAD:
			return fmt.Sprintf("format %d: made with associated data", f)
		case transport.FormatTenantKey:
			return "format 3: a wrapped tenant's row"
		}
		return fmt.Sprintf("format %d", f)
	}
	for _, d := range m.Profiles {
		for j, c := range d.Ciphertexts {
			b.add(fmt.Sprintf("ciphertextKeyID/%s/%d", d.Name, j), KindCiphertextKeyID, formatNote(c.Format),
				CiphertextKeyIDInput{Ciphertext: Hex(c.Ciphertext)}, CiphertextKeyIDOutput{KeyID: keyID(c)})
		}
		for j, tk := range d.Tenants {
			for k, c := range tk.Ciphertexts {
				b.add(fmt.Sprintf("ciphertextKeyID/%s/tenant-%d/%d", d.Name, j, k), KindCiphertextKeyID, formatNote(c.Format),
					CiphertextKeyIDInput{Ciphertext: Hex(c.Ciphertext)}, CiphertextKeyIDOutput{KeyID: keyID(c)})
			}
		}
		for j, o := range d.Objects {
			h, segs, err := transport.ParseSegmented(transport.Release(), o.Object)
			if err != nil {
				t.Fatal(err)
			}
			for i, seg := range segs {
				b.add(fmt.Sprintf("ciphertextKeyID/%s/object-%d/segment-%d", d.Name, j, i), KindCiphertextKeyID,
					"a CPS1 object's segment: a format-5 ciphertext", CiphertextKeyIDInput{Ciphertext: seg},
					CiphertextKeyIDOutput{KeyID: o.Version})
				final := i == len(segs)-1
				flag, note := []byte{0}, "a segment that is not the last, with the caller's associated data"
				if final {
					flag, note = []byte{1}, "the last segment, with the caller's associated data"
				}
				spec := lpJoin([]byte("cipheron/v1|segment"), h.ObjectID, []byte{0, 0, 0, byte(i)}, flag, o.AssociatedData)
				b.add(fmt.Sprintf("segmentAssociatedData/%s/object-%d/%d", d.Name, j, i), KindSegmentAssociatedData, note,
					SegmentAssociatedDataInput{ObjectID: h.ObjectID, Index: uint32(i), Final: final, AssociatedData: Hex(o.AssociatedData)},
					AssociatedDataOutput{AssociatedData: spec})
			}
		}
		for _, j := range d.JSON {
			for _, p := range j.Pointers {
				spec := lpJoin([]byte("cipheron/v1|json-field"), []byte(j.RecordID), []byte(p), j.AssociatedData)
				b.add("jsonFieldAssociatedData/"+d.Name+"/"+j.RecordID+strings.ReplaceAll(p, "/", "."), KindJSONFieldAssociatedData,
					"the field's record and place, then the caller's associated data",
					JSONFieldAssociatedDataInput{RecordID: j.RecordID, Pointer: p, AssociatedData: Hex(j.AssociatedData)},
					AssociatedDataOutput{AssociatedData: spec})
			}
		}
	}
	// A segment with no caller associated data (the field is zero-length: still a field).
	b.add("segmentAssociatedData/no-associated-data", KindSegmentAssociatedData, "the last segment, no associated data",
		SegmentAssociatedDataInput{ObjectID: bytes.Repeat([]byte{7}, transport.ObjectIDLen), Index: 9, Final: true, AssociatedData: Hex{}},
		AssociatedDataOutput{AssociatedData: lpJoin([]byte("cipheron/v1|segment"), bytes.Repeat([]byte{7}, transport.ObjectIDLen),
			[]byte{0, 0, 0, 9}, []byte{1}, nil)})

	// A re-encryption's associated-data rule (owner decisions R8 and S2), written from the rule: the new ciphertext is
	// bound to the stored one's associated data, byte for byte. The stored ciphertext's associated data with none for
	// the new one is refused (false) — cipheron answers it INVALID_ARGUMENT, CIPHERON_ASSOCIATED_DATA; other associated
	// data for the new one, or some where the stored ciphertext has none, is a re-binding (false) — cipheron answers it
	// PERMISSION_DENIED to an entry not granted decrypt and encrypt; a client sends neither.
	row, archived := []byte("ledger/row-1"), []byte("archive/row-1")
	for _, c := range []struct {
		id, note   string
		aad, toAAD []byte
		valid      bool
	}{
		{"refused", "associated data for the stored ciphertext and none for the new one: refused, so a re-encryption " +
			"never drops the binding", row, nil, false},
		{"kept", "the same bytes for the new one: the binding kept", row, row, true},
		{"changed", "other bytes for the new one: a re-binding, which a client does not send", row, archived, false},
		{"none", "no associated data on either side", nil, nil, true},
		{"added", "associated data for the new one only: a re-binding, which a client does not send", nil, row, false},
	} {
		b.add("reEncryptAssociatedData/"+c.id, KindReEncryptAssociatedData, c.note,
			ReEncryptAssociatedDataInput{AssociatedData: c.aad, ToAssociatedData: c.toAAD}, ValidOutput{Valid: c.valid})
	}

	addTenantCases(t, b, &m)
	addRefusalCases(t, b, &m)
	addSignatureEdgeCases(b, &m, requestKey, responseKeys)
	addErrorClassCases(b)

	if requestKey == nil || ed25519.PublicKeySize != len(requestKey) {
		t.Fatal("the frozen request key")
	}
	return &Suite{
		Schema: SchemaID,
		Comment: "cipheron's conformance vectors, transcript version 1 (the protocol's one version). Derived from the frozen " +
			"set (spec/frozen: manifest.json and its keysets) and held to it by generate_test.go; " +
			"the reEncryptAssociatedData, tenantId and errorClass cases are written from the rules, and the layouts' " +
			"refusals from the frozen bytes and the layouts' registry. A refusal's output is {\"refused\": true}. " +
			"Every byte string is lower-case hex. ILLUSTRATIVE TEST KEYS ONLY. " +
			"Schema: vectors.schema.json; the layouts: spec/api.md, Conformance kit.",
		TranscriptVersion: transport.TranscriptVersion,
		Cases:             b.cases,
	}
}

func marshalSuite(t *testing.T, s *Suite) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestTheVectorsAreTheFrozenFilesDerivation: the embedded vectors file is, byte for byte, what the frozen set
// derives. With -update-conformance it writes that file instead.
func TestTheVectorsAreTheFrozenFilesDerivation(t *testing.T) {
	want := marshalSuite(t, buildSuite(t))
	if *updateConformance {
		if err := os.WriteFile(filepath.Join("..", "spec", VectorsFile), want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", VectorsFile, len(want))
		return
	}
	if !bytes.Equal(Vectors(), want) {
		t.Fatalf("%s is not what the frozen set derives (run with -update-conformance only when the frozen set gained a "+
			"value; never to make a reader pass)", VectorsFile)
	}
}
