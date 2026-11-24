package conformance

// reference.go — Reference: the kit's kinds computed by wire/transport, the implementation cipheron and its Go
// client use. It passes every case; the inputs and outputs it reads and writes are the kit's JSON shapes (the schema).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nnicora/cipheron/wire/transport"
)

// Hex is a byte string as the kit writes it: lower-case hex.
type Hex []byte

// MarshalJSON writes h as lower-case hex.
func (h Hex) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

// UnmarshalJSON reads lower-case hex (an upper-case digit is refused: the kit has one spelling).
func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for _, c := range s {
		if c >= 'A' && c <= 'F' {
			return fmt.Errorf("hex %q: lower-case only", s)
		}
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = d
	return nil
}

// The kinds' inputs and outputs.
type (
	// DigestInput is a digest case's input.
	DigestInput struct {
		Fields []Hex `json:"fields"`
	}
	// DigestOutput is its output.
	DigestOutput struct {
		Digest Hex `json:"digest"`
	}
	// RequestTranscriptInput is a requestTranscript case's input. No transcript kind takes a version: each binds the
	// protocol's one transcript version (the suite's transcriptVersion, transport.TranscriptVersion).
	RequestTranscriptInput struct {
		Profile     string `json:"profile"`
		Operation   string `json:"operation"`
		TimestampMS int64  `json:"timestampMs"`
		Nonce       Hex    `json:"nonce"`
		Digest      Hex    `json:"digest"`
	}
	// TranscriptOutput is the output of every transcript kind.
	TranscriptOutput struct {
		Transcript Hex `json:"transcript"`
	}
	// SignatureInput is a requestSignature or responseSignature case's input.
	SignatureInput struct {
		PublicKey  Hex `json:"publicKey"`
		Transcript Hex `json:"transcript"`
		Signature  Hex `json:"signature"`
	}
	// ValidOutput is the output of every verification kind.
	ValidOutput struct {
		Valid bool `json:"valid"`
	}
	// RequestSealInfoInput is a requestSealInfo case's input.
	RequestSealInfoInput struct {
		Profile          string `json:"profile"`
		Operation        string `json:"operation"`
		Tenant           string `json:"tenant"`
		RequestPublicKey Hex    `json:"requestPublicKey"`
	}
	// ResponseSealInfoInput is a responseSealInfo case's input.
	ResponseSealInfoInput struct {
		Profile   string `json:"profile"`
		Operation string `json:"operation"`
		Tenant    string `json:"tenant"`
	}
	// InfoOutput is the output of the seal-info kinds.
	InfoOutput struct {
		Info Hex `json:"info"`
	}
	// ResponseTranscriptInput is a responseTranscript case's input: ContextDigest is the answering cipheron's
	// key-context digest ("sha256:" and 64 hex digits, as a PublicKey answer gives it).
	ResponseTranscriptInput struct {
		Profile          string `json:"profile"`
		ContextDigest    string `json:"contextDigest"`
		Operation        string `json:"operation"`
		RequestNonce     Hex    `json:"requestNonce"`
		RequestSignature Hex    `json:"requestSignature"`
		RequestDigest    Hex    `json:"requestDigest"`
		ResponseDigest   Hex    `json:"responseDigest"`
	}
	// SigningKeyInput is one signing key of a signingKeysTranscript case: its state by name ("active",
	// "verifyOnly", "revoked"), which the transcript writes as its number (1, 2, 3).
	SigningKeyInput struct {
		KeyID     Hex    `json:"keyId"`
		State     string `json:"state"`
		PublicKey Hex    `json:"publicKey"`
	}
	// SigningKeysTranscriptInput is a signingKeysTranscript case's input.
	SigningKeysTranscriptInput struct {
		Profile       string            `json:"profile"`
		Tenancy       string            `json:"tenancy"`
		ContextDigest string            `json:"contextDigest"`
		Nonce         Hex               `json:"nonce"`
		Keys          []SigningKeyInput `json:"keys"`
	}
	// SigningKeyIDInput is a signingKeyID case's input; KeyIDOutput its output.
	SigningKeyIDInput struct {
		Algorithm uint32 `json:"algorithm"`
		PublicKey Hex    `json:"publicKey"`
	}
	KeyIDOutput struct {
		KeyID Hex `json:"keyId"`
	}
	// SegmentAssociatedDataInput is a segmentAssociatedData case's input.
	SegmentAssociatedDataInput struct {
		ObjectID       Hex    `json:"objectId"`
		Index          uint32 `json:"index"`
		Final          bool   `json:"final"`
		AssociatedData Hex    `json:"associatedData"`
	}
	// JSONFieldAssociatedDataInput is a jsonFieldAssociatedData case's input.
	JSONFieldAssociatedDataInput struct {
		RecordID       string `json:"recordId"`
		Pointer        string `json:"pointer"`
		AssociatedData Hex    `json:"associatedData"`
	}
	// AssociatedDataOutput is the output of the associated-data kinds.
	AssociatedDataOutput struct {
		AssociatedData Hex `json:"associatedData"`
	}
	// ReEncryptAssociatedDataInput is a reEncryptAssociatedData case's input: a re-encryption's associated_data (the
	// stored ciphertext's) and to_associated_data (the new one's), empty for none. Its output is a ValidOutput:
	// false for a request a client does not send — one that drops the associated data (cipheron refuses it to
	// everyone) or changes it (cipheron serves it only to an entry granted decrypt and encrypt).
	ReEncryptAssociatedDataInput struct {
		AssociatedData   Hex `json:"associatedData"`
		ToAssociatedData Hex `json:"toAssociatedData"`
	}
	// HPKESuiteInput names an HPKE suite by its RFC 9180 identifiers.
	HPKESuiteInput struct {
		KEM  uint16 `json:"kem"`
		KDF  uint16 `json:"kdf"`
		AEAD uint16 `json:"aead"`
	}
	// FingerprintInput is a fingerprint case's input: a profile's identity. Additional are the keys added to it
	// (none: left out); an identity with any, or with another suite or algorithm, has a version-2 fingerprint.
	FingerprintInput struct {
		Profile           string             `json:"profile"`
		Tenancy           string             `json:"tenancy"`
		HPKESuite         HPKESuiteInput     `json:"hpkeSuite"`
		HPKEPublicKey     Hex                `json:"hpkePublicKey"`
		ResponseAlgorithm uint32             `json:"responseAlgorithm"`
		ResponsePublicKey Hex                `json:"responsePublicKey"`
		Additional        []IdentityKeyInput `json:"additional,omitempty"`
	}
	// IdentityKeyInput is a key added to a profile's identity: its role (1 an HPKE key, 2 a response key), an HPKE
	// key's suite (zero for any other role) and any other role's algorithm (0 for an HPKE key).
	IdentityKeyInput struct {
		Role      uint32         `json:"role"`
		Suite     HPKESuiteInput `json:"suite"`
		Algorithm uint32         `json:"algorithm"`
		PublicKey Hex            `json:"publicKey"`
	}
	// FingerprintOutput is its output.
	FingerprintOutput struct {
		Fingerprint string `json:"fingerprint"`
	}
	// KeyStatementInput is a keyStatement case's input.
	KeyStatementInput struct {
		Statement   Hex    `json:"statement"`
		Signature   Hex    `json:"signature"`
		Profile     string `json:"profile"`
		Fingerprint string `json:"fingerprint"`
	}
	// CiphertextKeyIDInput is a ciphertextKeyID case's input.
	CiphertextKeyIDInput struct {
		Ciphertext Hex `json:"ciphertext"`
	}
	// CiphertextKeyIDOutput is its output: the master version id, or "tenant-key:<hex id>". Bytes that are not a
	// ciphertext of one of the protocol's formats are a RefusedOutput.
	CiphertextKeyIDOutput struct {
		KeyID string `json:"keyId"`
	}
	// RefusedOutput is the output of a case whose input an implementation must refuse (RefusableKinds): exactly
	// {"refused": true}. An error answer is not a refusal: the runner fails it, as any error.
	RefusedOutput struct {
		Refused bool `json:"refused"`
	}
	// TenantKeyInput is a tenantKey case's input: a tenant key blob, and the profile and tenant of the call it came with.
	TenantKeyInput struct {
		Blob    Hex    `json:"blob"`
		Profile string `json:"profile"`
		Tenant  string `json:"tenant"`
	}
	// TenantKeyOutput is what its header names (Created: Unix seconds) and the tenant key's fingerprint; a blob that is
	// not one of this layout, or is another tenant's or profile's, is a RefusedOutput.
	TenantKeyOutput struct {
		KeyID            Hex    `json:"keyId"`
		SigningPublicKey Hex    `json:"signingPublicKey"`
		WrappingVersion  string `json:"wrappingVersion"`
		Created          int64  `json:"created"`
		Fingerprint      string `json:"fingerprint"`
	}
	// TenantFingerprintInput is a tenantFingerprint case's input; its output is a FingerprintOutput.
	TenantFingerprintInput struct {
		Profile          string `json:"profile"`
		Tenant           string `json:"tenant"`
		KeyID            Hex    `json:"keyId"`
		SigningPublicKey Hex    `json:"signingPublicKey"`
	}
	// TenantSignedMessageInput is a tenantSignedMessage case's input.
	TenantSignedMessageInput struct {
		Profile string `json:"profile"`
		Tenant  string `json:"tenant"`
		Data    Hex    `json:"data"`
	}
	// MessageOutput is its output.
	MessageOutput struct {
		Message Hex `json:"message"`
	}
	// TenantIDInput is a tenantId case's input; its output is a ValidOutput: whether the string is a tenant id.
	TenantIDInput struct {
		Tenant string `json:"tenant"`
	}
	// ErrorClassInput is an errorClass case's input: a refusal's status code by its canonical name ("UNAVAILABLE"),
	// its google.rpc.ErrorInfo (none: left out) and its google.rpc.RetryInfo delay in milliseconds (none: left out).
	ErrorClassInput struct {
		Code         string          `json:"code"`
		ErrorInfo    *ErrorInfoInput `json:"errorInfo,omitempty"`
		RetryDelayMS *int64          `json:"retryDelayMs,omitempty"`
	}
	// ErrorInfoInput is a google.rpc.ErrorInfo's domain and reason.
	ErrorInfoInput struct {
		Domain string `json:"domain"`
		Reason string `json:"reason"`
	}
	// ErrorClassOutput is its output: the class, the retry rule ("never", "transient", "resign") and the least wait
	// before the retry the rule allows (the RetryInfo's delay; 0 with none, and when the rule is never).
	ErrorClassOutput struct {
		Class     string `json:"class"`
		Retry     string `json:"retry"`
		MinWaitMS int64  `json:"minWaitMs"`
	}
)

// statusCodes are the google.rpc.Code numbers by their canonical names.
var statusCodes = map[string]uint32{"OK": 0, "CANCELLED": 1, "UNKNOWN": 2, "INVALID_ARGUMENT": 3, "DEADLINE_EXCEEDED": 4,
	"NOT_FOUND": 5, "ALREADY_EXISTS": 6, "PERMISSION_DENIED": 7, "RESOURCE_EXHAUSTED": 8, "FAILED_PRECONDITION": 9,
	"ABORTED": 10, "OUT_OF_RANGE": 11, "UNIMPLEMENTED": 12, "INTERNAL": 13, "UNAVAILABLE": 14, "DATA_LOSS": 15,
	"UNAUTHENTICATED": 16}

// decodeStrict reads a case's input, refusing unknown fields (an input of another kind is an error, not a guess).
func decodeStrict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

type reference struct{}

// Reference is the kit computed by wire/transport.
func Reference() Implementation { return reference{} }

func (reference) Evaluate(_ context.Context, kind string, raw json.RawMessage) (json.RawMessage, error) {
	out, err := evaluate(kind, raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func evaluate(kind string, raw json.RawMessage) (any, error) {
	switch kind {
	case KindDigest:
		var in DigestInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		fields := make([][]byte, len(in.Fields))
		for i, f := range in.Fields {
			fields[i] = f
		}
		d := transport.Digest(fields...)
		return DigestOutput{Digest: d[:]}, nil
	case KindRequestTranscript:
		var in RequestTranscriptInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		d, err := digest32(in.Digest)
		if err != nil {
			return nil, err
		}
		return TranscriptOutput{Transcript: transport.RequestTranscript(transport.Release(), in.Profile, transport.Operation(in.Operation),
			in.TimestampMS, in.Nonce, d)}, nil
	case KindRequestSignature, KindResponseSignature:
		var in SignatureInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		verify := transport.VerifyResponse
		if kind == KindRequestSignature {
			verify = transport.VerifyRequest
		}
		return ValidOutput{Valid: verify(ed25519.PublicKey(in.PublicKey), in.Transcript, in.Signature) == nil}, nil
	case KindRequestSealInfo:
		var in RequestSealInfoInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return InfoOutput{Info: transport.RequestSealInfo(transport.Release(), in.Profile, transport.Operation(in.Operation), in.Tenant,
			ed25519.PublicKey(in.RequestPublicKey))}, nil
	case KindResponseSealInfo:
		var in ResponseSealInfoInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return InfoOutput{Info: transport.ResponseInfoTenant(transport.Release(), in.Profile, transport.Operation(in.Operation), in.Tenant)}, nil
	case KindResponseTranscript:
		var in ResponseTranscriptInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		rq, err := digest32(in.RequestDigest)
		if err != nil {
			return nil, err
		}
		rs, err := digest32(in.ResponseDigest)
		if err != nil {
			return nil, err
		}
		return TranscriptOutput{Transcript: transport.ResponseTranscript(transport.Release(), in.Profile, in.ContextDigest,
			transport.Operation(in.Operation), in.RequestNonce, in.RequestSignature, rq, rs)}, nil
	case KindSigningKeysTranscript:
		var in SigningKeysTranscriptInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		keys := make([]transport.SigningKey, len(in.Keys))
		for i, k := range in.Keys {
			keys[i] = transport.SigningKey{KeyID: k.KeyID, State: transport.SigningKeyState(k.State),
				PublicKey: ed25519.PublicKey(k.PublicKey)}
		}
		t, err := transport.SigningKeysTranscript(transport.Release(), in.Profile, transport.Tenancy(in.Tenancy), in.ContextDigest, in.Nonce, keys)
		if err != nil {
			return nil, err
		}
		return TranscriptOutput{Transcript: t}, nil
	case KindFingerprint:
		var in FingerprintInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		id := transport.Identity{Tenancy: transport.Tenancy(in.Tenancy), HPKE: in.HPKEPublicKey,
			HPKESuite: transport.HPKESuite{KEM: in.HPKESuite.KEM, KDF: in.HPKESuite.KDF, AEAD: in.HPKESuite.AEAD},
			Response:  ed25519.PublicKey(in.ResponsePublicKey), ResponseAlgorithm: transport.SignatureAlgorithm(in.ResponseAlgorithm)}
		for _, a := range in.Additional {
			id.Additional = append(id.Additional, transport.IdentityKey{Role: transport.IdentityKeyRole(a.Role),
				Suite:     transport.HPKESuite{KEM: a.Suite.KEM, KDF: a.Suite.KDF, AEAD: a.Suite.AEAD},
				Algorithm: transport.SignatureAlgorithm(a.Algorithm), PublicKey: a.PublicKey})
		}
		return FingerprintOutput{Fingerprint: transport.Fingerprint(in.Profile, id)}, nil
	case KindKeyStatement:
		var in KeyStatementInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		_, err := transport.VerifyKeyStatement(transport.Release(), in.Statement, in.Signature, in.Profile, in.Fingerprint)
		return ValidOutput{Valid: err == nil}, nil
	case KindCiphertextKeyID:
		var in CiphertextKeyIDInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		k, err := transport.ParseKeyID(transport.Release(), in.Ciphertext)
		if err != nil {
			return RefusedOutput{Refused: true}, nil //nolint:nilerr // the refusal is the case's output
		}
		return CiphertextKeyIDOutput{KeyID: k.String()}, nil
	case KindTenantKey:
		var in TenantKeyInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		h, err := transport.CheckTenantKey(transport.Release(), in.Blob, in.Profile, in.Tenant)
		if err != nil {
			return RefusedOutput{Refused: true}, nil //nolint:nilerr // the refusal is the case's output
		}
		return TenantKeyOutput{KeyID: h.KeyID, SigningPublicKey: Hex(h.SigningPublicKey), WrappingVersion: h.WrappingVersion,
			Created: h.Created.Unix(), Fingerprint: h.Fingerprint()}, nil
	case KindTenantFingerprint:
		var in TenantFingerprintInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return FingerprintOutput{Fingerprint: transport.TenantFingerprint(in.Profile, in.Tenant, in.KeyID,
			ed25519.PublicKey(in.SigningPublicKey))}, nil
	case KindTenantSignedMessage:
		var in TenantSignedMessageInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return MessageOutput{Message: transport.TenantSignedMessage(in.Profile, in.Tenant, in.Data)}, nil
	case KindTenantID:
		var in TenantIDInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return ValidOutput{Valid: transport.ValidTenant(in.Tenant)}, nil
	case KindErrorClass:
		var in ErrorClassInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		code, ok := statusCodes[in.Code]
		if !ok {
			return nil, fmt.Errorf("%q is not a status code's canonical name", in.Code)
		}
		r := transport.Refusal{Code: code}
		if in.ErrorInfo != nil {
			r.HasErrorInfo, r.ErrorDomain, r.Reason = true, in.ErrorInfo.Domain, in.ErrorInfo.Reason
		}
		class, rule := r.Classify()
		out := ErrorClassOutput{Class: string(class), Retry: string(rule)}
		if in.RetryDelayMS != nil && rule != transport.RetryNever {
			if *in.RetryDelayMS < 0 {
				return nil, errors.New("a RetryInfo delay is not negative")
			}
			out.MinWaitMS = *in.RetryDelayMS
		}
		return out, nil
	case KindSigningKeyID:
		var in SigningKeyIDInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return KeyIDOutput{KeyID: transport.SigningKeyIDOf(transport.SignatureAlgorithm(in.Algorithm), in.PublicKey)}, nil
	case KindSegmentAssociatedData:
		var in SegmentAssociatedDataInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return AssociatedDataOutput{AssociatedData: transport.SegmentAssociatedData(in.ObjectID, in.Index, in.Final,
			in.AssociatedData)}, nil
	case KindJSONFieldAssociatedData:
		var in JSONFieldAssociatedDataInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return AssociatedDataOutput{AssociatedData: transport.JSONFieldAssociatedData(in.RecordID, in.Pointer,
			in.AssociatedData)}, nil
	case KindReEncryptAssociatedData:
		var in ReEncryptAssociatedDataInput
		if err := decodeStrict(raw, &in); err != nil {
			return nil, err
		}
		return ValidOutput{Valid: transport.CheckReEncryptAssociatedData(in.AssociatedData, in.ToAssociatedData) == nil}, nil
	}
	return nil, ErrUnsupported
}

func digest32(b []byte) ([sha256.Size]byte, error) {
	var d [sha256.Size]byte
	if len(b) != sha256.Size {
		return d, errors.New("a digest is 32 bytes")
	}
	copy(d[:], b)
	return d, nil
}
