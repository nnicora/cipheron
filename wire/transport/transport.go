// Package transport is cipheron's wire contract: how a payload crosses cipheron's socket, the transcripts every
// request and answer is signed over, a profile's identity and its fingerprint, the signing-key list, the
// key-context digest, the tenant key blob and the ciphertext headers a client reads.
//
// A payload is sealed with HPKE (RFC 9180) single-shot, base mode, in the suite DHKEM(P-256, HKDF-SHA256) /
// HKDF-SHA256 / AES-256-GCM — every primitive the Go Cryptographic Module's own. A request payload (a plaintext to
// encrypt, data to sign) is sealed by the client to the profile's HPKE public key; a decrypted plaintext is sealed
// by cipheron to a one-time public key the client sends with the Decrypt request. Both directions bind the seal to
// its context through the HPKE info string (RequestSealInfo; ResponseInfo, ResponseInfoTenant in a perTenant profile,
// wrapped or derived): a request names the profile, the operation and the tenant, so a payload sealed to be encrypted
// cannot be opened as one to sign, in another profile or for another tenant; a response names the profile, the
// operation and the tenant. Requests and responses carry different direction labels, so neither can be presented as
// the other, and both bind the transcript version (TranscriptVersion), so neither opens under another layout's
// info. ReEncrypt and RewrapTenantKey seal nothing: they carry no plaintext.
//
// A REQUEST'S SEAL ALSO NAMES WHO SEALED IT (RequestSealInfo): the info string ends with the SHA-256 of the
// requester's request public key. Without it, a second caller of the profile that saw another's
// sealed payload (enc and sealed plaintext) could send it again under its OWN entry and request key — the payload
// opened, since it named only the profile, operation and tenant — have it encrypted, and decrypt the ciphertext with
// its own grant. Bound to the requester, the payload opens only for the caller whose request key signed the request.
//
// WHAT HPKE BASE MODE DOES NOT GIVE: sender authentication. Anyone holding the profile's public key can seal
// a request to it, and anyone can seal a response to the client's one-time key. Both directions are therefore
// authenticated separately, with Ed25519 over transcripts this package defines (auth.go):
//   - a request, by one of the caller entry's request keys (RequestTranscript: profile, transcript label,
//     timestamp, nonce, payload digest — the tenant and the tenant key blobs are digested fields), which the
//     server holds to a skew window and accepts once — so an intermediary holding the caller's connection identity
//     can neither forge, replay nor redirect it, to another payload or another tenant;
//   - every answer but PublicKey's — Encrypt, Decrypt, Sign, ReEncrypt, CreateTenantKey, RewrapTenantKey — by the
//     profile's response key (ResponseTranscript: profile, the answering cipheron's key-context digest, transcript
//     label, the request's nonce, the requester — the SHA-256 of the request's own signature —, the request's
//     digest, the response digest) — so a client that pinned the profile's identity (Fingerprint) detects any party
//     that is not cipheron, accepts an answer only to the request it sent itself, not to another caller's request
//     made under its nonce, and — pinning the key context (ContextDigest) — only from a cipheron on a pinned context;
//   - PublicKey's signing-key list and key-context digest, by the same response key (SigningKeysTranscript,
//     keys.go), so the pin of the identity keys — which never rotate — authenticates every signing key version.
//
// tenant.go is the tenant layer's part of the protocol: the tenancy, the tenant id, the tenant key blob's
// readable header, a tenant key's fingerprint and the tenant-bound signature of a derived profile. keys.go is the
// signing-key list and the key-context digest; ciphertext.go the stored ciphertexts' headers (which key a
// ciphertext was made under).
package transport

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/nnicora/cipheron/wire/format"
)

// The suite's RFC 9180 identifiers (section 7).
const (
	KEMID  uint16 = 0x0010 // DHKEM(P-256, HKDF-SHA256)
	KDFID  uint16 = 0x0001 // HKDF-SHA256
	AEADID uint16 = 0x0002 // AES-256-GCM
)

// EncLen is the length of an encapsulated key, and PublicKeyLen of a serialized public key, for
// DHKEM(P-256): an uncompressed point.
const (
	EncLen       = 65
	PublicKeyLen = 65
)

// Operation names what a request is for. A grantable operation (Grantable) is what a caller entry is given; every
// Operation but OpExport, OpImport and OpRetenant is also a transcript label — the operation field of
// RequestTranscript and ResponseTranscript — and the operation of the HPKE info strings of the operations that seal a
// payload (encrypt, decrypt, sign). OpExport, OpImport and OpRetenant are grants only: a cross-profile ReEncrypt is
// signed both ways under OpReEncrypt and authorized as OpExport on its source profile and OpImport on its target
// profile, and — when it changes the tenant — as OpRetenant on its source profile too.
type Operation string

const (
	// OpEncrypt is Encrypt.
	OpEncrypt Operation = "encrypt"
	// OpDecrypt is Decrypt.
	OpDecrypt Operation = "decrypt"
	// OpSign is Sign.
	OpSign Operation = "sign"
	// OpReEncrypt is ReEncrypt within one profile (and ReEncryptBatch), and the transcript label of every ReEncrypt,
	// the cross-profile one included. It never moves a ciphertext to another profile: that is OpExport + OpImport.
	OpReEncrypt Operation = "reencrypt"
	// OpExport is the grant a cross-profile ReEncrypt's SOURCE profile requires of the caller's entry there: the
	// ciphertext of that profile may leave it, re-encrypted under another profile's key. It is never a transcript
	// label (the request is signed as OpReEncrypt), and it gives no plaintext to anybody.
	OpExport Operation = "export"
	// OpImport is the grant a cross-profile ReEncrypt's TARGET profile requires of the caller's entry there: a
	// ciphertext of another profile may be re-encrypted into this one. Never a transcript label. It is a WRITE grant
	// into the target: whatever its holder can export from a source profile becomes an authentic ciphertext of the
	// target, so the importer — and every writer (encrypt) of the profiles it can export from — is trusted with the
	// target's integrity and the origin of its data as its own writers are. The move keeps the associated data
	// (CheckReEncryptAssociatedData), so the importer cannot choose a new binding during it.
	OpImport Operation = "import"
	// OpRetenant is the grant a cross-profile ReEncrypt that CHANGES THE TENANT requires of the caller's entry in its
	// SOURCE profile, in addition to OpExport there and OpImport on the target: the ciphertext may be re-encrypted
	// for another tenant than the one it was made for. A move changes the tenant when both profiles are perTenant
	// and the target tenant is not the source's, or when one profile is shared and the other perTenant (either
	// way). A move between two shared profiles, or within one tenant, needs no OpRetenant. Never a transcript label
	// (the request is signed as OpReEncrypt), and it gives no plaintext to anybody.
	OpRetenant Operation = "retenant"
	// OpProvision is CreateTenantKey's operation and transcript label, and the operation RewrapTenantKey is
	// authorized as (its transcript label is OpRewrapTenantKey).
	OpProvision Operation = "provision"
	// OpRewrapTenantKey is RewrapTenantKey's transcript label. It is NOT an operation a caller entry is given:
	// RewrapTenantKey is authorized as OpProvision (Grant). The label differs from CreateTenantKey's, so a
	// signed request or answer of one is never taken for the other's, although their digests have one form.
	OpRewrapTenantKey Operation = "rewrap-tenant-key"

	// The batch operations' transcript labels (batch.go). None is an operation a caller entry is given: each is
	// authorized as its single operation (Grant).
	OpEncryptBatch         Operation = "encrypt-batch"
	OpDecryptBatch         Operation = "decrypt-batch"
	OpReEncryptBatch       Operation = "reencrypt-batch"
	OpRewrapTenantKeyBatch Operation = "rewrap-tenant-key-batch"
)

// Grantable reports whether op is one of the operations a caller entry may be given: encrypt, decrypt, sign,
// reencrypt, provision, export, import and retenant.
func (op Operation) Grantable() bool {
	switch op {
	case OpEncrypt, OpDecrypt, OpSign, OpReEncrypt, OpProvision, OpExport, OpImport, OpRetenant:
		return true
	}
	return false
}

// Grant is the operation a request under transcript label op is authorized as: OpProvision for
// OpRewrapTenantKey and OpRewrapTenantKeyBatch, the single operation for a batch label, op itself for a grantable
// op, and "" for anything else.
func (op Operation) Grant() Operation {
	switch {
	case op == OpRewrapTenantKey, op == OpRewrapTenantKeyBatch:
		return OpProvision
	case op == OpEncryptBatch:
		return OpEncrypt
	case op == OpDecryptBatch:
		return OpDecrypt
	case op == OpReEncryptBatch:
		return OpReEncrypt
	case op.Grantable():
		return op
	}
	return ""
}

// Batch reports whether op is a batch operation's transcript label.
func (op Operation) Batch() bool {
	switch op {
	case OpEncryptBatch, OpDecryptBatch, OpReEncryptBatch, OpRewrapTenantKeyBatch:
		return true
	}
	return false
}

// GrantableOperations are the operations a caller entry may be given, in a fixed order.
func GrantableOperations() []Operation {
	return []Operation{OpEncrypt, OpDecrypt, OpSign, OpReEncrypt, OpProvision, OpExport, OpImport, OpRetenant}
}

// ChangesTenant reports whether a cross-profile ReEncrypt out of a profile of tenancy from, for tenant (empty in a
// shared profile), into a profile of tenancy to, for toTenant, changes the tenant — and so needs OpRetenant on its
// source profile. toTenant is the target tenant the move is made for: the request's to_tenant, or the
// source's tenant when to_tenant is empty and the target is perTenant. Both perTenant: it changes when toTenant is
// not tenant (derived profiles alike). One shared and the other perTenant, either way: it always changes. Two shared
// profiles: never. A tenancy that is not one of the three changes it.
func ChangesTenant(from Tenancy, tenant string, to Tenancy, toTenant string) bool {
	switch {
	case !from.Valid() || !to.Valid():
		return true
	case from.PerTenant() && to.PerTenant():
		return toTenant != tenant
	}
	return from.PerTenant() != to.PerTenant()
}

// The machine-readable reasons of cipheron's refusals: every such answer carries a google.rpc.ErrorInfo status
// detail {reason: Reason…, domain: ErrorDomain} — on gRPC as a status detail, through the HTTP gateway in the
// JSON google.rpc.Status body's "details". A client decides on the reason, never on the message, which is for
// humans and may change.
const (
	// ErrorDomain is the ErrorInfo domain of every reason below.
	ErrorDomain = "cipheron.v1"
	// ReasonKeyVersionUnavailable: INVALID_ARGUMENT (HTTP 400) — the ciphertext, or the tenant key blob, was made
	// under a master key version the configuration does not list (a version removed). Not corruption: listed again,
	// it reads again.
	ReasonKeyVersionUnavailable = "CIPHERON_KEY_VERSION_UNAVAILABLE"
	// ReasonBusy: RESOURCE_EXHAUSTED (HTTP 429) — cipheron is at a limit of requests in flight, or has no locked
	// memory for the request's key now; retry later. The answer carries a google.rpc.RetryInfo too.
	ReasonBusy = "CIPHERON_BUSY"
	// ReasonNoWriter: UNAVAILABLE (HTTP 503) — no master key version writes at this cipheron's clock (it is
	// before the activateAt of every active version: a clock stepped back, or a configuration whose only writer is
	// still to come), so it makes no new ciphertext or tenant key now. Not the request's fault, and not the
	// ciphertext's: reading still works, and another replica (whose clock is right) may serve the write.
	ReasonNoWriter = "CIPHERON_NO_WRITER"
	// ReasonAssociatedData: INVALID_ARGUMENT (HTTP 400) — a ciphertext made with associated data (format 5 or 6) sent
	// without any, or one made without (format 3 or 4) sent with some; or a re-encryption with associated_data and no
	// to_associated_data (CheckReEncryptAssociatedData: ErrTargetAssociatedData). Wrong associated data is not this
	// reason: it fails the tag, as any modification does ("could not be decrypted"). Nor is a re-encryption to other
	// associated data by a caller entry not granted decrypt and encrypt (ErrAssociatedDataChanged): that is
	// PERMISSION_DENIED, the grants' answer.
	ReasonAssociatedData = "CIPHERON_ASSOCIATED_DATA"
	// ReasonBatchLimit: INVALID_ARGUMENT (HTTP 400) — a batch over the configured limits; the ErrorInfo metadata names
	// them ("maxItems", "maxBytes": decimal numbers).
	ReasonBatchLimit = "CIPHERON_BATCH_LIMIT"
	// ReasonAuditUnavailable: UNAVAILABLE (HTTP 503) — cipheron's audit trail could not record the request (its sinks
	// fail or are behind, and the configuration refuses unrecorded requests); nothing was done, and the answer
	// carries a google.rpc.RetryInfo. Retry here later, or on another replica.
	ReasonAuditUnavailable = "CIPHERON_AUDIT_UNAVAILABLE"
	// ReasonProfileSealed: UNAVAILABLE (HTTP 503) — the profile is sealed on this replica (unseal.partial: its master
	// versions did not unseal at the start, and are being retried); nothing was done, and the answer carries a
	// google.rpc.RetryInfo. Given only to a caller the profile lists. Retry later, or on another replica.
	ReasonProfileSealed = "CIPHERON_PROFILE_SEALED"
	// ReasonStarting: UNAVAILABLE (HTTP 503) — a request whose signature verified carries a timestamp before the
	// instant the answering cipheron process started (its start barrier): that process cannot know whether one
	// alive before it served the same request, so it serves nothing signed before its start. Nothing was done and
	// nothing was recorded; the answer carries a google.rpc.RetryInfo of how far the timestamp is before the start.
	// Sign the request again, with a new timestamp and nonce, and send it again: safe for every operation,
	// CreateTenantKey and RewrapTenantKey included. The client library does so once by itself.
	ReasonStarting = "CIPHERON_STARTING"
)

// ErrSigningKeyRevoked is a signature, or a Sign answer, under a signing key the profile lists as revoked: never a
// valid signature, whatever the bytes. The key's public part stays listed so the refusal is named.
var ErrSigningKeyRevoked = errors.New("cipheron: the signing key is revoked")

// ErrOpen is what Open answers for any payload it cannot open: a wrong key, a wrong info string, a
// modified enc or ciphertext. It names no cause, on purpose.
var ErrOpen = errors.New("cipheron: the sealed payload could not be opened")

// KEM is the suite's KEM.
func KEM() hpke.KEM { return hpke.DHKEM(ecdh.P256()) }

// KDF is the suite's KDF.
func KDF() hpke.KDF { return hpke.HKDFSHA256() }

// AEAD is the suite's AEAD.
func AEAD() hpke.AEAD { return hpke.AES256GCM() }

// ResponseInfo is the HPKE info string of a payload cipheron seals to a client's one-time key for op in a shared
// profile. It is ResponseInfoTenant(profile, op, "").
func ResponseInfo(p *format.Policy, profile string, op Operation) []byte {
	return ResponseInfoTenant(p, profile, op, "")
}

// RequestInfoTenant is the context part of RequestSealInfo — never a seal info by itself: it carries no transcript
// version and no requester, and cipheron opens no request under it. It is "cipheron/v1|request|<profile>|<op>|<tenant>"
// for op in profile, for tenant in a perTenant profile (wrapped or derived); for a shared profile (tenant "") the tenant
// and its separator are left out: "cipheron/v1|request|<profile>|<op>". Profile names cannot contain "|"
// (ValidProfile) and the operations are fixed words without one, so the profile and the operation end at
// their "|" and the tenant is the rest of the string — a tenant id may contain "|" (ValidTenant): one context
// string names one (profile, operation, tenant).
func RequestInfoTenant(profile string, op Operation, tenant string) []byte {
	return info(false, profile, op, tenant, 0)
}

// ResponseInfoTenant is the HPKE info string a Decrypt answer's plaintext (and each DecryptBatch item's) is sealed
// under, to the client's one-time key, for tenant in a perTenant profile (wrapped or derived; "" in a shared one):
//
//	"cipheron/v1|response|<profile>|<op>|<tenant>" lp(TranscriptVersion: 4 bytes)
//
// lp being a 4-byte big-endian length and the bytes; for a shared profile (tenant "") the tenant and its separator
// are left out of the context string. Neither a profile, an operation nor a tenant id holds a 0x00 byte, so the
// context string ends where the version's length begins: one info string names one (profile, operation, tenant)
// under this protocol's transcript version, and a payload sealed under another layout's info does not open.
func ResponseInfoTenant(p *format.Policy, profile string, op Operation, tenant string) []byte {
	s := writtenTranscripts(p)
	return s.Codec().responseSealInfo(s.Version(), profile, op, tenant)
}

// responseSealInfoV1 is ResponseInfoTenant's layout at transcript version 1, binding v.
func responseSealInfoV1(v uint32, profile string, op Operation, tenant string) []byte {
	return transcript(info(true, profile, op, tenant, 4+4)).addUint32(v)
}

// RequesterKeyHash is the requester field of a request's seal info (RequestSealInfo): the SHA-256 of the
// requester's Ed25519 request public key (32 bytes), or empty when it signs with none (a socket entry without a
// request key).
func RequesterKeyHash(requestKey ed25519.PublicKey) []byte {
	if len(requestKey) == 0 {
		return nil
	}
	sum := sha256.Sum256(requestKey)
	return sum[:]
}

// RequestSealInfo is the HPKE info string a request payload — Encrypt's plaintext, Sign's data — is sealed under:
//
//	RequestInfoTenant(profile, op, tenant) lp(TranscriptVersion: 4 bytes) lp(RequesterKeyHash(requestKey))
//
// lp being a 4-byte big-endian length and the bytes: the requester field is 32 bytes, or zero-length for a requester
// without a request key. Neither a profile, an operation nor a tenant id holds a 0x00 byte, so the context string ends
// where the version's length begins, and one info string names one (profile, operation, tenant, requester).
// requestKey is the public key that signs the request: the client passes its own, cipheron the entry key that
// verified the request's signature (none for an entry without a request key). A payload sealed by one caller does
// not open in a request another caller signed.
func RequestSealInfo(p *format.Policy, profile string, op Operation, tenant string, requestKey ed25519.PublicKey,
) []byte {
	s := writtenTranscripts(p)
	return s.Codec().requestSealInfo(s.Version(), profile, op, tenant, RequesterKeyHash(requestKey))
}

// requestSealInfoV1 is RequestSealInfo's layout at transcript version 1, binding v, of the requester field requester
// (RequesterKeyHash).
func requestSealInfoV1(v uint32, profile string, op Operation, tenant string, requester []byte) []byte {
	t := info(false, profile, op, tenant, 4+4+4+len(requester))
	return transcript(t).addUint32(v).add(requester)
}

// info is the context string "cipheron/v1|<request|response|><profile>|<op>[|<tenant>]" (format.AppendRequestContext,
// format.AppendResponseContext), built in one buffer with room for spare bytes more (the version field, and
// RequestSealInfo's requester field).
func info(response bool, profile string, op Operation, tenant string, spare int) []byte {
	// contextRoom holds the namespace, the direction and the two separators.
	const contextRoom = 32
	b := make([]byte, 0, contextRoom+len(profile)+len(op)+len(tenant)+spare)
	if response {
		return format.AppendResponseContext(b, profile, string(op), tenant)
	}
	return format.AppendRequestContext(b, profile, string(op), tenant)
}

// ParsePublicKey reads a serialized public key of the suite's KEM.
func ParsePublicKey(b []byte) (hpke.PublicKey, error) {
	if len(b) != PublicKeyLen {
		return nil, fmt.Errorf("cipheron: a public key is %d bytes, not %d", PublicKeyLen, len(b))
	}
	pk, err := KEM().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("cipheron: not a P-256 public key: %w", err)
	}
	return pk, nil
}

// NewOneTimeKey generates the key pair a client sends the public half of with a Decrypt request. It is for
// one request: generate a new one for the next.
func NewOneTimeKey() (hpke.PrivateKey, error) { return KEM().GenerateKey() }

// Seal seals plaintext to pk under info and returns the encapsulated key and the ciphertext.
func Seal(pk hpke.PublicKey, info, plaintext []byte) (enc, ciphertext []byte, err error) {
	if pk == nil || pk.KEM().ID() != KEMID {
		return nil, nil, errors.New("cipheron: the public key is not of the suite's KEM")
	}
	enc, sender, err := hpke.NewSender(pk, KDF(), AEAD(), info)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err = sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ciphertext, nil
}

// Open opens a payload sealed to sk under info. Any failure is ErrOpen.
func Open(sk hpke.PrivateKey, info, enc, ciphertext []byte) ([]byte, error) {
	if sk == nil || sk.KEM().ID() != KEMID || len(enc) != EncLen {
		return nil, ErrOpen
	}
	recipient, err := hpke.NewRecipient(enc, sk, KDF(), AEAD(), info)
	if err != nil {
		return nil, ErrOpen
	}
	plaintext, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}
