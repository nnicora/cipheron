package transport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"

	"github.com/nnicora/cipheron/wire/format"
)

// NonceLen is the length of a request's request_nonce: 128 random bits, new for every request.
const NonceLen = 16

// SignatureLen is the length of every Ed25519 signature on the wire (RFC 8032).
const SignatureLen = ed25519.SignatureSize

// The labels that open each transcript and the fingerprint. Each names what it signs and the protocol, so no
// signature or digest of one kind is ever accepted as another.
//
// The three signed transcripts' labels contain "_", which no profile name can; the transcript version
// (TranscriptVersion, transcripts.go) follows each of them as a field. Each is in the protocol's namespace, from the
// purpose table (format's labels.go).
var (
	requestLabel     = format.LabelSignedRequest.String()
	responseLabel    = format.LabelSignedResponse.String()
	digestLabel      = format.LabelDigest.String()
	fingerprintLabel = format.LabelFingerprint.String()
	// fingerprint2Label opens fingerprint derivation 2 (Fingerprint): an identity that is not classical.
	fingerprint2Label = format.LabelFingerprint2.String()
	// tenantFingerprintLabel opens a tenant key's fingerprint (TenantFingerprint).
	tenantFingerprintLabel = format.LabelTenantFingerprint.String()
	// signingKeysLabel opens the signing-key list's transcript (SigningKeysTranscript).
	signingKeysLabel = format.LabelSignedKeys.String()
	// signingKeyIDLabel opens a signing key's id (SigningKeyID).
	signingKeyIDLabel = format.LabelSigningKeyID.String()
	// contextLabel opens the key-context digest (ContextDigest).
	contextLabel = format.LabelContext.String()
	// tenantSignatureLabel opens a derived profile's tenant-bound signed message (TenantSignedMessage).
	tenantSignatureLabel = format.LabelTenantSignature.String()
)

// FingerprintPrefix opens every fingerprint string, and the key-context digest.
const FingerprintPrefix = "sha256:"

// ErrAuth is what VerifyRequest, VerifyResponse, VerifySigningKeys and VerifyTenant answer for any signature that does not verify. It names no
// cause, on purpose.
var ErrAuth = errors.New("cipheron: the signature does not verify")

// transcript is a length-prefixed encoding: each field is its length (4 bytes, big-endian) followed by its
// bytes, so no two different field lists encode the same.
type transcript []byte

// newTranscript is an empty transcript with room for fields of the given lengths (each with its 4-byte length):
// built in one allocation instead of growing field by field.
func newTranscript(lens ...int) transcript {
	n := 0
	for _, l := range lens {
		n += 4 + l
	}
	return make(transcript, 0, n)
}

func (t transcript) add(b []byte) transcript {
	t = binary.BigEndian.AppendUint32(t, uint32(len(b)))
	return append(t, b...)
}

func (t transcript) addString(s string) transcript {
	t = binary.BigEndian.AppendUint32(t, uint32(len(s)))
	return append(t, s...)
}

// addUint32 adds v as a field: 4 bytes big-endian, behind its length (4).
func (t transcript) addUint32(v uint32) transcript {
	t = binary.BigEndian.AppendUint32(t, 4)
	return binary.BigEndian.AppendUint32(t, v)
}

// Digest is the SHA-256 of fields, length-prefixed: what a transcript commits to a request's or a response's
// payload with. Its fields, per transcript label (through the functions below, which name them):
//
//	request  encrypt            enc, sealed_plaintext, tenant, tenant_key            EncryptDigest
//	request  decrypt            recipient_public_key, ciphertext, tenant, tenant_key DecryptDigest
//	request  sign               enc, sealed_data, tenant, tenant_key                 SignDigest
//	request  reencrypt          ciphertext, tenant, tenant_key, to_tenant_key        ReEncryptDigest
//	request  provision          tenant, tenant_key (empty: CreateTenantKey has none) ProvisionDigest
//	request  rewrap-tenant-key  tenant, tenant_key                                   RewrapTenantKeyDigest
//	response encrypt            ciphertext                                           CiphertextResponseDigest
//	response decrypt            recipient_public_key, enc, sealed_plaintext          Digest
//	response sign               signature, key_id                                    SignResponseDigest
//	response reencrypt          ciphertext                                           CiphertextResponseDigest
//	response provision          tenant_key, signing_public_key, fingerprint          TenantKeyResponseDigest
//	response rewrap-tenant-key  tenant_key, signing_public_key, fingerprint          TenantKeyResponseDigest
//
// The optional fields are appended ONLY when the request carries them, so a request that uses none is digested
// exactly as above: associated_data after Encrypt's and Decrypt's fields
// (EncryptDigestAAD, DecryptDigestAAD); ReEncrypt's group associated_data, to_associated_data, to_profile,
// to_tenant (ReEncryptDigestExt). The batch operations' digests are batch.go's.
//
// tenant and tenant_key are empty when a request does not carry them (a shared profile's; tenant_key in a derived
// profile), and are digested all the same: every request digest has its tenant fields, so a request of one
// tenancy is never another's. Digests of one form (encrypt and sign; provision and rewrap-tenant-key; the encrypt
// and reencrypt responses) are told apart by the transcript label they are signed under.
//
// The fields are hashed in place — each one's length, then its bytes, written to the hash — and never copied:
// a field may be a whole request (a ciphertext, a sealed plaintext of up to 64 MiB), and both cipheron and its
// clients digest every request and every answer. The digest is the SHA-256 of exactly the bytes the length-prefixed
// encoding (transcript) of the label and the fields is.
func Digest(fields ...[]byte) [sha256.Size]byte {
	h := sha256.New()
	var n [4]byte
	write := func(b []byte) {
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:]) // a hash.Hash never returns an error
		h.Write(b)
	}
	write([]byte(digestLabel))
	for _, f := range fields {
		write(f)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// EncryptDigest is an Encrypt request's digest (Digest's table): tenant and tenantKey are empty when the request
// does not carry them.
func EncryptDigest(enc, sealedPlaintext []byte, tenant string, tenantKey []byte) [sha256.Size]byte {
	return Digest(enc, sealedPlaintext, []byte(tenant), tenantKey)
}

// DecryptDigest is a Decrypt request's digest (Digest's table).
func DecryptDigest(recipientPublicKey, ciphertext []byte, tenant string, tenantKey []byte) [sha256.Size]byte {
	return Digest(recipientPublicKey, ciphertext, []byte(tenant), tenantKey)
}

// SignDigest is a Sign request's digest (Digest's table).
func SignDigest(enc, sealedData []byte, tenant string, tenantKey []byte) [sha256.Size]byte {
	return Digest(enc, sealedData, []byte(tenant), tenantKey)
}

// ReEncryptDigest is a ReEncrypt request's digest (Digest's table): the ciphertext, the tenant, the tenant key
// blob the ciphertext was made under and the one it is to be made under (both empty outside a wrapped profile).
func ReEncryptDigest(ciphertext []byte, tenant string, tenantKey, toTenantKey []byte) [sha256.Size]byte {
	return Digest(ciphertext, []byte(tenant), tenantKey, toTenantKey)
}

// MaxAssociatedDataLen bounds a request's caller associated data (associated_data, to_associated_data): 64 KiB.
// It is context — a row's key, a record's type — bound into the ciphertext, not data to encrypt.
const MaxAssociatedDataLen = 64 << 10

// EncryptDigestAAD is an Encrypt request's (or an EncryptBatch item's) digest with its associated data: EncryptDigest
// when aad is empty, else Digest's table's fields followed by aad as one more field. A digest of five fields is never
// one of four, so no request with associated data is signed as one without.
func EncryptDigestAAD(enc, sealedPlaintext []byte, tenant string, tenantKey, aad []byte) [sha256.Size]byte {
	if len(aad) == 0 {
		return EncryptDigest(enc, sealedPlaintext, tenant, tenantKey)
	}
	return Digest(enc, sealedPlaintext, []byte(tenant), tenantKey, aad)
}

// DecryptDigestAAD is a Decrypt request's (or a DecryptBatch item's) digest with its associated data, as
// EncryptDigestAAD.
func DecryptDigestAAD(recipientPublicKey, ciphertext []byte, tenant string, tenantKey, aad []byte) [sha256.Size]byte {
	if len(aad) == 0 {
		return DecryptDigest(recipientPublicKey, ciphertext, tenant, tenantKey)
	}
	return Digest(recipientPublicKey, ciphertext, []byte(tenant), tenantKey, aad)
}

// ReEncryptExt is a ReEncrypt request's fields beyond Digest's table: the associated data of the stored ciphertext
// and of the new one, and the cross-profile target (profile, tenant). The zero value is none of them.
type ReEncryptExt struct {
	AssociatedData, ToAssociatedData []byte
	ToProfile, ToTenant              string
}

// empty reports whether e carries nothing.
func (e ReEncryptExt) empty() bool {
	return len(e.AssociatedData) == 0 && len(e.ToAssociatedData) == 0 && e.ToProfile == "" && e.ToTenant == ""
}

// ReEncryptDigestExt is a ReEncrypt request's (or a ReEncryptBatch item's) digest with its extension: ReEncryptDigest
// when e is empty, else Digest's table's four fields followed by ALL FOUR of e's (associated data, target associated
// data, target profile, target tenant — each length-prefixed, empty ones too), so no field of e can be taken for
// another and a request carrying any of them is never signed as one carrying none.
func ReEncryptDigestExt(ciphertext []byte, tenant string, tenantKey, toTenantKey []byte, e ReEncryptExt) [sha256.Size]byte {
	if e.empty() {
		return ReEncryptDigest(ciphertext, tenant, tenantKey, toTenantKey)
	}
	return Digest(ciphertext, []byte(tenant), tenantKey, toTenantKey, e.AssociatedData, e.ToAssociatedData,
		[]byte(e.ToProfile), []byte(e.ToTenant))
}

// ProvisionDigest is a CreateTenantKey request's digest: the tenant, and an empty tenant key (Digest's table).
func ProvisionDigest(tenant string) [sha256.Size]byte {
	return Digest([]byte(tenant), nil)
}

// RewrapTenantKeyDigest is a RewrapTenantKey request's digest: the tenant and its blob (Digest's table). Its form is
// ProvisionDigest's with a blob; the transcript label (OpRewrapTenantKey) tells the two apart.
func RewrapTenantKeyDigest(tenant string, tenantKey []byte) [sha256.Size]byte {
	return Digest([]byte(tenant), tenantKey)
}

// CiphertextResponseDigest is the response digest of an Encrypt or ReEncrypt answer: the ciphertext.
func CiphertextResponseDigest(ciphertext []byte) [sha256.Size]byte {
	return Digest(ciphertext)
}

// SignResponseDigest is the response digest of a Sign answer: the signature and the id of the key that made it.
func SignResponseDigest(signature, keyID []byte) [sha256.Size]byte {
	return Digest(signature, keyID)
}

// TenantKeyResponseDigest is the response digest of a CreateTenantKey or RewrapTenantKey answer: the tenant key
// blob, its signing public key and its fingerprint (TenantFingerprint).
func TenantKeyResponseDigest(tenantKey, signingPublicKey []byte, fingerprint string) [sha256.Size]byte {
	return Digest(tenantKey, signingPublicKey, []byte(fingerprint))
}

// RequestTranscript is what a caller's request key signs (RequestAuth.signature):
//
//	lp("cipheron/v1|signed_request") lp(TranscriptVersion: 4 bytes) lp(profile) lp(operation)
//	lp(timestamp: 8 bytes) lp(nonce) lp(digest)
//
// the operation being the transcript label (OpRewrapTenantKey for RewrapTenantKey), the timestamp the client's
// (milliseconds, big-endian two's complement), the nonce the request's and the digest that of its payload fields
// (Digest's table).
func RequestTranscript(p *format.Policy, profile string, op Operation, timestampMS int64, nonce []byte,
	digest [sha256.Size]byte,
) []byte {
	s := writtenTranscripts(p)
	return s.Codec().request(s.Version(), profile, op, timestampMS, nonce, digest)
}

// requestTranscriptV1 is RequestTranscript's layout at transcript version 1, binding v.
func requestTranscriptV1(v uint32, profile string, op Operation, timestampMS int64, nonce []byte,
	digest [sha256.Size]byte,
) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestampMS))
	return newTranscript(len(requestLabel), 4, len(profile), len(op), len(ts), len(nonce), len(digest)).
		addString(requestLabel).addUint32(v).addString(profile).addString(string(op)).
		add(ts[:]).add(nonce).add(digest[:])
}

// Requester is the response transcript's requester field for a request whose auth.signature is
// requestSignature: its SHA-256 (32 bytes), or EMPTY (a zero-length field, never 32 zero bytes) when the
// request carried no signature — no auth, or an auth with an empty signature. Length-prefixed in the transcript,
// the two forms can never be taken for each other.
func Requester(requestSignature []byte) []byte {
	if len(requestSignature) == 0 {
		return nil
	}
	sum := sha256.Sum256(requestSignature)
	return sum[:]
}

// ResponseTranscript is what the profile's response key signs (response_signature):
//
//	label          "cipheron/v1|signed_response"
//	version        TranscriptVersion, 4 bytes big-endian
//	profile         the request's profile
//	context digest the key-context digest (ContextDigest, "sha256:" and 64 hex digits) of the cipheron that answered
//	operation      the transcript label: encrypt, decrypt, sign, reencrypt, provision (CreateTenantKey) or
//	               rewrap-tenant-key (RewrapTenantKey)
//	request nonce  the request's request_nonce
//	requester      Requester(the request's auth.signature): its SHA-256, empty when it carried none
//	request digest Digest of the REQUEST's payload fields (the same digest RequestTranscript signs)
//	response digest Digest of the response's fields
//
// each length-prefixed. requestSignature is the auth.signature the request carried — the server passes what it
// received, the client what it sent — and the transcript holds Requester of it.
//
// The context digest binds every answer to the KEY CONTEXT of the cipheron that made it — its listed master versions
// and their keys, its keyset and its published and revoked signing keys — not only to the profile's identity, which
// every cipheron of the profile shares. A client verifies an answer under the digests it pins
// (WithContextDigestPin), so an answer made by a replica on another context — a stale or drifted shared file, a
// rollout the pins do not name — does not verify, whichever path carried it; without a pin it verifies under the
// digests the profile's verified PublicKey answers gave it. The digest is not sent with the answer: the client
// supplies it, as it supplies the nonce and the request digest.
//
// The request digest binds an answer to the request it answers, not only to its nonce: without it, a party in
// the path that is itself a caller of the profile could send cipheron its OWN request under the victim's nonce
// (and, for Decrypt, the victim's one-time recipient key) and hand the victim the genuinely signed answer — a
// plaintext of a ciphertext the victim never sent, or a ciphertext of data the victim never sealed.
//
// The requester binds it to WHO asked. A request whose fields all equal the victim's — CreateTenantKey's are
// only the tenant — has the victim's request digest; an insider with its own entry and request key could send
// such a request under the victim's nonce, signed by ITSELF, and hand the victim cipheron's answer to it (a
// tenant key the insider asked for). Its signature is not the victim's, so its answer's requester is not
// either, and the victim's check — against the signature it sent — fails. The only request whose answer
// verifies for the victim is one carrying the victim's own signature over the victim's own transcript: the
// victim's request, relayed. (An entry without a request key, whose signature cipheron does not check, could
// attach the victim's signature bytes; with the request digest and nonce equal too that is the victim's request
// again, relayed under another identity.)
//
// The transcript version follows the label, so no answer signed under this layout verifies as one of another.
func ResponseTranscript(p *format.Policy, profile, contextDigest string, op Operation, requestNonce,
	requestSignature []byte, requestDigest, responseDigest [sha256.Size]byte,
) []byte {
	s := writtenTranscripts(p)
	return s.Codec().response(s.Version(), profile, contextDigest, op, requestNonce, Requester(requestSignature),
		requestDigest, responseDigest)
}

// responseTranscriptV1 is ResponseTranscript's layout at transcript version 1, binding v, of the requester field
// requester (Requester).
func responseTranscriptV1(v uint32, profile, contextDigest string, op Operation, requestNonce, requester []byte,
	requestDigest, responseDigest [sha256.Size]byte,
) []byte {
	return newTranscript(len(responseLabel), 4, len(profile), len(contextDigest), len(op), len(requestNonce),
		len(requester), len(requestDigest), len(responseDigest)).
		addString(responseLabel).addUint32(v).addString(profile).addString(contextDigest).
		addString(string(op)).add(requestNonce).add(requester).add(requestDigest[:]).add(responseDigest[:])
}

// VerifyRequest checks a RequestAuth signature. Any failure is ErrAuth.
func VerifyRequest(pub ed25519.PublicKey, transcript, signature []byte) error {
	return verify(pub, transcript, signature)
}

// VerifyResponse checks a response_signature. Any failure is ErrAuth.
func VerifyResponse(pub ed25519.PublicKey, transcript, signature []byte) error {
	return verify(pub, transcript, signature)
}

func verify(pub ed25519.PublicKey, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != SignatureLen || !ed25519.Verify(pub, msg, sig) {
		return ErrAuth
	}
	return nil
}

// Identity is what a profile's fingerprint covers: its tenancy and the keys that never rotate — the HPKE key
// requests are sealed to and the response key every answer is signed by. PublicKey answers them as
// hpke_public_key, response_public_key and tenancy. The signing keys are not in it: they rotate, and their list is
// authenticated by the response key (SigningKeysTranscript), so rotating one never changes the identity.
type Identity struct {
	Tenancy Tenancy
	HPKE    []byte // the suite's public key (DHKEM(P-256): an uncompressed point, PublicKeyLen bytes)
	// HPKESuite is HPKE's suite; the zero value is the classical suite (ClassicalSuite), which every identity this
	// release makes has. On the wire it is always written (PublicKeyResponse.hpke_suite).
	HPKESuite HPKESuite
	Response  ed25519.PublicKey // Ed25519: 32 bytes
	// ResponseAlgorithm is Response's algorithm; 0 is Ed25519 (AlgorithmEd25519), as every identity of this release.
	ResponseAlgorithm SignatureAlgorithm
	// Additional are keys added to the identity after the profile was made (identity.go): covered by the fingerprint
	// (version 2), used by nothing in this release. None in an identity this release makes.
	Additional []IdentityKey
}

// Suite is the identity's HPKE suite, the zero value read as ClassicalSuite.
func (k Identity) Suite() HPKESuite { return k.HPKESuite.orClassical() }

// ResponseAlg is the response key's algorithm, 0 read as AlgorithmEd25519.
func (k Identity) ResponseAlg() SignatureAlgorithm { return k.ResponseAlgorithm.orEd25519() }

// Classical reports whether k is a classical identity — the classical HPKE suite, an Ed25519 response key, no
// additional key — whose fingerprint is version 1 (Fingerprint).
func (k Identity) Classical() bool {
	return k.Suite() == ClassicalSuite && k.ResponseAlg() == AlgorithmEd25519 && len(k.Additional) == 0
}

// Usable reports whether this package can use k's primary keys: the HPKE suite and the response algorithm are
// the ones it implements. An identity that is not usable may still verify and be pinned (ValidateReceived): a
// client refuses to USE it. It is the extension point of an identity of another suite or algorithm (identity.go).
func (k Identity) Usable() error {
	if s := k.Suite(); s != ClassicalSuite {
		return fmt.Errorf("cipheron: the profile's HPKE suite %s is not one this package implements (%s)", s,
			ClassicalSuite)
	}
	if a := k.ResponseAlg(); a != AlgorithmEd25519 {
		return fmt.Errorf("cipheron: the profile's response key algorithm %d is not one this package implements (Ed25519)",
			uint32(a))
	}
	return nil
}

// Validate is the STRICT check of an identity: Usable (the classical suite and Ed25519), the tenancy, that the HPKE
// key is a point of the suite's KEM, the response key's length, and the additional keys' form (validateAdditional).
func (k Identity) Validate() error {
	if err := k.Usable(); err != nil {
		return err
	}
	return k.validate(true)
}

// ValidateReceived is the TOLERANT check a client makes of an identity it received: as Validate, but an HPKE suite
// or a response algorithm it does not implement is accepted (the identity can be pinned and its lists verified
// only when the response key is Ed25519, which ProfileKeys.Verify needs; Usable tells whether it can be used).
func (k Identity) ValidateReceived() error {
	return k.validate(k.Suite() == ClassicalSuite)
}

func (k Identity) validate(classicalHPKE bool) error {
	if !k.Tenancy.Valid() {
		return fmt.Errorf("cipheron: the profile's tenancy %q is not one of %s, %s, %s", k.Tenancy,
			TenancyShared, TenancyPerTenantWrapped, TenancyPerTenantDerived)
	}
	if classicalHPKE {
		if _, err := ParsePublicKey(k.HPKE); err != nil {
			return err
		}
	} else if len(k.HPKE) == 0 || len(k.HPKE) > MaxIdentityKeyLen {
		return fmt.Errorf("cipheron: an HPKE public key is 1 to %d bytes", MaxIdentityKeyLen)
	}
	if k.ResponseAlg() == AlgorithmEd25519 && len(k.Response) != ed25519.PublicKeySize {
		return fmt.Errorf("cipheron: an Ed25519 public key is %d bytes", ed25519.PublicKeySize)
	}
	if len(k.Response) == 0 || len(k.Response) > MaxIdentityKeyLen {
		return fmt.Errorf("cipheron: a response public key is 1 to %d bytes", MaxIdentityKeyLen)
	}
	return validateAdditional(k.Additional)
}

// Equal reports whether two identities are the same, tenancy, suite, algorithms and additional keys included, in
// constant time (two identities are equal exactly when their fingerprints are).
func (k Identity) Equal(o Identity) bool {
	return subtle.ConstantTimeCompare([]byte(Fingerprint("", k)), []byte(Fingerprint("", o))) == 1
}

// Fingerprint is the string a client pins a profile's identity by. It has two derivations, and an identity has
// exactly one of them — which one is decided by the identity itself:
//
// Version 1, for a CLASSICAL identity (Identity.Classical: the classical HPKE suite, an Ed25519 response key, no
// additional key — every identity this release makes): "sha256:" and the lower-case hex SHA-256 of
//
//	lp("cipheron/v1|fingerprint") lp(profile) lp(tenancy) lp(HPKE) lp(Response)
//
// (lp: a 4-byte big-endian length and the bytes). Its derivation fixes the suite and the algorithm, so it names
// them as surely as version 2 does.
//
// Version 2, for any other identity: the SHA-256 of
//
//	lp("cipheron/v1|fingerprint2") lp(profile) lp(tenancy) lp(suite: 6 bytes) lp(HPKE)
//	lp(response algorithm: 4 bytes) lp(Response) lp(n: 4 bytes) n × (lp(role: 4) lp(algorithm id) lp(public key))
//
// the additional keys in canonical order (IdentityKey.encode, bytewise): every suite id, algorithm and key is in
// it. Its label differs from version 1's, so no version-2 value is a version-1 value. Adding a key to an identity
// therefore changes its fingerprint — the pin is updated (both pinned while it changes) — and the added key is
// covered by the pin itself, never only by a signature of the classical response key.
//
// The tenancy is in both, so a client that pinned a profile never accepts it with another tenancy.
func Fingerprint(profile string, k Identity) string {
	derive, _ := fingerprintDerivationOf(FingerprintVersion(k))
	sum := sha256.Sum256(derive(profile, k))
	return FingerprintPrefix + hex.EncodeToString(sum[:])
}

// fingerprintDerivation is one fingerprint derivation: what its SHA-256 is taken over.
type fingerprintDerivation func(profile string, k Identity) []byte

// fingerprintDerivationOf is fingerprint derivation v: 1 (fingerprintV1) or 2 (fingerprintV2). A fingerprint is never
// parsed, and its derivation is chosen by the identity (FingerprintVersion): a pin matches an identity exactly when it
// is the fingerprint of the derivation chosen for it (MatchesFingerprint), so a classical identity has only its
// derivation-1 fingerprint. No caller asks for another derivation; one is refused.
func fingerprintDerivationOf(v int) (fingerprintDerivation, error) {
	switch v {
	case 1:
		return fingerprintV1, nil
	case 2:
		return fingerprintV2, nil
	}
	return nil, fmt.Errorf("cipheron: no profile fingerprint of version %d", v)
}

// fingerprintV1 is derivation 1 (Fingerprint), of a classical identity.
func fingerprintV1(profile string, k Identity) []byte {
	return transcript(nil).addString(fingerprintLabel).addString(profile).addString(string(k.Tenancy)).
		add(k.HPKE).add(k.Response)
}

// fingerprintV2 is derivation 2 (Fingerprint), of any identity.
func fingerprintV2(profile string, k Identity) []byte {
	suite := k.Suite()
	t := transcript(nil).addString(fingerprint2Label).addString(profile).addString(string(k.Tenancy)).
		add(suite.bytes()).add(k.HPKE).addUint32(uint32(k.ResponseAlg())).add(k.Response)
	t = t.addUint32(uint32(len(k.Additional)))
	for _, e := range sortedAdditional(k.Additional) {
		t = append(t, e...)
	}
	return t
}

// FingerprintVersion is the derivation Fingerprint uses for k: 1 for a classical identity, 2 for any other.
func FingerprintVersion(k Identity) int {
	if k.Classical() {
		return 1
	}
	return 2
}

// ValidFingerprint reports whether s is written as Fingerprint writes one.
func ValidFingerprint(s string) bool {
	h, ok := strings.CutPrefix(s, FingerprintPrefix)
	if !ok || len(h) != 2*sha256.Size || strings.ToLower(h) != h {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// MatchesFingerprint reports whether k is the profile identity fp names, in constant time.
func MatchesFingerprint(profile string, k Identity, fp string) bool {
	return subtle.ConstantTimeCompare([]byte(Fingerprint(profile, k)), []byte(fp)) == 1
}

// ParseRequestPublicKey reads a caller's request key: one PEM "PUBLIC KEY" block (PKIX) holding an Ed25519 key,
// and nothing else. The key must be a canonical encoding of a point that is not of small order
// (CheckRequestPublicKey): ed25519.Verify accepts a forged signature over any message under a small-order key.
func ParseRequestPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	der, err := onePEM(pemBytes, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("cipheron: request key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cipheron: a request key is an Ed25519 key, not %T", k)
	}
	if err := CheckRequestPublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// ErrWeakRequestKey is CheckRequestPublicKey's refusal: the 32 bytes are not a canonical encoding of an Ed25519
// point, or the point is of small order.
var ErrWeakRequestKey = errors.New("cipheron: the request key is not a usable Ed25519 public key: its 32 bytes are " +
	"not the canonical encoding of a point, or the point is of small order (the identity, the all-zero key and the " +
	"other degenerate keys verify signatures nobody made); make the key pair with `cipheron keygen caller`")

// CheckRequestPublicKey refuses a request public key that verifies forgeries. ed25519.Verify is cofactorless and
// accepts a small-order public key A: with the identity point (01 00…00) the signature R = B, S = 1 verifies over
// every message, and with the all-zero key a guessed R does one time in four. So a key must decode to a point
// (edwards25519), re-encode to the same 32 bytes (no y ≥ p, no "negative zero": one encoding per key), and [8]A
// must not be the identity (A is not of small order). Every key ed25519.GenerateKey (`cipheron keygen caller`)
// makes passes: [s]B for a clamped s is in the prime-order subgroup.
func CheckRequestPublicKey(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrWeakRequestKey
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil || subtle.ConstantTimeCompare(p.Bytes(), pub) != 1 {
		return ErrWeakRequestKey
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return ErrWeakRequestKey
	}
	return nil
}

// ParseRequestPrivateKey reads a caller's request private key: one PEM "PRIVATE KEY" block (PKCS #8) holding an
// Ed25519 key, and nothing else. The caller wipes pemBytes; the key returned is on the heap.
func ParseRequestPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	der, err := onePEM(pemBytes, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("cipheron: request private key: not a PKCS #8 private key")
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cipheron: a request key is an Ed25519 key, not %T", k)
	}
	return priv, nil
}

// MarshalRequestKeys encodes a caller's request key pair as `cipheron keygen caller` writes it: the private key
// as PEM PKCS #8, the public key as PEM PKIX.
func MarshalRequestKeys(priv ed25519.PrivateKey) (privPEM, pubPEM []byte, err error) {
	p8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pkix, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})
	for i := range p8 {
		p8[i] = 0
	}
	return privPEM, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), nil
}

// onePEM returns the DER of the only PEM block in b, which must be of type typ, with nothing but whitespace
// around it.
func onePEM(b []byte, typ string) ([]byte, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != typ || len(block.Headers) != 0 {
		return nil, fmt.Errorf("cipheron: expected one PEM %q block", typ)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("cipheron: expected one PEM %q block and nothing after it", typ)
	}
	return block.Bytes, nil
}
