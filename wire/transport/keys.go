package transport

// keys.go — a profile's versioned signing keys as PublicKey answers them, the transcript the response key signs
// them under, and the key-context digest that tells whether two cipherons share one profile's keys.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nnicora/cipheron/wire/format"
)

// SigningKeyState is a signing key version's state. Its string is what the keyset, the configuration and the
// key-context digest carry; its number (Code) is what the API's enum and the signing-key transcript carry.
type SigningKeyState string

const (
	// SigningKeyActive is the key Sign signs with: exactly one per profile that has signing keys.
	SigningKeyActive SigningKeyState = "active"
	// SigningKeyVerifyOnly is a key listed so its signatures keep verifying; Sign does not use it.
	SigningKeyVerifyOnly SigningKeyState = "verifyOnly"
	// SigningKeyRevoked is a key revoked for good: listed (its public key stays, so a refusal can name it), never
	// signs, and every signature under it is refused (ErrSigningKeyRevoked). The keyset records it and holds no
	// private key for it.
	SigningKeyRevoked SigningKeyState = "revoked"
)

// The states' numbers on the wire: the API's SigningKeyState enum (0 is UNSPECIFIED, never a state).
const (
	stateCodeActive     uint32 = 1
	stateCodeVerifyOnly uint32 = 2
	stateCodeRevoked    uint32 = 3
)

// Valid reports whether s is one of the three states cipheron publishes: active, verifyOnly or revoked.
func (s SigningKeyState) Valid() bool {
	return s == SigningKeyActive || s == SigningKeyVerifyOnly || s == SigningKeyRevoked
}

// Usable reports whether a signature under a key in state s may verify: active or verifyOnly. A revoked key's
// never does (ErrSigningKeyRevoked), nor one in any other state.
func (s SigningKeyState) Usable() bool { return s == SigningKeyActive || s == SigningKeyVerifyOnly }

// Code is s's number on the wire: 1 active, 2 verifyOnly, 3 revoked; 0 for anything else.
func (s SigningKeyState) Code() uint32 {
	switch s {
	case SigningKeyActive:
		return stateCodeActive
	case SigningKeyVerifyOnly:
		return stateCodeVerifyOnly
	case SigningKeyRevoked:
		return stateCodeRevoked
	}
	return 0
}

// SigningKeyStateOf is the state whose wire number is code: active, verifyOnly or revoked for 1, 2 and 3; "" — no
// state, refused by every validation — for any other number (0, the enum's UNSPECIFIED, included).
func SigningKeyStateOf(code uint32) SigningKeyState {
	switch code {
	case stateCodeActive:
		return SigningKeyActive
	case stateCodeVerifyOnly:
		return SigningKeyVerifyOnly
	case stateCodeRevoked:
		return SigningKeyRevoked
	}
	return ""
}

const (
	// SigningKeyIDLen is the length of a signing key's id (SigningKeyID).
	SigningKeyIDLen = 16
	// MaxSigningKeys is the most signing keys a profile lists. Every key ever used stays listed, and a signing
	// rotation is a rare operator action: the bound only keeps an unverified answer from being unbounded.
	MaxSigningKeys = 256
)

// SigningKey is one version of a profile's signing key.
type SigningKey struct {
	// KeyID is SigningKeyID(PublicKey).
	KeyID     []byte
	State     SigningKeyState
	PublicKey ed25519.PublicKey
	// Algorithm is the key's algorithm; 0 is Ed25519 (what every key cipheron makes is). The key id binds it
	// (SigningKeyIDOf), so every list that covers the id covers the algorithm. A client keeps a key of an algorithm
	// it does not implement listed, and uses it for nothing (Usable): the crypto-agility extension point of the
	// signing keys (identity.go).
	Algorithm SignatureAlgorithm
}

// Alg is the key's algorithm, 0 read as AlgorithmEd25519.
func (k SigningKey) Alg() SignatureAlgorithm { return k.Algorithm.orEd25519() }

// Usable reports whether a signature under k may verify: a usable state (active, verifyOnly) and an algorithm this
// package implements.
func (k SigningKey) Usable() bool { return k.State.Usable() && k.Alg().Implemented() }

// stateCode is the number the signing-key transcript and the key statement cover for k: its State's. A state that
// is not active, verifyOnly or revoked is refused.
func (k SigningKey) stateCode() (uint32, error) {
	if !k.State.Valid() {
		return 0, fmt.Errorf("cipheron: a signing key's state %q is not %s, %s or %s", k.State, SigningKeyActive,
			SigningKeyVerifyOnly, SigningKeyRevoked)
	}
	return k.State.Code(), nil
}

// SigningKeyID is a signing key's id: the first 16 bytes of
//
//	SHA-256( lp("cipheron/v1|signing-key-id") lp(public key) )
//
// It is derived from the public key, not drawn: anyone checks that an id names its key, two listed keys cannot
// share an id unless they are one key, and the keyset, the configuration (`signing.active`) and Sign's answers
// all name a key the same way. 128 bits: ids are compared, never relied on for collision resistance — the list
// they index is authenticated by the response key.
func SigningKeyID(pub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(transcript(nil).addString(signingKeyIDLabel).add(pub))
	return sum[:SigningKeyIDLen]
}

// signingKeyID2Label opens the id of a signing key of another algorithm than Ed25519 (SigningKeyIDOf).
var signingKeyID2Label = format.LabelSigningKeyID2.String()

// SigningKeyIDOf is the id of a signing key of algorithm alg: SigningKeyID(pub) for Ed25519 (and 0), and for any
// other algorithm the first 16 bytes of
//
//	SHA-256( lp("cipheron/v1|signing-key-id2") lp(alg: 4 bytes) lp(public key) )
//
// so the id names the algorithm: the signing-key transcript and the key-context digest cover the id, and with it
// the algorithm, with no change to their layouts. A client computes it for an algorithm it does not know too.
func SigningKeyIDOf(alg SignatureAlgorithm, pub []byte) []byte {
	if alg.orEd25519() == AlgorithmEd25519 {
		return SigningKeyID(pub)
	}
	sum := sha256.Sum256(transcript(nil).addString(signingKeyID2Label).addUint32(uint32(alg)).add(pub))
	return sum[:SigningKeyIDLen]
}

// ValidateSigningKeys is the STRICT check of a profile's signing-key list against its identity — what cipheron
// publishes and a keyset holds: none for a wrapped profile; for a shared or derived one, 1 to MaxSigningKeys keys,
// each a 32-byte public key under its own id (SigningKeyID) in a valid state (active, verifyOnly or revoked), no id
// twice, exactly one active.
func ValidateSigningKeys(id Identity, keys []SigningKey) error {
	return validateSigningKeys(id, keys, true)
}

// ValidateReceivedSigningKeys is the check a client makes of a list it received (ProfileKeys.Verify, a key
// statement): ValidateSigningKeys, except that a key may be of an algorithm this package does not implement (its id
// is SigningKeyIDOf that algorithm) — the crypto-agility extension point: the key is listed and unusable
// (SigningKey.Usable). Every key's state is one of the three, and exactly one is active, as in ValidateSigningKeys.
func ValidateReceivedSigningKeys(id Identity, keys []SigningKey) error {
	return validateSigningKeys(id, keys, false)
}

// validateSigningKeys is both checks; strict refuses an algorithm this package does not implement.
func validateSigningKeys(id Identity, keys []SigningKey, strict bool) error {
	if !id.Tenancy.HasSigningKeys() {
		if len(keys) != 0 {
			return fmt.Errorf("cipheron: a %s profile has no signing keys of its own", id.Tenancy)
		}
		return nil
	}
	if len(keys) == 0 || len(keys) > MaxSigningKeys {
		return fmt.Errorf("cipheron: a %s profile lists 1 to %d signing keys, not %d", id.Tenancy, MaxSigningKeys, len(keys))
	}
	active := 0
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if _, err := k.stateCode(); err != nil {
			return err
		}
		switch {
		case k.Alg() == AlgorithmEd25519 && len(k.PublicKey) != ed25519.PublicKeySize:
			return fmt.Errorf("cipheron: an Ed25519 public key is %d bytes", ed25519.PublicKeySize)
		case len(k.PublicKey) == 0 || len(k.PublicKey) > MaxIdentityKeyLen:
			return fmt.Errorf("cipheron: a signing public key is 1 to %d bytes", MaxIdentityKeyLen)
		case strict && !k.Alg().Implemented():
			return fmt.Errorf("cipheron: a signing key's algorithm %d is not one cipheron makes", uint32(k.Alg()))
		case !bytes.Equal(k.KeyID, SigningKeyIDOf(k.Alg(), k.PublicKey)):
			return errors.New("cipheron: a signing key's id is not its public key's")
		case seen[string(k.KeyID)]:
			return fmt.Errorf("cipheron: signing key %x is listed twice", k.KeyID)
		}
		seen[string(k.KeyID)] = true
		if k.State == SigningKeyActive {
			active++
		}
	}
	if active != 1 {
		return fmt.Errorf("cipheron: a profile has exactly one active signing key, not %d", active)
	}
	return nil
}

// SortSigningKeys sorts keys into the canonical order: ascending key id (bytewise). PublicKey answers them in it.
func SortSigningKeys(keys []SigningKey) {
	slices.SortFunc(keys, func(a, b SigningKey) int { return bytes.Compare(a.KeyID, b.KeyID) })
}

// SigningKeysTranscript is what the profile's response key signs a PublicKey answer with (keys_signature):
//
//	lp("cipheron/v1|signed_keys") lp(TranscriptVersion: 4 bytes) lp(profile) lp(tenancy) lp(context digest)
//	lp(request nonce)
//	lp(k: 4 bytes) then, for each key in canonical order (ascending key id):
//	    lp(key id) lp(state number: 4 bytes) lp(public key)
//
// lp is a 4-byte big-endian length and the bytes; every number is 4 bytes big-endian. The state is its NUMBER
// (SigningKeyState.Code), as the answer carries it.
//
// The order is canonical — the transcript sorts a copy — so the list's order on the wire does not matter, and one
// list has one transcript; the count keeps the list from running into anything after it. A wrapped profile's list is
// empty (k = 0), which still binds the version, the profile, the tenancy, the context digest and the nonce. The
// context digest is in it so that the digest a client prints and compares is cipheron's too, not a party's in the
// path. The request nonce is the PublicKeyRequest's request_nonce (NonceLen fresh random bytes; empty when the
// request carried none): it makes the answer FRESH — an answer recorded before (an older signing-key list, an older
// digest) does not verify for a request with another nonce, so a party in the path cannot roll a client back to it.
//
// It does not validate the keys (ValidateSigningKeys, ValidateReceivedSigningKeys); it refuses a key whose state is
// not one of the three (SigningKeyState.Valid).
func SigningKeysTranscript(p *format.Policy, profile string, tenancy Tenancy, contextDigest string, nonce []byte,
	keys []SigningKey,
) ([]byte, error) {
	received := make([]ReceivedSigningKey, len(keys))
	for i, k := range keys {
		code, err := k.stateCode()
		if err != nil {
			return nil, err
		}
		received[i] = ReceivedSigningKey{KeyID: k.KeyID, State: code, PublicKey: k.PublicKey}
	}
	return ReceivedSigningKeysTranscript(p, profile, tenancy, contextDigest, nonce, received), nil
}

// ReceivedSigningKey is a signing key as a PublicKey answer carries it, before anything of it is read: State is the
// number the answer carries, whatever it is (SigningKeyStateOf reads it).
type ReceivedSigningKey struct {
	KeyID     []byte
	State     uint32
	PublicKey []byte
}

// ReceivedSigningKeysTranscript is SigningKeysTranscript's transcript — the same layout, the same canonical order —
// over keys as an answer carries them: each key's state is the number received, a number that is no state included.
// For keys in the three states it is SigningKeysTranscript's, byte for byte. A client verifies keys_signature over it
// (VerifyKeysSignature) before it reads what the answer says: a state number changed in the path then fails the
// signature, and a number that verifies is the one the response key signed.
func ReceivedSigningKeysTranscript(p *format.Policy, profile string, tenancy Tenancy, contextDigest string,
	nonce []byte, keys []ReceivedSigningKey,
) []byte {
	s := writtenTranscripts(p)
	return s.Codec().signingKeys(s.Version(), profile, tenancy, contextDigest, nonce, sortedReceived(keys))
}

// sortedReceived is a copy of keys in the canonical order: ascending key id (bytewise).
func sortedReceived(keys []ReceivedSigningKey) []ReceivedSigningKey {
	sorted := slices.Clone(keys)
	slices.SortFunc(sorted, func(a, b ReceivedSigningKey) int { return bytes.Compare(a.KeyID, b.KeyID) })
	return sorted
}

// signingKeysTranscriptV1 is the signing-keys transcript's layout at transcript version 1, binding v, of keys in the
// canonical order (sortedReceived).
func signingKeysTranscriptV1(v uint32, profile string, tenancy Tenancy, contextDigest string, nonce []byte,
	sorted []ReceivedSigningKey,
) []byte {
	t := transcript(nil).addString(signingKeysLabel).addUint32(v).addString(profile).
		addString(string(tenancy)).addString(contextDigest).add(nonce).addUint32(uint32(len(sorted)))
	for _, k := range sorted {
		t = t.add(k.KeyID).addUint32(k.State).add(k.PublicKey)
	}
	return t
}

// VerifyKeysSignature checks a keys_signature: pub's Ed25519 signature over a signing-keys transcript
// (SigningKeysTranscript, ReceivedSigningKeysTranscript). Any failure is ErrAuth.
func VerifyKeysSignature(pub ed25519.PublicKey, transcript, signature []byte) error {
	return verify(pub, transcript, signature)
}

// ProfileKeys is a PublicKey answer: the profile's identity, its signing keys, its key-context digest, and the
// response key's signature over them and the request's nonce (SigningKeysTranscript).
type ProfileKeys struct {
	Identity

	SigningKeys   []SigningKey
	ContextDigest string
	KeysSignature []byte
}

// Verify checks a PublicKey answer for profile to the request whose request_nonce was nonce: the identity
// (Identity.ValidateReceived), the context digest's form, the signing-key list (ValidateReceivedSigningKeys) and
// keys_signature under the identity's response key over the transcript with nonce — an answer made for another
// request (a replayed one) is ErrAuth.
//
// It does not check the identity against a pin (MatchesFingerprint): a client does that first.
//
// The identity is checked as received (Identity.ValidateReceived: an HPKE suite this package does not implement is
// accepted, for the caller to refuse to USE it, Identity.Usable), but its response key must be Ed25519: nothing
// else can be verified here.
func (d *ProfileKeys) Verify(p *format.Policy, profile string, nonce []byte) error {
	if a := d.ResponseAlg(); !a.Implemented() {
		return fmt.Errorf("cipheron: the profile's response key algorithm %d is not one this package implements", uint32(a))
	}
	if err := d.Identity.ValidateReceived(); err != nil {
		return err
	}
	if !ValidFingerprint(d.ContextDigest) {
		return fmt.Errorf("cipheron: %q is not a key-context digest", d.ContextDigest)
	}
	if err := ValidateReceivedSigningKeys(d.Identity, d.SigningKeys); err != nil {
		return err
	}
	received := make([]ReceivedSigningKey, len(d.SigningKeys))
	for i, k := range d.SigningKeys {
		code, err := k.stateCode()
		if err != nil {
			return err
		}
		received[i] = ReceivedSigningKey{KeyID: k.KeyID, State: code, PublicKey: k.PublicKey}
	}
	return VerifyReceivedSigningKeys(p, d.Response, d.KeysSignature, profile, d.Tenancy, d.ContextDigest, nonce, received)
}

// Active is the active signing key; false for a wrapped profile (or a list without one).
func (d *ProfileKeys) Active() (SigningKey, bool) {
	for _, k := range d.SigningKeys {
		if k.State == SigningKeyActive {
			return k, true
		}
	}
	return SigningKey{}, false
}

// SigningKey is the listed key whose id is keyID, in whatever state: the caller decides on its State — only a
// Usable one verifies; a revoked one is ErrSigningKeyRevoked.
func (d *ProfileKeys) SigningKey(keyID []byte) (SigningKey, bool) {
	for _, k := range d.SigningKeys {
		if bytes.Equal(k.KeyID, keyID) {
			return k, true
		}
	}
	return SigningKey{}, false
}

// MasterVersionState is a master key version's configured state. It is configuration, not key context: which
// listed version writes does not change what can be read, so it is not in ContextDigest.
type MasterVersionState string

const (
	// MasterVersionActive is a version new data keys may come from (with activateAt, from that time on).
	MasterVersionActive MasterVersionState = "active"
	// MasterVersionDecryptOnly is a version listed so its data keeps decrypting.
	MasterVersionDecryptOnly MasterVersionState = "decryptOnly"
)

// Valid reports whether s is one of the two states.
func (s MasterVersionState) Valid() bool {
	return s == MasterVersionActive || s == MasterVersionDecryptOnly
}

// KeyCheckValueLen is the length of a key check value (MasterVersionCheck.KCV): 128 bits.
const KeyCheckValueLen = 16

// MasterVersionCheck is one listed master key version as the key-context digest covers it: its id and its key
// check value — a non-secret value computed from the version's key (the server's keyset, KCV), equal on two
// cipherons exactly when the version unseals to the same key on both (but with negligible probability).
type MasterVersionCheck struct {
	ID  string
	KCV []byte
}

// KeyContext is what decides which of a profile's ciphertexts, tenant key blobs and signatures a cipheron can
// read, open and answer for, and which ones it makes: the inputs of ContextDigest.
type KeyContext struct {
	Profile string
	Tenancy Tenancy
	// MasterVersions are the listed master key versions (any order) with their key check values: two cipherons
	// whose version v2 unseals to different keys have different digests. Their states are not in it.
	MasterVersions []MasterVersionCheck
	// KeysetFingerprint is the profile's fingerprint as the keyset file gives it (Fingerprint of its identity).
	KeysetFingerprint string
	// SigningKeys are the published signing keys (shared and derived; none in a wrapped profile) with their states
	// as configured — the one active is the one the configuration's signing.active names (or the keyset's), the
	// revoked ones those the keyset records revoked: its key id and state are covered (the public key is: the id
	// is its digest). Two cipherons that would sign with different keys, or publish different lists — one of them
	// with a key revoked, the other not — have different digests.
	SigningKeys []SigningKey
}

// ContextDigest is a profile's key-context digest: "sha256:" and the lower-case hex SHA-256 of
//
//	lp("cipheron/v1|context") lp(profile) lp(tenancy)
//	lp(n) then n × (lp(master version id) lp(kcv))          ascending id (bytewise)
//	lp(keyset fingerprint)
//	lp(k) then k × (lp(signing key id) lp(state))          ascending id (bytewise); state "published" (an active or
//	                                                       a verifyOnly key) or "revoked" (the string, not the wire
//	                                                       number)
//
// (lp: a 4-byte big-endian length and the bytes; n and k are 4-byte big-endian counts, length-prefixed like
// every field, so no list can run into what follows it). It covers what decides what a cipheron of the profile
// reads and writes: the profile and its tenancy; which master versions are listed AND the key each unseals to (its
// check value: a version present on two members under one id but two keys reads as corruption on one of them); the
// keyset (its fingerprint names the identity keys); and the signing keys published and those revoked. Two cipherons with one
// digest read each other's ciphertexts, publish alike and verify each other's signatures; a member of a group pins it
// (expectContext) to refuse to start on a shared file — or a master — that differs.
//
// A signing key is written in ONE state while it is published, active or verifyOnly ("published", SigningKeyPublished),
// and "revoked" once revoked: the digest binds which signing keys are published and which are revoked, not which
// published key signs now. A signing activation — signing.activeGeneration, or its signing.activateAt passing — never
// moves it (owner decision D-Q): a signature under any published key verifies on every client anyway (clients accept
// any usable listed key), so which one signs is not what a pin protects. A key added, a key revoked, another master
// version or check value, another keyset does move it. The list is still checked as the profile publishes it
// (exactly one active in a shared or derived profile).
//
// NOT covered, on purpose: the master versions' STATES (active, decryptOnly) and activateAt — they decide only
// which listed version NEW ciphertexts are made under, never what can be read: a ciphertext names its version, and
// a listed version decrypts whatever its state; covering them would change every pin at every activation. Nor the
// seals' configuration (how a master version is unsealed is per deployment; what it unseals to is the check
// value). Nor anything per service (callers, listeners, limits). Nor any tenant: cipheron's configuration names
// none (the application owns its tenancy); a tenant is bound per request, inside each ciphertext, blob, derivation
// and signature.
//
// It refuses a profile that is not a profile name (ValidProfile), an invalid tenancy, no master version, an invalid or
// repeated version id, a check value not KeyCheckValueLen bytes, a keyset fingerprint not written as Fingerprint writes one, a
// signing-key list of the wrong form for the tenancy (ids not SigningKeyIDLen bytes, repeated, a state not valid,
// not exactly one active in a shared or derived profile, any in a wrapped one). A revoked SIGNING key is covered as
// any other: the digest of a list without one is what it always was, and a signing-key revocation (keygen ensure,
// for good) changes the digest.
func ContextDigest(c KeyContext) (string, error) {
	if !ValidProfile(c.Profile) {
		return "", fmt.Errorf("cipheron: %q is not a profile name", c.Profile)
	}
	if !c.Tenancy.Valid() {
		return "", fmt.Errorf("cipheron: the profile's tenancy %q is not one of %s, %s, %s", c.Tenancy,
			TenancyShared, TenancyPerTenantWrapped, TenancyPerTenantDerived)
	}
	if len(c.MasterVersions) == 0 {
		return "", errors.New("cipheron: a profile lists at least one master key version")
	}
	if !ValidFingerprint(c.KeysetFingerprint) {
		return "", fmt.Errorf("cipheron: %q is not a keyset fingerprint", c.KeysetFingerprint)
	}
	versions := slices.Clone(c.MasterVersions)
	slices.SortFunc(versions, func(a, b MasterVersionCheck) int { return strings.Compare(a.ID, b.ID) })
	for i, v := range versions {
		switch {
		case !ValidMasterVersionID(v.ID):
			return "", fmt.Errorf("cipheron: %q is not a master key version id", v.ID)
		case i > 0 && versions[i-1].ID == v.ID:
			return "", fmt.Errorf("cipheron: master key version %q is listed twice", v.ID)
		case len(v.KCV) != KeyCheckValueLen:
			return "", fmt.Errorf("cipheron: master key version %q's check value is %d bytes, not %d", v.ID, len(v.KCV),
				KeyCheckValueLen)
		}
	}
	signing := slices.Clone(c.SigningKeys)
	SortSigningKeys(signing)
	active := 0
	for i, k := range signing {
		switch {
		case len(k.KeyID) != SigningKeyIDLen:
			return "", fmt.Errorf("cipheron: a signing key id is %d bytes, not %d", len(k.KeyID), SigningKeyIDLen)
		case !k.State.Valid():
			return "", fmt.Errorf("cipheron: a signing key's state %q is not %s, %s or %s", k.State, SigningKeyActive,
				SigningKeyVerifyOnly, SigningKeyRevoked)
		case i > 0 && bytes.Equal(signing[i-1].KeyID, k.KeyID):
			return "", fmt.Errorf("cipheron: signing key %x is listed twice", k.KeyID)
		}
		if k.State == SigningKeyActive {
			active++
		}
	}
	if c.Tenancy.HasSigningKeys() && active != 1 {
		return "", fmt.Errorf("cipheron: a %s profile has exactly one active signing key, not %d", c.Tenancy, active)
	}
	if !c.Tenancy.HasSigningKeys() && len(signing) > 0 {
		return "", fmt.Errorf("cipheron: a %s profile has no signing keys of its own", c.Tenancy)
	}
	t := transcript(nil).addString(contextLabel).addString(c.Profile).addString(string(c.Tenancy)).
		add(binary.BigEndian.AppendUint32(nil, uint32(len(versions))))
	for _, v := range versions {
		t = t.addString(v.ID).add(v.KCV)
	}
	t = t.addString(c.KeysetFingerprint).add(binary.BigEndian.AppendUint32(nil, uint32(len(signing))))
	for _, k := range signing {
		state := string(k.State)
		if k.State.Usable() {
			state = SigningKeyPublished
		}
		t = t.add(k.KeyID).addString(state)
	}
	sum := sha256.Sum256(t)
	return FingerprintPrefix + hex.EncodeToString(sum[:]), nil
}

// SigningKeyPublished is the state ContextDigest writes for an active or a verifyOnly signing key: one "published"
// state (owner decision D-Q). It is never a state cipheron publishes, a keyset records or a configuration names.
const SigningKeyPublished = "published"
