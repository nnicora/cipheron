// Package client is cipheron's protocol client: it dials cipheron — its unix socket, or its mutual-TLS network
// listener — over gRPC or over HTTP, fetches and authenticates a profile's keys, signs every request with the
// caller's request key, verifies every answer, and does the HPKE sealing and opening of the protocol, which is
// the same on both transports.
//
// Applications use package cipheron, the public library over this package, which hides the transport and the
// wire errors. This package keeps both transports so the command-line client (`cipheron client --transport
// http`) and the tests can exercise the HTTP API too.
//
//	c, err := client.DialGRPC("/run/cipheron/private/cipheron.sock", client.WithServerUID(10443),
//		client.WithProfileFingerprint("credentials", "sha256:…")) // what `cipheron keygen` printed
//	ct, err := c.Encrypt(ctx, "credentials", plaintext)
//	pt, err := c.Decrypt(ctx, "credentials", ct)
//	ct2, err := c.ReEncrypt(ctx, "credentials", ct) // the same plaintext under the current keys
//	s, err := c.Sign(ctx, "credentials", data)      // s.Bytes, s.KeyID
//	ok, err := c.Verify(ctx, "credentials", data, s.Bytes, s.KeyID)
//	k, err := c.Keys(ctx, "credentials")
//	ok, err := client.VerifyWithKeys(k.SigningKeys, data, s.Bytes, s.KeyID) // no cipheron needed
//
// What each call does on the wire:
//   - A profile's keys are fetched once per profile — concurrent first calls share one fetch — and cached. They are
//     its IDENTITY (the HPKE key requests are sealed to, the response key every answer is signed by, and the
//     tenancy), which never changes and which the
//     fingerprint covers (WithProfileFingerprint pins it; without a pin the identity first seen is trusted), and its
//     SIGNING-KEY LIST and KEY-CONTEXT DIGEST, which rotate and are signed by the response key (keys_signature) —
//     so the identity authenticates them. A later fetch whose identity differs is ErrServerKeyChanged and is never
//     adopted; a later list that verifies under the same identity and still names every key the cached one did is
//     adopted (that is a signing rotation). A list that does not verify is never adopted. A key revoked in any list
//     this Client adopted or verified stays revoked for the Client's life, whatever a later list says. Verify
//     fetches the list again when it is older than WithKeysMaxAge (5 minutes by default), and fails closed
//     (ErrKeysStale) when that fetch fails.
//   - Every signed request, answer and key list is a transcript of wire/transport that binds the protocol's
//     one transcript version (transport.TranscriptVersion): nothing is negotiated, and a request names no version.
//   - Encrypt and Sign seal the payload with HPKE to the profile's HPKE key. Decrypt sends a public key generated
//     for that one call; cipheron seals the plaintext back to it and the client opens it with the private half,
//     which is then dropped. ReEncrypt and RewrapTenantKey carry no plaintext.
//   - Every request carries a fresh 16-byte request nonce and, with a request key (WithRequestKeyFile,
//     WithRequestKey), an Ed25519 signature over the profile, the operation, the time, the nonce and the payload
//     (wire/transport RequestTranscript), which cipheron checks and accepts once.
//   - Every answer is verified before it is returned: its response signature, by the profile's response key, over
//     the key-context digest of the replica that made it (one this client accepts: a pinned one, else one the
//     profile's verified keys gave), the request's nonce, the requester, the digest of the payload this client sent,
//     and the answer; then what
//     the answer says — a ciphertext's format and the key it names, a signature under the key its key id names
//     (an unknown key id makes the client fetch the profile's keys again, once, to learn a rotation), a tenant
//     key blob's identity. An answer that fails is ErrServerIdentity (not the profile's) or ErrBadResponse
//     (signed, but malformed — a ciphertext format or a tenant key blob version this protocol does not have
//     included), never returned to the caller; a Sign answer under a key the profile lists as revoked (a stale
//     replica) is ErrSigningKeyRevoked.
//
// TENANTS (tenant.go): in a perTenant WRAPPED profile CreateTenantKey makes a tenant key and returns the blob the
// application stores, and Tenant(profile, tenant, blob) is the handle whose calls carry the tenant and the blob;
// RewrapTenantKey moves a blob to the current wrapping key. In a perTenant DERIVED profile Tenant(profile, tenant,
// nil) is the handle: requests carry the tenant only. The Client's own calls refuse a perTenant profile, and the
// tenant calls a shared one (ErrTenancy).
//
// WHO IS ON THE OTHER END. On the socket the client checks, on every connection and before sending anything,
// that the listening process runs as the uid WithServerUID names, as the kernel reports it; a socket address
// without it is refused unless WithAnyServer says, explicitly, that whatever listens on the path is trusted. On
// the network the server is verified by its certificate: its hostname against the TLS configuration's RootCAs,
// or its SPIFFE ID with WithServerSPIFFEID; a configuration that would fall back on the system's roots, verifies
// no server, or presents no client certificate is refused. Beyond the connection, the profile's identity is the
// server's: with a pin, a party that is not the profile's cipheron cannot answer a single call.
//
// Errors are gRPC status errors on both transports when cipheron answered with one (status.Code reads them):
// PERMISSION_DENIED when this process may not use the profile or the operation — or, on the network, when
// cipheron refused this client's certificate in the TLS handshake, an authenticated alert the client turns into
// that status at once (refusal.go; it is ErrCertificateRefused too) — INVALID_ARGUMENT for a ciphertext that does
// not open (or whose key version is not available), RESOURCE_EXHAUSTED for a request over cipheron's limit (gRPC's
// own refusal of a message, which carries no details) or when it is busy (cipheron's, with a RetryInfo and the
// ErrorInfo of transport.ReasonBusy), UNAVAILABLE when it cannot serve, UNIMPLEMENTED for a call the server does
// not have (over HTTP, a 404 of the operation's route). What the client itself decides is one of this package's
// sentinels (ErrServerIdentity, ErrServerKeyChanged, ErrPinRequired, ErrBadResponse, ErrTooLarge, ErrTenancy,
// ErrTenantKey, ErrUnknownSigningKey, ErrSigningKeyRevoked, ErrKeysStale, ErrInvalidKeyList, ErrClosed) or
// transport.ErrCiphertext, wrapped with the reason;
// test them with errors.Is. Two kinds of error are neither: what DialGRPC and DialHTTP refuse (a configuration
// error, a plain error naming what is wrong: an option, a file, the environment), and the error of the call's own
// context when it ended the call. package cipheron maps all of them to its own values (its mapErr).
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

var (
	// ErrServerIdentity: the party that answered could not be shown to be the profile's cipheron — the socket's
	// process does not run as WithServerUID's uid, the server's certificate or SPIFFE ID did not verify, the
	// profile's identity does not match its pin (WithProfileFingerprint), its signing-key list does not verify under
	// its identity, or an answer is not the profile's: a response signature missing or not verifying (under any key
	// context this client accepts or has seen the profile give: a replica on a context it never saw cannot be told from
	// an impostor), a Sign answer
	// naming a key the profile's authenticated list does not have, or a signature that does not verify under the
	// key it names. A PublicKey answer and a batch answer are authenticated before anything in them is read
	// (fetchKeys, verifyBatch), so a value changed in the path — a batch result dropped, added or changed among them —
	// is this error, never ErrBadResponse; so is an answer that cannot be authenticated at all — a tenancy or a
	// response key algorithm this client does not have, an hpke_suite or algorithm cipheron always writes left out, a
	// batch answer of more results than any batch holds, a batch error item that also carries a result. The error
	// wraps the reason. Nothing from that party is returned.
	ErrServerIdentity = errors.New("cipheron: not the profile's cipheron")
	// ErrServerKeyChanged: cipheron answered another identity for the profile than the one this Client fetched
	// first (or pinned). A profile's identity never changes — rotations change its signing-key list and its data
	// keys, never the identity — so either the profile was re-created or something else answers for it; the new
	// identity is never adopted, and every call that needs it fails until the Client is re-created (with a pin,
	// after checking the new fingerprint). It is also ErrServerIdentity.
	ErrServerKeyChanged = errors.New("cipheron: the profile's identity changed")
	// ErrBadResponse: an answer signed by the profile's response key is not well formed — a ciphertext not in the
	// format the profile's tenancy writes (a format this protocol does not have included), of the wrong length or
	// under the wrong key, a sealed plaintext that does not open, a tenant key blob that is not the one asked for (or
	// of another layout version), a signed batch answer with another number of results than items sent or an item
	// error of a code no item is answered with; or an answer holding what this client does not have: a signing-key
	// state in a PublicKey answer whose keys_signature verified, or an HPKE suite or algorithm of a key it is asked to
	// use. The answer is never returned to the caller. It points at a defect of cipheron's; the observer is not told of
	// it.
	ErrBadResponse = errors.New("cipheron: malformed answer")
	// ErrTooLarge: what THIS CLIENT refuses for its size — a payload larger than it sends or receives in one message
	// (WithMaxMessageBytes), refused before anything is sent, or (over HTTP) an answer larger than that, or an HTTP
	// 413 whose body is not a status. cipheron's own refusal of a request over its limit (its listener's
	// maxRequestBytes) is NOT this value in this package: over gRPC it is the RESOURCE_EXHAUSTED status gRPC itself
	// answers for a message over the limit, with no details ("grpc: received message larger than max"), which
	// package cipheron maps to its ErrTooLarge (this same value); over HTTP cipheron answers a body over the limit HTTP 413,
	// which this client returns as ErrTooLarge that is also RESOURCE_EXHAUSTED by its code (tooLargeError, dial.go),
	// whatever the body says.
	ErrTooLarge = errors.New("cipheron: too large")
	// ErrTenancy: the call is not one of the profile's tenancy — the Client's own Encrypt, Decrypt, ReEncrypt,
	// Sign or Verify in a perTenant profile, whose calls go through Tenant; a Tenant's, CreateTenantKey or
	// RewrapTenantKey in a shared profile; CreateTenantKey, RewrapTenantKey or a blob in a derived profile (a blob of
	// the call's profile and tenant: one of another profile or tenant is ErrTenantKey, checked first). Refused
	// before the operation is sent: the tenancy is read from the profile's keys, so the first call in a profile
	// fetches them (PublicKey, which carries nothing of the caller's) before it can be refused. A key statement's Verify
	// of a statement that is not a shared profile's, and its VerifyTenant of one that is not a derived profile's, answer
	// it too, with nothing verified.
	ErrTenancy = errors.New("cipheron: the call is not one of the profile's tenancy")
	// ErrTenantKey: a tenant id that is not one (1 to transport.MaxTenantLen bytes of printable ASCII, 0x21 to
	// 0x7E); a tenant key blob that is not one, that is another tenant's or profile's than the call's, that is not
	// the key pinned for the tenant (WithTenantFingerprint), or missing where a wrapped profile needs one — the
	// handle's blob, or ReEncrypt's target blob (to) in a wrapped profile. Refused before the operation is sent: the
	// tenant id, the blob's header and the pin are checked with nothing sent at all; a blob missing for a wrapped
	// profile is known only from the profile's keys, so the first call in a profile fetches them (PublicKey) first.
	ErrTenantKey = errors.New("cipheron: not the tenant's key")
	// ErrPinRequired: the client was made WithRequiredPins and the profile has no fingerprint pin (WithProfileFingerprint,
	// or a "<profile>.fingerprint" file in the pins directory WithEnvironment reads). Nothing was asked of cipheron:
	// the profile's identity is not trusted on first use. It is also ErrServerIdentity — nothing showed the party on
	// the other end to be the profile's cipheron.
	ErrPinRequired = errors.New("cipheron: the profile has no pin, and the client requires one")
	// ErrContextDigest: the key-context digest cipheron answered for the profile — signed by the profile's response
	// key, so it is cipheron's — is not one the client pins (WithContextDigestPin, or a "<profile>.contextDigest" file
	// in the pins directory WithEnvironment reads), in a PublicKey answer or in the response signature of any other
	// answer (which covers the digest of the replica that made it: transport.ResponseTranscript); or an answer made new
	// data under a master key version the writer pin does not name (WithWriterVersionPin). The replica that answered
	// serves another key context than the one this application was deployed against: another master version list,
	// signing key or keyset, or another writer — a drifted or stale shared file, a replica that lags a rollout, or a
	// rollout this client's pins do not name yet. Nothing of the answer is used or cached; after a key fetch or an
	// answer of an unpinned context the profile's cached keys are not used again until a fetch that the pins accept
	// stored them anew, so the profile's calls fail until a replica with a pinned context answers. It is not
	// ErrServerIdentity: the identity verified. An answer whose context is one this client never saw a verified
	// PublicKey answer give cannot be told from a forged one: it is ErrServerIdentity.
	ErrContextDigest = errors.New("cipheron: the profile's key context is not one this client pins")
	// ErrUnknownSigningKey: Verify was asked about a signature whose key id names no signing key this Client knows
	// for the profile, so it could neither confirm nor refute the signature. IT IS NOT A VERDICT ON THE SIGNATURE: a
	// genuine signature made just after a signing rotation gets it until this Client has learnt the new key. Verify
	// answers it when the key id is not in the cached list and
	//   - the list was not fetched again, because it was fetched (or a fetch was tried) within the last few seconds
	//     — the flood protection: key ids come from whoever stored the signature, and must not turn into one
	//     PublicKey call each. Try again in a few seconds;
	//   - or the fetch failed: the error wraps the fetch's error too (a status, ErrServerIdentity, ...);
	//   - or a fresh list, fetched for this call, does not name it either: the signature is another profile's or
	//     another deployment's, or its key id is corrupt or forged. This case is an error too, by choice: only a key
	//     this Client knows makes Verify answer (false, nil);
	//   - or the key id is not transport.SigningKeyIDLen bytes.
	// Nothing was verified. It is the answer of Client.Verify (a shared profile) and of a DERIVED profile's
	// Tenant.Verify, whose keys are the profile's list. A WRAPPED profile's Tenant.Verify never answers it: its handle
	// has one key, the blob's, and a key id that is not the blob's is (false, nil) there (Tenant.Verify).
	ErrUnknownSigningKey = errors.New("cipheron: the signature names a signing key this client does not know")
	// ErrSigningKeyRevoked (transport.ErrSigningKeyRevoked, the same value): the signature names a signing key the
	// profile lists as REVOKED — Verify (a shared profile's, a derived profile's Tenant.Verify) and VerifyWithKeys
	// answer (false, ErrSigningKeyRevoked) for it whatever the bytes: never true, never a bare false. It is also a
	// Sign answer naming a revoked key (a replica that did not learn the revocation), which is refused. Once a list
	// this Client verified marks a key revoked, the key stays revoked for the Client's life, whatever a later list
	// says. KeyStatement answers it when the statements cipheron answered list as usable a key this Client holds
	// revoked: no statement is handed out. The raw-key Verify and VerifyTenant do not know about states and still check
	// the bytes: that is the escape hatch of an application with trusted evidence of its own of when a signature was made.
	ErrSigningKeyRevoked = transport.ErrSigningKeyRevoked
	// ErrKeysStale: Verify — or Sign, judging the key its answer names — needed the profile's signing-key list fetched
	// again — it was older than WithKeysMaxAge (measured on the monotonic clock) — and the fetch failed (or failed
	// within the last few seconds, and is not tried again yet). Nothing was verified, and Sign returns no signature:
	// the client does not decide on a list that may miss a revocation. The error wraps the fetch's error. KeyStatement
	// answers it too when no statement this Client verified within WithKeysMaxAge agrees with the list it holds.
	ErrKeysStale = errors.New("cipheron: the profile's signing-key list is too old and could not be fetched again")
	// ErrInvalidKeyList: the signing-key list handed to VerifyWithKeys or VerifyTenantWithKeys is not one list of a
	// profile: it names a key id twice (two lists joined, whose order would then decide whether a revoked key
	// verifies), a key under an id that is not its public key's (transport.SigningKeyID), or a key in a state that is
	// not active, verifyOnly or revoked; or the key asked about is of an algorithm this client does not implement.
	// Nothing was verified: fetch the list again (Keys) and pass that list alone. package cipheron answers it as its
	// ErrInvalidInput (the caller's input), with this value in the chain.
	ErrInvalidKeyList = errors.New("cipheron: the signing-key list given is not one profile's list")
	// ErrClosed: the Client was closed (Close). A call made after Close answers it without sending anything, and a
	// call that Close cut short answers it too. Make a new Client.
	ErrClosed = errors.New("cipheron: the client is closed")
	// ErrAssociatedData (transport.ErrAssociatedData, the same value): the associated data given does not match the
	// ciphertext's format — a ciphertext made with associated data (format 5 or 6) given without any, one made without
	// (format 3 or 4) given with some, or associated data over transport.MaxAssociatedDataLen. Refused before
	// anything is sent (and cipheron's CIPHERON_ASSOCIATED_DATA refusal maps to it). Wrong associated data is not this
	// error: the ciphertext does not decrypt (INVALID_ARGUMENT), as a modified one does — never other data.
	ErrAssociatedData = transport.ErrAssociatedData
)

// keyUsable is nil for a signing key a signature may be verified under (active, verifyOnly, of an algorithm this
// client implements) and ErrSigningKeyRevoked for a revoked one. Any other key is refused as kind: ErrBadResponse
// for a key of a list cipheron answered, ErrInvalidKeyList for one of a list a caller handed in — a key of an
// algorithm this client does not implement (the crypto-agility extension point: listed, never used), or in a state
// that is none of the three (no verified list holds one). who names the scope in the error.
func keyUsable(key transport.SigningKey, who string, kind error) error {
	switch {
	case key.State.Usable() && !key.Alg().Implemented():
		return fmt.Errorf("%w (%s, key id %x): the key's algorithm (number %d) is not one this client implements",
			kind, who, key.KeyID, uint32(key.Alg()))
	case key.State.Usable():
		return nil
	case key.State == transport.SigningKeyRevoked:
		return fmt.Errorf("%w (%s, key id %x): the profile revoked it: no signature under it is accepted",
			ErrSigningKeyRevoked, who, key.KeyID)
	}
	return fmt.Errorf("%w (%s, key id %x): the key's state %q is not active, verifyOnly or revoked", kind, who,
		key.KeyID, key.State)
}

// unknownKey is ErrUnknownSigningKey for keyID in the scope, with why, and with the fetch's error when one failed.
func unknownKey(s scope, keyID []byte, why string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w (%s, key id %x): %s: %w", ErrUnknownSigningKey, s.who(), keyID, why, cause)
	}
	return fmt.Errorf("%w (%s, key id %x): %s", ErrUnknownSigningKey, s.who(), keyID, why)
}

// pinRequired is ErrPinRequired for profile, which is also ErrServerIdentity.
func pinRequired(profile string) error {
	return fmt.Errorf("%w (profile %q: pin it with WithProfileFingerprint, or give it a <profile>%s file in %s): %w",
		ErrPinRequired, profile, PinFingerprintSuffix, EnvPinsDir, ErrServerIdentity)
}

// identityFailure is ErrServerIdentity with its reason.
func identityFailure(cause error) error { return fmt.Errorf("%w: %w", ErrServerIdentity, cause) }

// keyChanged is ErrServerKeyChanged, which is also ErrServerIdentity.
func keyChanged(profile string) error {
	return fmt.Errorf("%w (profile %q): %w", ErrServerKeyChanged, profile, ErrServerIdentity)
}

// Signature is a signature Sign made and the id of the key that made it: a signing key's id
// (transport.SigningKeyID; Keys.SigningKeys) in a shared or derived profile, the tenant key's id (its blob's) in
// a wrapped one. Store both: a profile's signing key rotates, and the key id is how a verifier picks the key.
type Signature struct {
	// Bytes is the Ed25519 signature (64 bytes, RFC 8032). Shared profile: over the data. Derived profile: over
	// transport.TenantSignedMessage(profile, tenant, data). Wrapped profile: over the data, by the tenant key.
	Bytes []byte
	// KeyID is the id of the key that signed (16 bytes).
	KeyID []byte
}

// Keys are a profile's keys as cipheron answered them, authenticated: the identity matched the pin (or was the
// one first seen), and the signing-key list and the context digest verified under the identity's response key.
type Keys struct {
	// Profile is the profile's name.
	Profile string
	// Tenancy is the profile's: shared, perTenantWrapped or perTenantDerived.
	Tenancy transport.Tenancy
	// HPKE is the profile's HPKE public key, which requests are sealed to. Identity: never rotates.
	HPKE hpke.PublicKey
	// Response is the profile's Ed25519 response public key: every answer is signed by it, and the signing-key
	// list. Identity: never rotates.
	Response ed25519.PublicKey
	// SigningKeys are every signing key the profile has ever signed with, in canonical order (ascending key id), at
	// most one active: Sign's signatures verify under the one their key id names. A key's State is active,
	// verifyOnly or revoked (listed, never signs, every signature under it refused: ErrSigningKeyRevoked). A key
	// revoked in any list this Client verified is revoked here, whatever cipheron answers now. None in a wrapped
	// profile.
	SigningKeys []transport.SigningKey
	// ContextDigest is the profile's key-context digest ("sha256:…"): cipherons that answer the same one read
	// each other's ciphertexts. A signing activation does not move it (an active and a verifyOnly key are one
	// published state in it: owner decision D-Q).
	ContextDigest string
	// Fingerprint is the identity's fingerprint (transport.Fingerprint), which WithProfileFingerprint pins:
	// `cipheron keygen` prints it. It survives every rotation.
	Fingerprint string
	// HPKESuite is the suite of the identity's HPKE key, and ResponseAlgorithm its response key's algorithm. A
	// suite this client does not implement leaves HPKE nil: the identity is pinned and its lists verify, and every
	// call that seals a payload is ErrBadResponse.
	HPKESuite         transport.HPKESuite
	ResponseAlgorithm transport.SignatureAlgorithm
	// Additional are keys added to the identity after the profile was made (covered by Fingerprint, version 2); this
	// client uses none of them.
	Additional []transport.IdentityKey
	// Statement and StatementSignature are the profile's key statement (transport.KeyStatement), verified: the most
	// recent one a PublicKey answer carried whose signing keys are SigningKeys, states included — publishable, checkable
	// offline against Fingerprint (KeyStatement). Nil when no statement this Client verified agrees with SigningKeys: a
	// lagging replica's statement lists as usable a key this Client holds revoked, and is never kept.
	Statement, StatementSignature []byte

	// statementKeys is Statement's signing keys (SigningKeys when it was kept), statementAt when this Client verified
	// it (a reading of Client.now: monotonic), and statementRevoked, with no Statement, that the statements this Client
	// was last answered list as usable a key SigningKeys holds revoked (KeyStatement's ErrSigningKeyRevoked).
	statementKeys    []transport.SigningKey
	statementAt      time.Time
	statementRevoked bool

	id transport.Identity
	// checkedUnder is the pin set these keys were checked against (fetchKeys: the set in force when the fetch began;
	// checkCachedPins: the set it checked them under): keys checked under another set than the one in force are
	// checked again before they are used.
	checkedUnder *pinSet
}

// Active is the profile's active signing key; false in a wrapped profile (or when this Client knows none: the
// active key cipheron lists was revoked in a list this Client saw earlier).
func (k *Keys) Active() (transport.SigningKey, bool) {
	for _, s := range k.SigningKeys {
		if s.State == transport.SigningKeyActive {
			return s, true
		}
	}
	return transport.SigningKey{}, false
}

// SigningKey is the listed signing key whose id is keyID, in whatever state: only an active or verify-only one
// verifies (transport.SigningKeyState.Usable).
func (k *Keys) SigningKey(keyID []byte) (transport.SigningKey, bool) {
	return findKey(k.SigningKeys, keyID)
}

func findKey(keys []transport.SigningKey, keyID []byte) (transport.SigningKey, bool) {
	if len(keyID) != transport.SigningKeyIDLen {
		return transport.SigningKey{}, false
	}
	for _, s := range keys {
		if bytes.Equal(s.KeyID, keyID) {
			return s, true
		}
	}
	return transport.SigningKey{}, false
}

// clone is a copy of k that shares no slice with it.
func (k *Keys) clone() *Keys {
	c := *k
	c.Response = bytes.Clone(k.Response)
	c.SigningKeys = cloneKeys(k.SigningKeys)
	c.Additional = cloneAdditional(k.Additional)
	c.Statement, c.StatementSignature = bytes.Clone(k.Statement), bytes.Clone(k.StatementSignature)
	c.statementKeys = cloneKeys(k.statementKeys)
	c.id = transport.Identity{Tenancy: k.id.Tenancy, HPKE: bytes.Clone(k.id.HPKE), HPKESuite: k.id.HPKESuite,
		Response: c.Response, ResponseAlgorithm: k.id.ResponseAlgorithm, Additional: cloneAdditional(k.id.Additional)}
	return &c
}

// setStatement makes stmt (signed by sig), whose signing keys are keys, the statement k holds, verified at t.
func (k *Keys) setStatement(stmt, sig []byte, keys []transport.SigningKey, t time.Time) {
	k.Statement, k.StatementSignature = bytes.Clone(stmt), bytes.Clone(sig)
	k.statementKeys, k.statementAt, k.statementRevoked = cloneKeys(keys), t, false
}

// revokesUsable reports whether keys revokes a key that other lists as usable: other is a statement that would hand
// out a key this Client holds revoked.
func revokesUsable(keys, other []transport.SigningKey) bool {
	for _, k := range keys {
		if o, ok := findKey(other, k.KeyID); ok && k.State == transport.SigningKeyRevoked && o.State.Usable() {
			return true
		}
	}
	return false
}

func cloneAdditional(keys []transport.IdentityKey) []transport.IdentityKey {
	if keys == nil {
		return nil
	}
	out := make([]transport.IdentityKey, len(keys))
	for i, e := range keys {
		out[i] = e
		out[i].PublicKey = bytes.Clone(e.PublicKey)
	}
	return out
}

func cloneKeys(keys []transport.SigningKey) []transport.SigningKey {
	if keys == nil {
		return nil
	}
	out := make([]transport.SigningKey, len(keys))
	for i, s := range keys {
		out[i] = transport.SigningKey{KeyID: bytes.Clone(s.KeyID), State: s.State, PublicKey: bytes.Clone(s.PublicKey),
			Algorithm: s.Algorithm}
	}
	return out
}

// keepRevoked is a copy of keys in which every key that one of the lists from marks revoked is revoked: a
// revocation, once seen in a list this Client verified, is never undone by a later list (monotonic).
func keepRevoked(keys []transport.SigningKey, from ...[]transport.SigningKey) []transport.SigningKey {
	out := cloneKeys(keys)
	for i := range out {
		for _, l := range from {
			if o, ok := findKey(l, out[i].KeyID); ok && o.State == transport.SigningKeyRevoked {
				out[i].State = transport.SigningKeyRevoked
			}
		}
	}
	return out
}

// rpc is the calls, over one transport.
type rpc interface {
	PublicKey(ctx context.Context, in *cipheronv1.PublicKeyRequest) (*cipheronv1.PublicKeyResponse, error)
	Encrypt(ctx context.Context, in *cipheronv1.EncryptRequest) (*cipheronv1.EncryptResponse, error)
	Decrypt(ctx context.Context, in *cipheronv1.DecryptRequest) (*cipheronv1.DecryptResponse, error)
	Sign(ctx context.Context, in *cipheronv1.SignRequest) (*cipheronv1.SignResponse, error)
	ReEncrypt(ctx context.Context, in *cipheronv1.ReEncryptRequest) (*cipheronv1.ReEncryptResponse, error)
	CreateTenantKey(ctx context.Context, in *cipheronv1.CreateTenantKeyRequest) (*cipheronv1.CreateTenantKeyResponse, error)
	RewrapTenantKey(ctx context.Context, in *cipheronv1.RewrapTenantKeyRequest) (*cipheronv1.RewrapTenantKeyResponse, error)
	EncryptBatch(ctx context.Context, in *cipheronv1.EncryptBatchRequest) (*cipheronv1.EncryptBatchResponse, error)
	DecryptBatch(ctx context.Context, in *cipheronv1.DecryptBatchRequest) (*cipheronv1.DecryptBatchResponse, error)
	ReEncryptBatch(ctx context.Context, in *cipheronv1.ReEncryptBatchRequest) (*cipheronv1.ReEncryptBatchResponse, error)
	RewrapTenantKeyBatch(ctx context.Context, in *cipheronv1.RewrapTenantKeyBatchRequest) (*cipheronv1.RewrapTenantKeyBatchResponse, error)
	Close() error
}

// Client is a cipheron client. It is safe for concurrent use.
type Client struct {
	rpcs []rpc // the pool: calls go round-robin
	next atomic.Uint64
	id   *identityState

	requestKey ed25519.PrivateKey // nil: requests carry no auth
	// requestPub is requestKey's public half (nil without one), kept apart so Close's wipe of the private key never
	// races a seal: every request payload is sealed bound to it (transport.RequestSealInfo).
	requestPub ed25519.PublicKey
	// pins are the profiles' fingerprints and key-context digests in force: the options' and the pins directory's
	// (WithEnvironment), replaced whole by the live re-read of the directory (livepins.go); never nil after newClient.
	pins atomic.Pointer[pinSet]
	// refused is profile → a key fetch or an answer of a key context the pins do not accept (ErrContextDigest): the
	// profile's cached keys are not used until a fetch that the pins accept stores keys again (contextRefused).
	refused sync.Map
	// seen is profile → *digestSet: the key-context digests verified PublicKey answers of the profile gave (pinned or
	// not), the answers' candidates without a pin and the diagnosis of an answer that verifies under no pin.
	seen        sync.Map
	live        *livePins            // the pins directory's re-read; nil without one
	requirePins bool                 // WithRequiredPins: a profile with no pin is refused, not trusted on first use
	tenantPins  map[tenantRef]string // (profile, tenant) → tenant key fingerprint
	maxMessage  int
	keysMaxAge  time.Duration // WithKeysMaxAge
	// observer is told of every call that failed with an integrity or drift error, of a retry and of a pins update
	// that was not applied (WithObserver); nil: none.
	observer func(profile, kind string)
	// retry is WithRetry's policy (retry.go); nil: a call is sent once.
	retry *RetryPolicy
	// done is closed by Close: it ends the pins directory's re-read and a retry's wait.
	done chan struct{}

	keys    sync.Map // profile → *Keys: replaced only by fetchKeys, with the same identity
	fetched sync.Map // profile → *atomic.Pointer[time.Time]: when the profile's keys were last fetched, or a Verify last tried
	fresh   sync.Map // profile → *freshness: when a list last verified, and the last failed refresh (Verify's max age)
	fetch   singleflight.Group
	// now is the clock every age is measured on: time.Now, whose readings carry the monotonic clock, so an age
	// (Time.Sub of two readings) is never moved by a step of the wall clock (NTP, an operator). Tests replace it.
	now func() time.Time

	// closed is set by Close, first: a call that starts afterwards is refused (open), and no request is signed
	// afterwards (auth). keyMu guards requestKey's BYTES: auth signs under its read lock, Close wipes under its
	// write lock, after closed is set — so no request is ever signed with a wiped key, and the wipe never runs
	// under a signature.
	closed atomic.Bool
	keyMu  sync.RWMutex
}

func newClient(rpcs []rpc, id *identityState, p *plan) *Client {
	c := &Client{rpcs: rpcs, id: id, requestKey: p.requestKey, requirePins: p.requirePins,
		tenantPins: p.tenantPins, maxMessage: p.maxMessage, keysMaxAge: p.keysMaxAge, now: time.Now,
		observer: p.observer, retry: p.retry, done: make(chan struct{})}
	c.pins.Store(&pinSet{fingerprints: p.pins, context: p.contextPins, writers: p.writerPins})
	if p.pinsDir != "" {
		c.live = &livePins{dir: p.pinsDir, interval: pinsReloadInterval, inlinePins: p.inlinePins,
			inlineContext: p.inlineContext, inlineWriters: p.writerPins, last: p.dirPins}
		go c.watchPins()
	}
	if c.requestKey != nil {
		// Public answers an ed25519.PublicKey for every ed25519.PrivateKey (whose size the options checked).
		if pub, ok := c.requestKey.Public().(ed25519.PublicKey); ok {
			c.requestPub = slices.Clone(pub)
		}
	}
	if c.keysMaxAge == 0 {
		c.keysMaxAge = DefaultKeysMaxAge
	}
	return c
}

// freshness is how old a profile's signing-key list is, for Verify's maximum age (WithKeysMaxAge): when an answer
// last verified under the profile's identity, and the last refresh that failed. Every time in it is a reading of the
// Client's clock (Client.now: time.Now), kept as a time.Time — never as Unix nanoseconds, which drop the monotonic
// reading — so an age is measured on the monotonic clock and a wall clock stepped back does not make an old list
// look new.
type freshness struct {
	// verified is when the last PublicKey answer that verified was STORED (adopted, or the same as the cached): stamped
	// only after c.keys holds the list it vouches for. nil: never.
	verified atomic.Pointer[time.Time]

	mu       sync.Mutex
	failedAt time.Time // the last refresh made for Verify's maximum age that failed
	cause    error     // its error
}

func (c *Client) freshnessOf(profile string) *freshness {
	return loadOrStoreNew[freshness](&c.fresh, profile)
}

// loadOrStoreNew is m.LoadOrStore(key, new(V)) for a map that holds nothing but *V values: the *V m holds for key,
// stored first when it holds none. A value of any other type (never stored) is dropped and a new *V stored instead.
func loadOrStoreNew[V any](m *sync.Map, key string) *V {
	for {
		v, _ := m.LoadOrStore(key, new(V))
		if p, ok := v.(*V); ok {
			return p
		}
		m.CompareAndDelete(key, v)
	}
}

// cachedKeys is the profile's keys in the cache (c.keys), and false when it holds none.
func (c *Client) cachedKeys(profile string) (*Keys, bool) {
	v, ok := c.keys.Load(profile)
	if !ok {
		return nil, false
	}
	k, ok := v.(*Keys)
	return k, ok
}

// verifiedAt records an answer that verified, stored at t: the list is as new as it gets, and no failure stands.
func (f *freshness) verifiedAt(t time.Time) {
	f.verified.Store(&t)
	f.mu.Lock()
	f.failedAt, f.cause = time.Time{}, nil
	f.mu.Unlock()
}

// age is how old the list is now, by clock, and false when it has no age a decision may rest on: never verified, or
// verified "after" now (only a clock that is not monotonic answers that; it is treated as stale — fail closed — never
// as fresh). The stamp is read BEFORE the clock: a fetch that another call completes concurrently stamps the list
// after any instant read before that stamp, and that list read against the earlier instant would look verified in the
// future — stale — and make this call fetch the keys a second time.
func (f *freshness) age(clock func() time.Time) (time.Duration, bool) {
	v := f.verified.Load()
	if v == nil {
		return 0, false
	}
	age := clock().Sub(*v)
	return age, age >= 0
}

func (f *freshness) failed(now time.Time, err error) {
	f.mu.Lock()
	f.failedAt, f.cause = now, err
	f.mu.Unlock()
}

// recentFailure is the last failed refresh when it is less than minVerifyRefresh old at now.
func (f *freshness) recentFailure(now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if since := now.Sub(f.failedAt); f.cause != nil && since >= 0 && since < minVerifyRefresh {
		return f.cause
	}
	return nil
}

// pick is the connection the next call goes on: round-robin over the pool, skipping a connection that cannot carry
// a call now — gRPC's TransientFailure (its last attempt failed, it waits out a backoff), Connecting, or Shutdown —
// while another can (Ready, or Idle: it connects at the call). When none can, the round-robin one: the call waits
// for it (WaitForReady) as before. Deep review 2026-11-12, reliability 13: a call no longer waits behind a broken
// connection while the pool has a working one.
func (c *Client) pick() rpc {
	n := uint64(len(c.rpcs))
	if n == 1 {
		return c.rpcs[0]
	}
	start := c.next.Add(1)
	for i := range n {
		r := c.rpcs[(start+i)%n]
		if s, ok := r.(stateful); !ok || usable(s.state()) {
			return r
		}
	}
	return c.rpcs[start%n]
}

// stateful is a connection that knows its state (a gRPC connection; the HTTP gateway's pool does not).
type stateful interface{ state() connectivity.State }

// usable reports whether a connection in state s carries a call now, or connects for it at once.
func usable(s connectivity.State) bool {
	return s == connectivity.Ready || s == connectivity.Idle
}

// Close closes every connection and wipes the request key — the copy the Client holds: crypto/ed25519 keeps
// each private key's expansion in a cache of its own, keyed weakly by the key's slice, until the collector
// reclaims that slice, and nothing outside the standard library can wipe it. The Client is not usable
// afterwards: every call answers ErrClosed, and sends nothing. A call in flight is cut short and answers
// ErrClosed too (over HTTP a request already written is answered as it would have been). Close may be called more
// than once, and concurrently with calls: the first closes, and returns what closing the connections returned;
// the others do nothing and return nil. No request is signed once Close has begun, and the key is wiped only
// when no signature is being made with it.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.done != nil {
		close(c.done)
	}
	var errs []error
	for _, r := range c.rpcs {
		errs = append(errs, r.Close())
	}
	c.keyMu.Lock()
	for i := range c.requestKey {
		c.requestKey[i] = 0
	}
	c.keyMu.Unlock()
	return errors.Join(errs...)
}

// open refuses a call on a closed Client, before anything is done for it.
func (c *Client) open() error {
	if c.closed.Load() {
		return ErrClosed
	}
	return nil
}

// finish turns an error of a call whose context ended, or whose connection never came up, into
// ErrServerIdentity when the last connection attempt was refused for the server's identity: a caller learns
// that it reached an impostor, not that cipheron was slow.
//
// It also tells the observer (WithObserver) of an error of a kind it watches (observe): profile is the call's.
func (c *Client) finish(ctx context.Context, profile string, err error) error {
	err = c.finishErr(ctx, err)
	c.observe(profile, err)
	return err
}

func (c *Client) finishErr(ctx context.Context, err error) error {
	if err == nil || errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrClosed) {
		return err
	}
	if c.closed.Load() && ctx.Err() == nil {
		// Close cut the call short: gRPC ends the calls of a closed connection as CANCELED, and a call that had
		// not reached its connection yet as UNAVAILABLE or CANCELED. The call's own context has not ended, so the
		// cancellation is Close's, and is said so — not left to read as the caller's.
		switch status.Code(err) {
		case codes.Canceled, codes.Unavailable:
			return fmt.Errorf("%w: %w", ErrClosed, err)
		}
	}
	last := c.id.last()
	if last == nil {
		return err
	}
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable:
		return identityFailure(last)
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return identityFailure(last)
	}
	return err
}

// Keys asks cipheron for the profile's keys now and returns them as this Client holds them afterwards: the
// identity is the cached one (another is ErrServerKeyChanged), and the signing-key list and context digest are
// the answer's when it verified under that identity and still names every key the Client knew (a rotation),
// the cached ones otherwise. The first fetch is checked against the profile's pin, and what Keys returns against the
// pins in force when it returns — keys of a context the pins narrowed away while the fetch was in flight are
// ErrContextDigest, never returned. The Keys returned are the caller's own copy.
func (c *Client) Keys(ctx context.Context, profile string) (_ *Keys, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	k, err := c.load(ctx, profile)
	if err != nil {
		return nil, err
	}
	return k.clone(), nil
}

// cached returns the profile's cached keys, fetching them once.
func (c *Client) cached(ctx context.Context, profile string) (*Keys, error) {
	k, _, err := c.cachedOrFetched(ctx, profile)
	return k, err
}

// cachedOrFetched is cached, and whether the keys were fetched for this call (fresh) rather than found cached. The
// cached keys of a profile whose last fetch or answer was of a key context the pins do not accept (contextRefused) are
// not used: the keys are fetched again, and the call fails until a replica with a pinned context answers.
func (c *Client) cachedOrFetched(ctx context.Context, profile string) (_ *Keys, fresh bool, _ error) {
	if k, ok := c.cachedKeys(profile); ok && !c.contextRefused(profile) {
		return c.checkCachedPins(ctx, profile, k)
	}
	k, err := c.load(ctx, profile)
	if err != nil {
		return nil, false, err
	}
	k, _, err = c.checkCachedPins(ctx, profile, k)
	return k, err == nil, err
}

// refuseContext marks profile's cached keys unusable after a key fetch or an answer of a key context the pins do not
// accept (ErrContextDigest): every call fetches the keys again until a fetch that the pins accept stores them.
func (c *Client) refuseContext(profile string) { c.refused.Store(profile, true) }

// contextRefused reports whether profile's cached keys are marked unusable (refuseContext).
func (c *Client) contextRefused(profile string) bool {
	_, ok := c.refused.Load(profile)
	return ok
}

// digestSet is the key-context digests verified PublicKey answers of one profile gave, the latest last, at most
// MaxContextDigestPins of them (the oldest goes first).
type digestSet struct {
	mu   sync.Mutex
	list []string
}

// add records d as the latest digest.
func (s *digestSet) add(d string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = slices.DeleteFunc(s.list, func(x string) bool { return x == d })
	s.list = append(s.list, d)
	if len(s.list) > MaxContextDigestPins {
		s.list = slices.Delete(s.list, 0, len(s.list)-MaxContextDigestPins)
	}
}

// all is a copy of the digests.
func (s *digestSet) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.list)
}

// sawContext records d, the key-context digest of a verified PublicKey answer of profile (pinned or not).
func (c *Client) sawContext(profile, d string) { loadOrStoreNew[digestSet](&c.seen, profile).add(d) }

// seenContexts are the key-context digests verified PublicKey answers of profile gave (sawContext).
func (c *Client) seenContexts(profile string) []string {
	if v, ok := c.seen.Load(profile); ok {
		if s, ok := v.(*digestSet); ok {
			return s.all()
		}
	}
	return nil
}

// leaderEndedError marks a fetch that failed because the context of the call that made it — not necessarily this
// caller's — ended.
type leaderEndedError struct{ err error }

func (e *leaderEndedError) Error() string { return e.err.Error() }
func (e *leaderEndedError) Unwrap() error { return e.err }

// load fetches the profile's keys from cipheron, one fetch at a time per profile however many calls ask, and
// reconciles them with the cache (fetchKeys). A caller whose own context is still alive retries a shared fetch
// that failed only because the context of the call that made it ended. The keys it returns are held to the pins in
// force when it returns (holdToPins), whichever pins the fetch began under.
func (c *Client) load(ctx context.Context, profile string) (*Keys, error) {
	return c.loadUnless(ctx, profile, nil)
}

// loadUnless is load, except that the call that leads a fetch first looks at the cache and, when have says the
// cached keys already answer its question, returns them without asking cipheron. A call that found a key id unknown
// and then waited for the lock-free singleflight a moment too long — after another call's fetch learnt that key —
// thus makes no second fetch (deep review 2026-11-12: a signing rotation is learnt with one PublicKey call however
// many Signs ask, not "one, usually").
func (c *Client) loadUnless(ctx context.Context, profile string, have func(*Keys) bool) (*Keys, error) {
	k, err := c.loadShared(ctx, profile, have)
	if err != nil {
		return nil, err
	}
	return c.holdToPins(profile, k)
}

// holdToPins holds keys load returns to the pins in force now. A fetch is checked against the pins in force when it
// BEGAN (fetchKeys reads them once), and a waiter of the shared fetch may have joined it under other pins still: a pins
// update that arrives while the answer is on its way — a narrow of the context pins, a fingerprint pin for the profile —
// would otherwise hand the caller keys the pins in force refuse, and Keys, KeyStatement, Verify's refresh and the
// key-id lookups use what load returns directly (CL-1, the live-pins stamping window). Keys checked under the pins in
// force cost one pointer comparison; others:
//   - an identity a fingerprint pinned since does not match is ErrServerIdentity;
//   - a key-context digest the context pins in force do not name is ErrContextDigest, and the profile's cached keys
//     are not used until a fetch the pins accept stores keys again (refuseContext) — what a fetch begun under the pins
//     in force answers;
//   - keys that satisfy the pins in force are returned stamped with them (stored so only when the cache still holds k:
//     a newer store is never undone).
func (c *Client) holdToPins(profile string, k *Keys) (*Keys, error) {
	pins := c.pinsNow()
	if k.checkedUnder == pins {
		return k, nil
	}
	if fp, ok := pins.fingerprint(profile); ok && !transport.MatchesFingerprint(profile, k.id, fp) {
		return nil, identityFailure(fmt.Errorf("the identity answered for profile %q is %s, not the pinned %s",
			profile, k.Fingerprint, fp))
	}
	if ds, ok := pins.contextDigests(profile); ok && !slices.Contains(ds, k.ContextDigest) {
		c.refuseContext(profile)
		return nil, fmt.Errorf("%w: profile %q answered key-context digest %s; this client pins %s", ErrContextDigest,
			profile, k.ContextDigest, strings.Join(ds, ", "))
	}
	stamped := k.clone()
	stamped.checkedUnder = pins
	c.keys.CompareAndSwap(profile, k, stamped)
	return stamped, nil
}

// loadShared is loadUnless's shared fetch, before holdToPins.
func (c *Client) loadShared(ctx context.Context, profile string, have func(*Keys) bool) (*Keys, error) {
	for {
		ch := c.fetch.DoChan(profile, func() (any, error) {
			if have != nil {
				if k, ok := c.cachedKeys(profile); ok && have(k) {
					return k, nil
				}
			}
			k, err := c.fetchKeys(ctx, profile)
			if err != nil && ctx.Err() != nil {
				return nil, &leaderEndedError{err}
			}
			return k, err
		})
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-ch:
			if r.Err == nil {
				k, ok := r.Val.(*Keys)
				if !ok {
					return nil, fmt.Errorf("cipheron: the fetch of profile %q's keys answered a %T, not its keys", profile, r.Val)
				}
				return k, nil
			}
			var le *leaderEndedError
			if errors.As(r.Err, &le) {
				if ctx.Err() == nil {
					continue // another caller's context ended; this one's has not
				}
				return nil, le.err
			}
			return nil, r.Err
		}
	}
}

// minVerifyRefresh is how often, at most, a Verify that names a key id the cached list does not have makes the
// Client fetch the profile's keys again. A Sign answer that names one always does (it is signed by cipheron);
// a verified signature's key id comes from whoever stored it, and must not turn every forged one into a call.
// A Verify that is not allowed its fetch answers ErrUnknownSigningKey — never (false, nil), which would read as
// a verdict on a signature nothing was checked of.
const minVerifyRefresh = 5 * time.Second

// fetchStamp is the profile's last fetch (or Verify attempt) stamp: a reading of the Client's clock, nil for none.
func (c *Client) fetchStamp(profile string) *atomic.Pointer[time.Time] {
	return loadOrStoreNew[atomic.Pointer[time.Time]](&c.fetched, profile)
}

// claimVerifyFetch reports whether a Verify naming an unknown key id may fetch the profile's keys now: none was
// fetched — or tried — within minVerifyRefresh. It stamps the ATTEMPT, before the fetch, and only one caller wins
// the stamp (compare-and-swap): while cipheron fails, forged key ids cost one PublicKey call per minVerifyRefresh,
// not one each. The interval is measured on the monotonic clock (a wall-clock step moves nothing).
func (c *Client) claimVerifyFetch(profile string) bool {
	stamp := c.fetchStamp(profile)
	last := stamp.Load()
	now := c.now()
	if last != nil {
		if since := now.Sub(*last); since >= 0 && since < minVerifyRefresh {
			return false
		}
	}
	return stamp.CompareAndSwap(last, &now)
}

// profileKeysOf is a PublicKey answer as the transport reads it, copied out of the message.
func profileKeysOf(resp *cipheronv1.PublicKeyResponse) transport.ProfileKeys {
	d := transport.ProfileKeys{
		Identity: transport.Identity{
			Tenancy:  tenancyOf(resp.GetTenancy()),
			HPKE:     bytes.Clone(resp.GetHpkePublicKey()),
			Response: bytes.Clone(resp.GetResponsePublicKey()),
		},
		ContextDigest: resp.GetContextDigest(),
		KeysSignature: bytes.Clone(resp.GetKeysSignature()),
	}
	if su := resp.GetHpkeSuite(); su != nil {
		d.HPKESuite = suiteOf(su)
	}
	d.ResponseAlgorithm = transport.SignatureAlgorithm(resp.GetResponseKeyAlgorithm())
	if add := resp.GetAdditionalIdentityKeys(); len(add) > transport.MaxAdditionalKeys {
		d.Additional = make([]transport.IdentityKey, len(add)) // refused by Identity.ValidateReceived
	} else {
		for _, a := range add {
			e := transport.IdentityKey{Role: transport.IdentityKeyRole(a.GetRole()), PublicKey: bytes.Clone(a.GetPublicKey()),
				Algorithm: transport.SignatureAlgorithm(a.GetSignatureAlgorithm())}
			if a.GetHpkeSuite() != nil {
				e.Suite = suiteOf(a.GetHpkeSuite())
			}
			d.Additional = append(d.Additional, e)
		}
	}
	if n := len(resp.GetSigningKeys()); n > transport.MaxSigningKeys {
		// Refused by ValidateSigningKeys; do not copy an unbounded list first.
		d.SigningKeys = make([]transport.SigningKey, n)
		return d
	}
	for _, s := range resp.GetSigningKeys() {
		// The state as its number: one that is not active, verifyOnly or revoked is no state (fetchKeys refuses the
		// answer once keys_signature verified). Over HTTP cipheron writes the number too (an unknown NAME would read as
		// 0 here: protojson drops it under DiscardUnknown — fail-closed).
		d.SigningKeys = append(d.SigningKeys, transport.SigningKey{KeyID: bytes.Clone(s.GetKeyId()),
			State: transport.SigningKeyStateOf(uint32(s.GetState())), PublicKey: bytes.Clone(s.GetPublicKey()),
			Algorithm: transport.SignatureAlgorithm(s.GetAlgorithm())})
	}
	transport.SortSigningKeys(d.SigningKeys)
	return d
}

// suiteOf is an HpkeSuite of the API as the transport names it (ids beyond 16 bits are kept out: refused as a suite
// no client implements, never truncated into one).
func suiteOf(s *cipheronv1.HpkeSuite) transport.HPKESuite {
	if s.GetKemId() > 0xffff || s.GetKdfId() > 0xffff || s.GetAeadId() > 0xffff {
		return transport.HPKESuite{KEM: 0xffff, KDF: 0xffff, AEAD: 0xffff}
	}
	return transport.HPKESuite{KEM: uint16(s.GetKemId()), KDF: uint16(s.GetKdfId()), AEAD: uint16(s.GetAeadId())}
}

// covers reports whether keys names every key of old (same id, same public key): a list that forgets a key the
// Client knew is an older list replayed, or a server that broke the rule that every signing key ever used stays
// listed — either way it is not adopted.
func covers(keys, old []transport.SigningKey) bool {
	for _, o := range old {
		n, ok := findKey(keys, o.KeyID)
		if !ok || !bytes.Equal(n.PublicKey, o.PublicKey) {
			return false
		}
	}
	return true
}

func sameKeys(a, b []transport.SigningKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].KeyID, b[i].KeyID) || a[i].State != b[i].State ||
			!bytes.Equal(a[i].PublicKey, b[i].PublicKey) || a[i].Alg() != b[i].Alg() {
			return false
		}
	}
	return true
}

// fetchKeys asks cipheron for the profile's keys — with a fresh request nonce, which keys_signature must be made
// over, so a recorded older answer (an older list, an older digest) is refused as not cipheron's — and reconciles
// them with the cache: none cached yet → the answer, its identity matching the profile's pin and its list verifying
// under it, is adopted; cached → the identity must be the cached one (else ErrServerKeyChanged) and the list must
// verify under it, and the list and context digest are adopted when they name every key the cached list did; the
// cached keys are kept otherwise. Either way a key revoked in the cached list or in the answer is revoked in what is
// kept (keepRevoked). Nothing that does not verify is ever adopted. fetchKeys runs alone per profile (singleflight).
//
// THE ANSWER IS AUTHENTICATED BEFORE IT IS READ. First the identity — its form, the fields cipheron always writes,
// then the cached identity or the pin — and keys_signature over the answer as received, each signing key's state the
// number it carries (transport.ReceivedSigningKeysTranscript); only then is anything the answer says interpreted. A
// value a party in the path changed therefore fails authentication: ErrServerIdentity, which the observer counts
// (server_identity). What cannot be authenticated at all is refused the same way: a tenancy this client does not
// have (its name, which the transcript and the fingerprint hold, is unknown), a response key of an algorithm it does
// not implement (nothing verifies under it), an hpke_suite, response key algorithm or signing-key algorithm left out
// (cipheron always writes them; no signature covers their absence). ErrBadResponse is kept for what an authenticated
// answer holds that this client does not have: a signing-key state that is not active, verifyOnly or revoked, which
// the response key signed. Either way nothing is cached, and no unverified value is used for anything but its check.
func (c *Client) fetchKeys(ctx context.Context, profile string) (*Keys, error) {
	pins := c.pinsNow() // one set for the whole fetch, however the directory changes meanwhile
	if _, pinned := pins.fingerprint(profile); c.requirePins && !pinned {
		return nil, pinRequired(profile)
	}
	// The key fetch is idempotent: WithRetry sends it again after a transient refusal, each attempt with a nonce of
	// its own — the one keys_signature must then be made over is the last attempt's.
	var nonce []byte
	resp, err := retryCall(ctx, c, profile, func(ctx context.Context) (*cipheronv1.PublicKeyResponse, error) {
		nonce = newNonce()
		return c.pick().PublicKey(ctx, &cipheronv1.PublicKeyRequest{Profile: profile, RequestNonce: nonce})
	})
	if err != nil {
		return nil, err
	}
	// 1. The identity. A tenancy number this client does not have names no tenancy it could put into the fingerprint
	// or the transcript, which hold the tenancy's name: such an answer cannot be authenticated.
	if t := resp.GetTenancy(); tenancyOf(t) == "" {
		return nil, identityFailure(fmt.Errorf("profile %q answered tenancy number %d, which this client does not have: "+
			"the answer cannot be authenticated", profile, int32(t)))
	}
	d := profileKeysOf(resp)
	// ValidateReceived accepts only a known tenancy, a well-formed HPKE key (a P-256 point for the classical suite), a
	// 32-byte Ed25519 response key and well-formed additional keys; a suite or an additional key this client does not
	// implement is tolerated (the identity is pinned and its lists verify), and refused for use (seal:
	// Identity.Usable).
	if err := d.Identity.ValidateReceived(); err != nil {
		return nil, identityFailure(fmt.Errorf("the identity answered for profile %q: %w", profile, err))
	}
	// What cipheron always writes and no signature covers the absence of: the fingerprint reads a missing suite or
	// algorithm as the default, so only its presence tells a cipheron answer from an edited one.
	if resp.GetHpkeSuite() == nil || resp.GetResponseKeyAlgorithm() == cipheronv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED {
		return nil, identityFailure(fmt.Errorf("the keys answered for profile %q name no HPKE suite or no response key "+
			"algorithm", profile))
	}
	var prev *Keys
	if k, ok := c.cachedKeys(profile); ok {
		prev = k
		if !prev.id.Equal(d.Identity) {
			return nil, keyChanged(profile)
		}
	}
	// The fingerprint pin, whatever is cached: a pin the pins directory added while the profile was cached (trusted on
	// first use) holds for this fetch — Keys, KeyStatement — as it holds for every other call (checkCachedPins).
	if pin, ok := pins.fingerprint(profile); ok && !transport.MatchesFingerprint(profile, d.Identity, pin) {
		return nil, identityFailure(fmt.Errorf("the identity answered for profile %q is %s, not the pinned %s",
			profile, transport.Fingerprint(profile, d.Identity), pin))
	}
	// 2. keys_signature, over the answer as received. Nothing can be verified under a response key of an algorithm
	// this client does not implement, and a list longer than any cipheron publishes is not read.
	if a := d.ResponseAlg(); !a.Implemented() {
		return nil, identityFailure(fmt.Errorf("the response key of profile %q is of algorithm %d, which this client "+
			"does not implement: nothing it signs can be verified", profile, uint32(a)))
	}
	if n := len(resp.GetSigningKeys()); n > transport.MaxSigningKeys {
		return nil, identityFailure(fmt.Errorf("the keys answered for profile %q list %d signing keys; at most %d",
			profile, n, transport.MaxSigningKeys))
	}
	received := make([]transport.ReceivedSigningKey, 0, len(resp.GetSigningKeys()))
	for _, s := range resp.GetSigningKeys() {
		if s.GetAlgorithm() == cipheronv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED {
			return nil, identityFailure(fmt.Errorf("a signing key answered for profile %q names no algorithm", profile))
		}
		received = append(received, transport.ReceivedSigningKey{KeyID: s.GetKeyId(), State: uint32(s.GetState()),
			PublicKey: s.GetPublicKey()})
	}
	if err := transport.VerifyReceivedSigningKeys(transport.Release(), d.Response, d.KeysSignature, profile, d.Tenancy, d.ContextDigest, nonce,
		received); err != nil {
		return nil, identityFailure(fmt.Errorf("the signing keys answered for profile %q are not its identity's: %w",
			profile, err))
	}
	// 3. The authenticated answer, read. A state that is none of the three (a number past revoked, or UNSPECIFIED),
	// signed by the response key: the whole answer is refused, so no key in an unknown state is ever listed, verified
	// under or signed with.
	for _, s := range received {
		if !transport.SigningKeyStateOf(s.State).Valid() {
			return nil, fmt.Errorf("%w: signing key %x of profile %q is in state %d, which is not active, verifyOnly or "+
				"revoked", ErrBadResponse, s.KeyID, profile, s.State)
		}
	}
	if err := d.Verify(transport.Release(), profile, nonce); err != nil {
		return nil, identityFailure(fmt.Errorf("the signing keys answered for profile %q are not its identity's: %w",
			profile, err))
	}
	// The key statement: the same identity, digest and list, signed without the nonce — verified as an offline
	// verifier would (against the identity's fingerprint, which matched the pin or the cached identity above), and
	// held to be exactly the fresh answer's. A statement that is missing, does not verify or says something else is
	// not cipheron's answer for this profile.
	stmt, stSig := resp.GetKeyStatement(), resp.GetKeyStatementSignature()
	st, err := transport.VerifyKeyStatement(transport.Release(), stmt, stSig, profile, transport.Fingerprint(profile, d.Identity))
	if err != nil {
		return nil, identityFailure(fmt.Errorf("the key statement answered for profile %q: %w", profile, err))
	}
	if !st.Identity.Equal(d.Identity) || st.ContextDigest != d.ContextDigest || !sameKeys(st.SigningKeys, d.SigningKeys) {
		return nil, identityFailure(fmt.Errorf("the key statement answered for profile %q is not the answer's identity, "+
			"key-context digest and signing keys", profile))
	}
	// The digest is authentic now (Verify: keys_signature covers it): it is a context of the profile, which the answers'
	// check knows from now on (verifyResponse), pinned or not.
	c.sawContext(profile, d.ContextDigest)
	// The key-context pin (WithContextDigestPin): it must be pinned. An answer that is not is not adopted — neither its
	// list nor its digest — whatever is cached, and the cached keys are not used until a fetch that the pins accept
	// stores keys again (refuseContext).
	if pins, ok := pins.contextDigests(profile); ok && !slices.Contains(pins, d.ContextDigest) {
		c.refuseContext(profile)
		return nil, fmt.Errorf("%w: profile %q answered key-context digest %s; this client pins %s", ErrContextDigest,
			profile, d.ContextDigest, strings.Join(pins, ", "))
	}
	// The list is stored FIRST and stamped fresh only then (stored): a Verify that finds the fresh stamp reads the
	// merged list — with this answer's revocations — never the one it replaces. What is stored is stamped with the pin
	// set this fetch held it to (checkedUnder), and clears a refusal of the profile's context (refuseContext).
	now := c.now()
	if prev != nil {
		keys, digest := prev.SigningKeys, prev.ContextDigest
		if covers(d.SigningKeys, prev.SigningKeys) {
			keys, digest = d.SigningKeys, d.ContextDigest
		}
		keys = keepRevoked(keys, prev.SigningKeys, d.SigningKeys)
		// The statement kept is the most recent one that agrees with the merged list, states included (owner decision
		// S9): this answer's when its list is the merged one; else the one held, when it still agrees; else none — a
		// lagging answer's statement, which lists as usable a key this Client holds revoked, is never kept (KeyStatement).
		fresh := sameKeys(d.SigningKeys, keys)
		if sameKeys(prev.SigningKeys, keys) && prev.ContextDigest == digest {
			if prev.checkedUnder != pins || fresh {
				st := prev.clone()
				st.checkedUnder = pins
				if fresh {
					st.setStatement(stmt, stSig, d.SigningKeys, now)
				}
				if c.keys.CompareAndSwap(profile, prev, st) {
					prev = st
				}
			}
			c.refused.Delete(profile)
			c.stored(profile)
			return prev, nil
		}
		k := *prev
		switch {
		case fresh:
			k.setStatement(stmt, stSig, d.SigningKeys, now)
		case prev.Statement != nil && sameKeys(prev.statementKeys, keys):
		default:
			k.Statement, k.StatementSignature, k.statementKeys, k.statementAt = nil, nil, nil, time.Time{}
			k.statementRevoked = revokesUsable(keys, d.SigningKeys) ||
				(prev.Statement != nil && revokesUsable(keys, prev.statementKeys))
		}
		k.SigningKeys, k.ContextDigest, k.checkedUnder = keys, digest, pins
		c.keys.Store(profile, &k)
		c.refused.Delete(profile)
		c.stored(profile)
		return &k, nil
	}
	var hk hpke.PublicKey
	if d.Suite() == transport.ClassicalSuite {
		if hk, err = transport.ParsePublicKey(d.HPKE); err != nil {
			return nil, identityFailure(err)
		}
	}
	k := &Keys{Profile: profile, Tenancy: d.Tenancy, HPKE: hk, Response: d.Response,
		SigningKeys: d.SigningKeys, ContextDigest: d.ContextDigest, Fingerprint: transport.Fingerprint(profile, d.Identity),
		HPKESuite: d.Suite(), ResponseAlgorithm: d.ResponseAlg(),
		Additional: cloneAdditional(d.Additional), id: d.Identity, checkedUnder: pins}
	k.setStatement(stmt, stSig, d.SigningKeys, now)
	c.keys.Store(profile, k)
	c.refused.Delete(profile)
	c.stored(profile)
	return k, nil
}

// stored stamps the profile's list, which c.keys now holds, fetched and verified now. Call it only AFTER the store.
func (c *Client) stored(profile string) {
	now := c.now()
	c.fetchStamp(profile).Store(&now)
	c.freshnessOf(profile).verifiedAt(now)
}

// tenancyOf is a tenancy as the API's enum answers it; an unknown value is no tenancy (fetchKeys refuses it as
// ErrServerIdentity: an answer of a tenancy whose name this client does not know cannot be authenticated).
func tenancyOf(t cipheronv1.Tenancy) transport.Tenancy {
	switch t {
	case cipheronv1.Tenancy_TENANCY_SHARED:
		return transport.TenancyShared
	case cipheronv1.Tenancy_TENANCY_PER_TENANT_WRAPPED:
		return transport.TenancyPerTenantWrapped
	case cipheronv1.Tenancy_TENANCY_PER_TENANT_DERIVED:
		return transport.TenancyPerTenantDerived
	}
	return ""
}

// sharedKeys returns a shared profile's cached keys, and ErrTenancy for a perTenant profile.
func (c *Client) sharedKeys(ctx context.Context, profile string) (*Keys, error) {
	k, _, err := c.sharedKeysOrFetched(ctx, profile)
	return k, err
}

// sharedKeysOrFetched is sharedKeys, and whether the keys were fetched for this call.
func (c *Client) sharedKeysOrFetched(ctx context.Context, profile string) (*Keys, bool, error) {
	k, fresh, err := c.cachedOrFetched(ctx, profile)
	if err != nil {
		return nil, false, err
	}
	if k.Tenancy != transport.TenancyShared {
		return nil, false, fmt.Errorf("%w: profile %q is %s: its calls name a tenant (Client.Tenant)", ErrTenancy, profile, k.Tenancy)
	}
	return k, fresh, nil
}

// suspect is what a call returns when an answer failed verification under the cached keys, or when cipheron
// could not open a request sealed to them: the profile's keys are fetched again to tell an identity change
// (ErrServerKeyChanged) from the rest, which is answered as orig.
func (c *Client) suspect(ctx context.Context, profile string, orig error) error {
	if _, err := c.load(ctx, profile); errors.Is(err, ErrServerKeyChanged) {
		return err
	}
	return orig
}

// fits refuses, before anything is sealed or sent, a payload whose request or answer would be larger than one
// message of this client (WithMaxMessageBytes).
func (c *Client) fits(profile string, payload int) error {
	if limit := c.maxMessage - wireOverhead - len(profile); payload > limit {
		return fmt.Errorf("%w: %d bytes, and this client's messages carry at most %d (WithMaxMessageBytes)",
			ErrTooLarge, payload, max(limit, 0))
	}
	return nil
}

// newNonce is a request_nonce: transport.NonceLen fresh random bytes.
func newNonce() []byte {
	n := make([]byte, transport.NonceLen)
	_, _ = rand.Read(n) // crypto/rand.Read never fails; it crashes the program instead
	return n
}

// auth is the request's RequestAuth, or nil without a request key: a signature over the request transcript
// (transport.RequestTranscript). op is the transcript label. It signs under keyMu's read lock and refuses once
// Close has begun (ErrClosed): Close sets closed before it takes the write lock to wipe the key, so a signature is
// either made with the whole key or not made.
func (c *Client) auth(profile string, op transport.Operation, nonce []byte, digest [32]byte) (*cipheronv1.RequestAuth, error) {
	if c.requestKey == nil {
		return nil, c.open()
	}
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	if c.closed.Load() {
		return nil, ErrClosed
	}
	ts := time.Now().UnixMilli()
	return &cipheronv1.RequestAuth{
		TimestampMs: ts,
		Signature:   ed25519.Sign(c.requestKey, transport.RequestTranscript(transport.Release(), profile, op, ts, nonce, digest)),
	}, nil
}

// verifyResponse checks an answer's response signature under the profile's response key, over the request this
// client sent (its nonce, the auth it sent — the transcript's requester is the SHA-256 of that auth's signature,
// empty without one — and reqDigest, the digest of its payload fields as the client computed them), the answer
// (respDigest) and the key-context digest of the replica that made it. A party in the path that had cipheron answer
// another request under this request's nonce gets a signature over that other request's digest, which does not
// verify here; and one that had cipheron answer a request of the same fields signed by ANOTHER key (its own entry's)
// gets a signature over another requester, which does not verify either.
//
// THE ANSWER'S KEY CONTEXT. The transcript holds the answering replica's key-context digest, which the answer does not
// carry: the client verifies the signature under the digests it accepts NOW — the profile's context pins in force
// (WithContextDigestPin), else the digests verified PublicKey answers of the profile gave (sawContext, the cached keys'
// among them). So every answer proves that the replica that made it is on an accepted context, whichever replica the
// call reached and whatever the cached keys say; a narrow of the pins holds from the next answer on. An answer that
// verifies under none of them:
//   - pinned, and it verifies under a context the profile's PublicKey answers gave but the pins do not name: a replica
//     on another context answered — ErrContextDigest, and the cached keys are not used again until a fetch that the
//     pins accept (refuseContext);
//   - else the keys are fetched again (suspect: an identity change is ErrServerKeyChanged), and the answer is tried
//     under the contexts that fetch taught: unpinned, one of them verifying it is accepted (a rollout this client had
//     not seen yet); pinned, it is ErrContextDigest; otherwise ErrServerIdentity — a replica on a context this client
//     never saw cannot be told from a party that is not the profile's cipheron. That refusal is final: WithRetry never
//     sends the call again for it. Behind several replicas an unpinned client whose key fetch reached one still on the
//     old context fails the answers of one on the new context until a fetch shows it; a rollout without such failures
//     is the context pin's widen, roll, narrow (WithContextDigestPin naming both contexts while the replicas move).
func (c *Client) verifyResponse(ctx context.Context, profile string, k *Keys, op transport.Operation, nonce []byte,
	sent *cipheronv1.RequestAuth, reqDigest, respDigest [32]byte, sig []byte) error {
	if len(sig) == 0 {
		return c.suspect(ctx, profile, identityFailure(fmt.Errorf("the %s answer for profile %q carries no response signature", op, profile)))
	}
	verifies := func(digest string) bool {
		return transport.VerifyResponseSignature(transport.Release(), k.Response, sig, profile, digest, op, nonce, sent.GetSignature(), reqDigest,
			respDigest) == nil
	}
	// accepted, and tried after it, are this call's own slices: the pin set is published to every call at once and never
	// written (pinSet), so the pins are copied — an append onto the pins' own slice would write past its length into the
	// array every concurrent call reads.
	pins, pinned := c.pinsNow().contextDigests(profile)
	var accepted []string
	if pinned {
		accepted = slices.Clone(pins)
	} else {
		accepted = append(c.seenContexts(profile), k.ContextDigest) // seenContexts is a copy
	}
	for _, d := range accepted {
		if verifies(d) {
			return nil
		}
	}
	tried := accepted
	// unpinnedContext is the answer's context when it is one the profile's verified keys gave and not one accepted.
	unpinnedContext := func() (string, bool) {
		for _, d := range c.seenContexts(profile) {
			if !slices.Contains(tried, d) {
				tried = append(tried, d)
				if verifies(d) {
					return d, true
				}
			}
		}
		return "", false
	}
	refused := func(d string) error {
		c.refuseContext(profile)
		return fmt.Errorf("%w: the %s answer for profile %q was made by a replica on key context %s; this client pins %s",
			ErrContextDigest, op, profile, d, strings.Join(pins, ", "))
	}
	if pinned {
		if d, ok := unpinnedContext(); ok {
			return refused(d)
		}
	}
	// The keys fetched again, unless a fetch another call completed since accepted was read already learnt a context
	// the answer verifies under (a signing rotation: every answer after it is under the new digest, and many calls
	// find it unknown at once) — then this call makes no second fetch. The check is unpinnedContext's own, without
	// recording what it tried: what it accepts, unpinnedContext finds below.
	learnt := func(*Keys) bool {
		for _, d := range c.seenContexts(profile) {
			if !slices.Contains(tried, d) && verifies(d) {
				return true
			}
		}
		return false
	}
	if _, err := c.loadUnless(ctx, profile, learnt); errors.Is(err, ErrServerKeyChanged) {
		return err
	}
	if d, ok := unpinnedContext(); ok {
		if pinned {
			return refused(d)
		}
		return nil
	}
	return identityFailure(fmt.Errorf("the %s answer for profile %q is not signed by the profile's response key under a "+
		"key context this client accepts", op, profile))
}

// scope is what a call is made in: a profile and its keys, and in a perTenant profile the tenant — with its key
// blob and the blob's header in a wrapped one.
type scope struct {
	profile string
	k       *Keys
	tenant  string                     // "" in a shared profile
	blob    []byte                     // a wrapped profile's tenant key blob; nil otherwise
	h       *transport.TenantKeyHeader // blob's header
	fresh   bool                       // k was fetched for this call (Verify: the list is as new as a refresh would make it)
}

// who names the scope in an error.
func (s scope) who() string {
	if s.tenant == "" {
		return fmt.Sprintf("profile %q", s.profile)
	}
	return fmt.Sprintf("tenant %q of profile %q", s.tenant, s.profile)
}

// retried sends an idempotent operation op under the scope's keys: once (twice after cipheron's start barrier
// refusal, afterStart), or — for a Client made WithRetry — again after a transient refusal (retryCall), every attempt
// a fresh request under the call's one request id. The operations whose second execution is a second effect
// (CreateTenantKey makes another key; RewrapTenantKey and RewrapTenantKeyBatch another blob) are never sent through
// it (retry.go).
func retried[T any](ctx context.Context, c *Client, s scope, op func(context.Context, scope) (T, error)) (T, error) {
	ctx, _ = withRequestID(ctx) // one request id for the call and its retries
	return retryCall(ctx, c, s.profile, func(ctx context.Context) (T, error) { return op(ctx, s) })
}

// checkCiphertext checks a ciphertext an answer carries, for a plaintext of n bytes, exactly n plus its format's
// overhead long: in a wrapped profile format 3 under the tenant key keyID; in a shared or derived one format 4 (any
// master version: the header is authenticated when cipheron opens it, and the answer's signature covers it).
//
// A ciphertext in a format this protocol does not have (transport.ErrCiphertextFormat: cipheron's magic, another
// format byte) is ErrBadResponse like any other: refused, never accepted — the plaintext is still the caller's.
func (c *Client) checkCiphertext(s scope, ct []byte, n int, keyID []byte, withAAD bool) error {
	names := transport.NamesMasterVersion
	if s.k.Tenancy.Wrapped() {
		names = transport.NamesTenantKey
	}
	kid, ok, err := ciphertextFits(transport.Release(), ct, n, names, keyID, withAAD)
	if errors.Is(err, transport.ErrCiphertextFormat) {
		// Not wrapped (%v): the answer is malformed, not the caller's input.
		return fmt.Errorf("%w: the ciphertext answered for %s is in a format this protocol does not have (%v)",
			ErrBadResponse, s.who(), err) //nolint:errorlint // the cause is named, not wrapped: not the caller's input (transport.ErrCiphertext)
	}
	if !ok {
		return fmt.Errorf("%w: the ciphertext for %s is not in the %s profile's format under the expected key for a %d-byte plaintext",
			ErrBadResponse, s.who(), s.k.Tenancy, n)
	}
	if names == transport.NamesMasterVersion {
		return c.checkWriter(s.profile, kid.MasterVersion, "a ciphertext")
	}
	return nil
}

// ciphertextFits reads ct under p and reports whether it is a ciphertext of an n-byte plaintext, exactly n plus its
// format's overhead long, whose header names names (the tenant key keyID, for NamesTenantKey), made with associated
// data exactly when withAAD (format 5 or 6 then, never 3 or 4). err is ParseKeyID's refusal.
func ciphertextFits(p *format.Policy, ct []byte, n int, names transport.Names, keyID []byte, withAAD bool,
) (transport.KeyID, bool, error) {
	kid, err := transport.ParseKeyID(p, ct)
	ok := err == nil && len(ct) == n+transport.OverheadOf(p, kid) && kid.AssociatedData == withAAD &&
		transport.NamesOf(p, kid) == names
	if names == transport.NamesTenantKey {
		ok = ok && transport.SameKeyID(kid.TenantKeyID, keyID)
	}
	return kid, ok, err
}

// checkWriter holds new data an answer made in profile — a ciphertext under master version version, or a tenant key
// blob wrapped under it (what) — to the writer pin (WithWriterVersionPin): a version the pin does not name is
// ErrContextDigest. No pin: any version.
func (c *Client) checkWriter(profile, version, what string) error {
	vs, ok := c.pinsNow().writerVersions(profile)
	if !ok || slices.Contains(vs, version) {
		return nil
	}
	return fmt.Errorf("%w: profile %q answered %s made under master key version %q; this client pins the writer to %s",
		ErrContextDigest, profile, what, version, strings.Join(vs, ", "))
}

// parseCiphertext reads the header of a ciphertext this client is asked to send, refusing what is not one of
// cipheron's (transport.ErrCiphertext: a format this protocol does not have, transport.ErrCiphertextFormat,
// included) before the operation is sent (the profile's keys are fetched first, by the first call in a profile).
func parseCiphertext(s scope, ct, aad []byte) (transport.KeyID, error) {
	kid, err := transport.ParseKeyID(transport.Release(), ct)
	if err != nil {
		return kid, fmt.Errorf("the ciphertext given for %s: %w", s.who(), err)
	}
	// The associated data the ciphertext records it needs (format 5, 6) — or does not — is checked here, before
	// anything is sent: a mismatch is never a request cipheron has to refuse.
	if err := transport.CheckAssociatedData(kid, aad); err != nil {
		return kid, fmt.Errorf("the ciphertext given for %s: %w", s.who(), err)
	}
	return kid, nil
}

// CallOption is an option of one call: Encrypt, Decrypt, ReEncrypt, their tenant forms and their batch forms.
type CallOption func(*callOptions)

type callOptions struct {
	aad, toAAD []byte
	segment    int // EncryptObject's segment size (WithSegmentSize); 0: the default
}

// WithAssociatedData binds aad — context, not a secret: a row's key, a record's type, a column's name — into the
// ciphertext (Encrypt: the new ciphertext; Decrypt and ReEncrypt: the one given, which needs exactly the associated
// data it was made with). 1 to transport.MaxAssociatedDataLen bytes; nil or empty is none. cipheron stores nothing
// of it: the application gives it again at every Decrypt. A ciphertext made with it is format 5 (shared, derived)
// or 6 (wrapped), which records that it is required.
func WithAssociatedData(aad []byte) CallOption {
	return func(o *callOptions) { o.aad = bytes.Clone(aad) }
}

// WithTargetAssociatedData is a re-encryption's associated data for the NEW ciphertext (WithAssociatedData names the
// one given): ReEncrypt, ReEncryptAcross, their tenant forms, and the caller's part of ReEncryptJSONFields',
// ReEncryptObject's and ReEncryptStream's. It must be WithAssociatedData's, byte for byte: a re-encryption keeps the
// binding. Another — or one given without WithAssociatedData, or WithAssociatedData without it — is refused before
// anything is sent (ErrAssociatedData: transport.ErrTargetAssociatedData, transport.ErrAssociatedDataChanged).
// Moving a value to another row, record or binding is a decrypt and an encrypt, which the caller's entry must be
// granted. Without either, the new ciphertext is made without associated data.
func WithTargetAssociatedData(aad []byte) CallOption {
	return func(o *callOptions) { o.toAAD = bytes.Clone(aad) }
}

func callOpts(opts []CallOption) (callOptions, error) {
	var o callOptions
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	if len(o.aad) > transport.MaxAssociatedDataLen || len(o.toAAD) > transport.MaxAssociatedDataLen {
		return o, fmt.Errorf("%w: associated data is at most %d bytes", ErrAssociatedData, transport.MaxAssociatedDataLen)
	}
	return o, nil
}

// reencryptOpts is callOpts for a re-encryption: ReEncrypt, ReEncryptAcross, their tenant forms, ReEncryptJSONFields,
// ReEncryptObject and ReEncryptStream. WithTargetAssociatedData must be WithAssociatedData's, byte for byte, or the
// call is refused here, before anything is sent (transport.CheckReEncryptAssociatedData, an ErrAssociatedData):
// WithAssociatedData without it would drop the binding without a word (transport.ErrTargetAssociatedData), other bytes
// — or some where the stored data has none — would re-bind the value (transport.ErrAssociatedDataChanged), which a
// re-encryption never does. cipheron refuses the same request, but it cannot see a helper's caller part: a helper
// always sends a composite associated data (its own binding of record and pointer, or of object id and position, then
// the caller's), so for the helpers this check is the only one.
func reencryptOpts(opts []CallOption) (callOptions, error) {
	co, err := callOpts(opts)
	if err != nil {
		return co, err
	}
	if err := transport.CheckReEncryptAssociatedData(co.aad, co.toAAD); err != nil {
		return co, fmt.Errorf("%w: pass WithTargetAssociatedData equal to WithAssociatedData (a re-encryption keeps the "+
			"binding; a re-binding is a decrypt and an encrypt)", err)
	}
	return co, nil
}

// encrypt, decrypt, reencrypt and sign send their operation in the scope (retried).
func (c *Client) encrypt(ctx context.Context, s scope, plaintext []byte, co callOptions) ([]byte, error) {
	return retried(ctx, c, s, func(ctx context.Context, s scope) ([]byte, error) { return c.encryptOnce(ctx, s, plaintext, co) })
}

func (c *Client) decrypt(ctx context.Context, s scope, ciphertext []byte, co callOptions) ([]byte, error) {
	return retried(ctx, c, s, func(ctx context.Context, s scope) ([]byte, error) { return c.decryptOnce(ctx, s, ciphertext, co) })
}

func (c *Client) reencrypt(ctx context.Context, s scope, ciphertext, to []byte, toHeader *transport.TenantKeyHeader,
	co callOptions,
) ([]byte, error) {
	return retried(ctx, c, s, func(ctx context.Context, s scope) ([]byte, error) {
		return c.reencryptOnce(ctx, s, ciphertext, to, toHeader, co)
	})
}

func (c *Client) sign(ctx context.Context, s scope, data []byte) (Signature, error) {
	return retried(ctx, c, s, func(ctx context.Context, s scope) (Signature, error) { return c.signOnce(ctx, s, data) })
}

// seal seals a request payload for op in the scope to the profile's HPKE key, bound to the transcript version and
// this client's request key (transport.RequestSealInfo). An identity this client cannot use — an HPKE suite or a
// response algorithm it does not implement (transport.Identity.Usable) — is ErrBadResponse: nothing is sealed to it.
func (c *Client) seal(s scope, op transport.Operation, payload []byte) (enc, sealed []byte, err error) {
	if err := s.k.id.Usable(); err != nil {
		return nil, nil, fmt.Errorf("%w (%s): %w", ErrBadResponse, s.who(), err)
	}
	return transport.Seal(s.k.HPKE, transport.RequestSealInfo(transport.Release(), s.profile, op, s.tenant, c.requestPub), payload)
}

func (c *Client) encryptOnce(ctx context.Context, s scope, plaintext []byte, co callOptions) ([]byte, error) {
	enc, sealed, err := c.seal(s, transport.OpEncrypt, plaintext)
	if err != nil {
		return nil, err
	}
	nonce := newNonce()
	reqDigest := transport.EncryptDigestAAD(enc, sealed, s.tenant, s.blob, co.aad)
	auth, err := c.auth(s.profile, transport.OpEncrypt, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	resp, err := c.pick().Encrypt(ctx, &cipheronv1.EncryptRequest{Profile: s.profile, Enc: enc, SealedPlaintext: sealed,
		RequestNonce: nonce, Auth: auth, Tenant: s.tenant, TenantKey: s.blob, AssociatedData: co.aad})
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			// The client sealed the request itself: cipheron could not open it, so its key may not be the cached one.
			return nil, c.suspect(ctx, s.profile, err)
		}
		return nil, err
	}
	ct := resp.GetCiphertext()
	if err := c.verifyResponse(ctx, s.profile, s.k, transport.OpEncrypt, nonce, auth, reqDigest,
		transport.CiphertextResponseDigest(ct), resp.GetResponseSignature()); err != nil {
		return nil, err
	}
	var keyID []byte
	if s.h != nil {
		keyID = s.h.KeyID
	}
	if err := c.checkCiphertext(s, ct, len(plaintext), keyID, len(co.aad) > 0); err != nil {
		return nil, err
	}
	return ct, nil
}

func (c *Client) decryptOnce(ctx context.Context, s scope, ciphertext []byte, co callOptions) ([]byte, error) {
	if _, err := parseCiphertext(s, ciphertext, co.aad); err != nil {
		return nil, err
	}
	sk, err := transport.NewOneTimeKey()
	if err != nil {
		return nil, err
	}
	recipient := sk.PublicKey().Bytes()
	nonce := newNonce()
	reqDigest := transport.DecryptDigestAAD(recipient, ciphertext, s.tenant, s.blob, co.aad)
	auth, err := c.auth(s.profile, transport.OpDecrypt, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	resp, err := c.pick().Decrypt(ctx, &cipheronv1.DecryptRequest{Profile: s.profile, RecipientPublicKey: recipient,
		Ciphertext: ciphertext, RequestNonce: nonce, Auth: auth, Tenant: s.tenant, TenantKey: s.blob,
		AssociatedData: co.aad})
	if err != nil {
		return nil, err
	}
	enc, sealed := resp.GetEnc(), resp.GetSealedPlaintext()
	if err := c.verifyResponse(ctx, s.profile, s.k, transport.OpDecrypt, nonce, auth, reqDigest,
		transport.Digest(recipient, enc, sealed), resp.GetResponseSignature()); err != nil {
		return nil, err
	}
	pt, err := transport.OpenResponsePayload(transport.Release(), sk, s.profile, transport.OpDecrypt, s.tenant, enc, sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: the plaintext for %s: %w", ErrBadResponse, s.who(), err)
	}
	return pt, nil
}

// reencryptOnce sends ReEncrypt: in a wrapped profile to (with its header) is the blob to encrypt under; nil
// otherwise.
func (c *Client) reencryptOnce(ctx context.Context, s scope, ciphertext, to []byte, toHeader *transport.TenantKeyHeader,
	co callOptions,
) ([]byte, error) {
	kid, err := parseCiphertext(s, ciphertext, co.aad)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext) - kid.Overhead()
	nonce := newNonce()
	ext := transport.ReEncryptExt{AssociatedData: co.aad, ToAssociatedData: co.toAAD}
	reqDigest := transport.ReEncryptDigestExt(ciphertext, s.tenant, s.blob, to, ext)
	auth, err := c.auth(s.profile, transport.OpReEncrypt, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	resp, err := c.pick().ReEncrypt(ctx, &cipheronv1.ReEncryptRequest{Profile: s.profile, Ciphertext: ciphertext,
		Tenant: s.tenant, TenantKey: s.blob, ToTenantKey: to, RequestNonce: nonce, Auth: auth,
		AssociatedData: co.aad, ToAssociatedData: co.toAAD})
	if err != nil {
		return nil, err
	}
	ct := resp.GetCiphertext()
	if err := c.verifyResponse(ctx, s.profile, s.k, transport.OpReEncrypt, nonce, auth, reqDigest,
		transport.CiphertextResponseDigest(ct), resp.GetResponseSignature()); err != nil {
		return nil, err
	}
	var keyID []byte
	if toHeader != nil {
		keyID = toHeader.KeyID
	}
	if err := c.checkCiphertext(s, ct, n, keyID, len(co.toAAD) > 0); err != nil {
		return nil, err
	}
	return ct, nil
}

func (c *Client) signOnce(ctx context.Context, s scope, data []byte) (Signature, error) {
	enc, sealed, err := c.seal(s, transport.OpSign, data)
	if err != nil {
		return Signature{}, err
	}
	nonce := newNonce()
	reqDigest := transport.SignDigest(enc, sealed, s.tenant, s.blob)
	auth, err := c.auth(s.profile, transport.OpSign, nonce, reqDigest)
	if err != nil {
		return Signature{}, err
	}
	resp, err := c.pick().Sign(ctx, &cipheronv1.SignRequest{Profile: s.profile, Enc: enc, SealedData: sealed,
		RequestNonce: nonce, Auth: auth, Tenant: s.tenant, TenantKey: s.blob})
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			return Signature{}, c.suspect(ctx, s.profile, err)
		}
		return Signature{}, err
	}
	sig, keyID := resp.GetSignature(), resp.GetKeyId()
	if err := c.verifyResponse(ctx, s.profile, s.k, transport.OpSign, nonce, auth, reqDigest,
		transport.SignResponseDigest(sig, keyID), resp.GetResponseSignature()); err != nil {
		return Signature{}, err
	}
	// The answer is cipheron's, for this request. The signature must still be the profile's: under the key the
	// mode says, as the client knows it — never a key the answer itself would introduce.
	if len(sig) != transport.SignatureLen || len(keyID) != transport.SigningKeyIDLen {
		return Signature{}, identityFailure(fmt.Errorf("the signature answered for %s is not a %d-byte signature under a %d-byte key id",
			s.who(), transport.SignatureLen, transport.SigningKeyIDLen))
	}
	if s.k.Tenancy.Wrapped() {
		// The blob's own key: the answer is signed over the request, whose digest holds this blob, so cipheron
		// answered for exactly this blob — which it opened, so its header's public key is the key inside.
		if !transport.SameKeyID(keyID, s.h.KeyID) || !Verify(s.h.SigningPublicKey, data, sig) {
			return Signature{}, identityFailure(fmt.Errorf("the signature answered for %s is not by the tenant key of the blob", s.who()))
		}
		return Signature{Bytes: bytes.Clone(sig), KeyID: bytes.Clone(keyID)}, nil
	}
	// The answer's key is judged on a list no older than the maximum age, as Verify judges a signature (current): a
	// replica that still holds a key revoked since this Client's list was fetched signs with it, and that signature
	// is refused here (ErrSigningKeyRevoked), not handed out. A list that is too old and cannot be fetched again is
	// ErrKeysStale: no signature is returned under a key whose state is not known.
	if s, err = c.current(ctx, s); err != nil {
		return Signature{}, err
	}
	// A key id this Client does not know is a signing rotation: it is learnt from a list that verifies under the
	// profile's identity — one fetch however many calls ask — never from the answer.
	key, ok, err := c.answeredSigningKey(ctx, s, keyID)
	if err != nil {
		return Signature{}, err
	}
	if !ok {
		return Signature{}, identityFailure(fmt.Errorf("the signature answered for %s names signing key %x, "+
			"which is not in the profile's authenticated list", s.who(), keyID))
	}
	// A key revoked in a list this Client verified: a replica that has not learnt the revocation still signs with
	// it — refused (ErrSigningKeyRevoked), as Verify refuses the signature. A verify-only key is accepted: a replica
	// lagging a signing rotation. A key of an algorithm this client does not implement: ErrBadResponse.
	if err := keyUsable(key, s.who(), ErrBadResponse); err != nil {
		return Signature{}, err
	}
	if !verifyUnder(s, key.PublicKey, data, sig) {
		return Signature{}, identityFailure(fmt.Errorf("the signature answered for %s does not verify under the "+
			"profile's signing key %x", s.who(), keyID))
	}
	return Signature{Bytes: bytes.Clone(sig), KeyID: bytes.Clone(keyID)}, nil
}

// verifyUnder checks a signature of the scope's profile under a signing key of its list: over the data in a shared
// profile, over transport.TenantSignedMessage in a derived one.
func verifyUnder(s scope, pub ed25519.PublicKey, data, sig []byte) bool {
	if s.k.Tenancy == transport.TenancyPerTenantDerived {
		return VerifyTenant(pub, s.profile, s.tenant, data, sig)
	}
	return Verify(pub, data, sig)
}

// knownSigningKey is the scope's profile signing key keyID as this Client knows it now, with nothing fetched: from
// the cache first — never older than the keys the call started with, and a revocation learnt since (keepRevoked)
// is in it — else from the keys the call started with.
func (c *Client) knownSigningKey(s scope, keyID []byte) (transport.SigningKey, bool) {
	if k, ok := c.cachedKeys(s.profile); ok {
		if key, ok := k.SigningKey(keyID); ok {
			return key, true
		}
	}
	return s.k.SigningKey(keyID)
}

// current is s with keys no older than the Client's maximum age (WithKeysMaxAge), for Verify: the keys the call
// started with when they were fetched for it or verified recently enough; else the profile's keys fetched again —
// and ErrKeysStale, wrapping the fetch's error, when that fetch fails, or failed less than minVerifyRefresh ago (a
// cipheron that is down is not asked once per Verify). Verify does not decide on a list that may miss a revocation.
func (c *Client) current(ctx context.Context, s scope) (scope, error) {
	if s.fresh {
		return s, nil
	}
	f := c.freshnessOf(s.profile)
	age, known := f.age(c.now)
	if known && age <= c.keysMaxAge {
		return s, nil
	}
	now := c.now()
	stale := func(cause error) error {
		when := "has no age this client can measure"
		if known {
			when = fmt.Sprintf("was last verified %s ago", age.Round(time.Second))
		}
		return fmt.Errorf("%w (%s: the key list %s, and the maximum is %s): %w", ErrKeysStale, s.who(), when,
			c.keysMaxAge, cause)
	}
	if cause := f.recentFailure(now); cause != nil {
		return s, stale(cause)
	}
	k, err := c.load(ctx, s.profile)
	if err != nil {
		if ctx.Err() == nil { // the call's own end is not cipheron's failure
			f.failed(c.now(), err)
		}
		return s, stale(err)
	}
	s.k, s.fresh = k, true
	return s, nil
}

// answeredSigningKey is the scope's profile signing key keyID, an id a Sign answer named: known, or learnt from
// the profile's keys fetched again — always, whatever was fetched when: the answer is signed by cipheron, so the
// id is cipheron's word, not a stranger's. False when the fresh list does not name it either.
func (c *Client) answeredSigningKey(ctx context.Context, s scope, keyID []byte) (transport.SigningKey, bool, error) {
	if key, ok := c.knownSigningKey(s, keyID); ok {
		return key, true, nil
	}
	if len(keyID) != transport.SigningKeyIDLen {
		return transport.SigningKey{}, false, nil
	}
	k, err := c.loadUnless(ctx, s.profile, func(k *Keys) bool {
		_, ok := k.SigningKey(keyID)
		return ok
	})
	if err != nil {
		return transport.SigningKey{}, false, err
	}
	key, ok := k.SigningKey(keyID)
	return key, ok, nil
}

// verify checks sig under the scope's profile signing key keyID, an id a caller handed to Verify: known, or learnt
// from the profile's keys fetched again at most every minVerifyRefresh (claimVerifyFetch), from a list no older than
// the maximum age (current: else ErrKeysStale). It answers (false, nil) only for a key this Client knows, usable,
// under which sig does not verify; a key id it could not resolve — the fetch not allowed now, the fetch failed, or a
// fresh list that does not name it — is ErrUnknownSigningKey, which says that nothing was verified; a revoked key is
// ErrSigningKeyRevoked and a key of an algorithm this client does not implement ErrBadResponse, whatever the bytes.
func (c *Client) verify(ctx context.Context, s scope, data, sig, keyID []byte) (bool, error) {
	s, err := c.current(ctx, s)
	if err != nil {
		return false, err
	}
	key, ok := c.knownSigningKey(s, keyID)
	if !ok {
		if len(keyID) != transport.SigningKeyIDLen {
			return false, unknownKey(s, keyID, fmt.Sprintf("a signing key id is %d bytes, not %d", transport.SigningKeyIDLen, len(keyID)), nil)
		}
		if s.fresh {
			// The list was fetched for this very call (the Client's first in the profile): fetching it again would
			// answer the same, and "try again" would be wrong.
			return false, unknownKey(s, keyID, "the profile's key list, fetched now, does not name it", nil)
		}
		if !c.claimVerifyFetch(s.profile) {
			return false, unknownKey(s, keyID, fmt.Sprintf("it is not in the profile's key list as last fetched, and the list is "+
				"fetched again for an unknown key id at most every %s: try again then", minVerifyRefresh), nil)
		}
		k, err := c.load(ctx, s.profile)
		if err != nil {
			return false, unknownKey(s, keyID, "the profile's keys could not be fetched again", err)
		}
		if key, ok = k.SigningKey(keyID); !ok {
			return false, unknownKey(s, keyID, "the profile's key list, fetched again now, does not name it", nil)
		}
	}
	if err := keyUsable(key, s.who(), ErrBadResponse); err != nil {
		return false, err
	}
	return verifyUnder(s, key.PublicKey, data, sig), nil
}

// Encrypt has cipheron encrypt plaintext in the shared profile and returns the ciphertext to store (format 4,
// naming the master version it was made under), after checking the answer's response signature and the
// ciphertext's format.
func (c *Client) Encrypt(ctx context.Context, profile string, plaintext []byte, opts ...CallOption) (_ []byte, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	if err := c.fits(profile, len(plaintext)+len(co.aad)+maxCiphertextOverhead()); err != nil {
		return nil, err
	}
	k, err := c.sharedKeys(ctx, profile)
	if err != nil {
		return nil, err
	}
	return c.encrypt(ctx, scope{profile: profile, k: k}, plaintext, co)
}

// Decrypt has cipheron decrypt a ciphertext of the shared profile — format 4, or 5 with associated data — and returns the plaintext, after checking the answer's response signature.
func (c *Client) Decrypt(ctx context.Context, profile string, ciphertext []byte, opts ...CallOption) (_ []byte, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	if err := c.fits(profile, len(ciphertext)+len(co.aad)); err != nil {
		return nil, err
	}
	k, err := c.sharedKeys(ctx, profile)
	if err != nil {
		return nil, err
	}
	return c.decrypt(ctx, scope{profile: profile, k: k}, ciphertext, co)
}

// ReEncrypt has cipheron decrypt a stored ciphertext of the shared profile and encrypt the same plaintext again
// under the current master version, without the plaintext leaving cipheron, and returns the new
// ciphertext (format 4, or 5 with associated data) after checking the answer. It is how a
// service moves its rows to new keys; reading never needs it. WithTargetAssociatedData must be WithAssociatedData's:
// the new ciphertext keeps the binding (reencryptOpts).
func (c *Client) ReEncrypt(ctx context.Context, profile string, ciphertext []byte, opts ...CallOption) (_ []byte, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	if err := c.fits(profile, len(ciphertext)+len(co.aad)+len(co.toAAD)+maxCiphertextOverhead()); err != nil {
		return nil, err
	}
	k, err := c.sharedKeys(ctx, profile)
	if err != nil {
		return nil, err
	}
	return c.reencrypt(ctx, scope{profile: profile, k: k}, ciphertext, nil, nil, co)
}

// Sign has cipheron sign data with the shared profile's active signing key and returns the signature and the id
// of the key that made it, after verifying the answer's response signature and the signature under the key its
// id names in the profile's authenticated key list (fetched again, once, when the id is one this Client does not
// know: a signing rotation).
func (c *Client) Sign(ctx context.Context, profile string, data []byte) (_ Signature, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return Signature{}, err
	}
	if err := c.fits(profile, len(data)); err != nil {
		return Signature{}, err
	}
	k, err := c.sharedKeys(ctx, profile)
	if err != nil {
		return Signature{}, err
	}
	return c.sign(ctx, scope{profile: profile, k: k}, data)
}

// Verify reports whether sig is the shared profile's signature over data under its signing key keyID (Sign's
// Signature.KeyID). The check is LOCAL: the only thing it ever asks cipheron for is the profile's keys — the same
// cache Encrypt and Sign use, fetched again when it is older than WithKeysMaxAge, and (at most every
// minVerifyRefresh) when keyID is not in it — and neither data nor sig is sent anywhere.
//
// Its three answers are three different things:
//   - (true, nil): sig verifies under the profile's key keyID, active or verify-only;
//   - (false, nil): keyID names a usable key of the profile this Client knows, and sig does NOT verify under it —
//     the signature is not the profile's over data;
//   - (false, an error): nothing was verified, or the key may not be used. ErrSigningKeyRevoked when keyID names a
//     key the profile revoked (in this list or any earlier one this Client verified), whatever the bytes;
//     ErrBadResponse when it names a key of an algorithm this client does not implement; ErrKeysStale when the list was older
//     than the maximum age and could not be fetched again (the error wraps the fetch's); ErrUnknownSigningKey when
//     keyID names no key this Client knows and could not be resolved — the key list was fetched too recently to be
//     fetched again (try again in a few seconds: a signing rotation is learnt then), the fetch failed (the error
//     wraps the fetch's too), or a list fetched now does not name it; the error of the first fetch of the profile's
//     keys (a status, ErrServerIdentity, ErrPinRequired, ErrBadResponse); ErrTenancy for a perTenant profile;
//     ErrClosed; the context's.
//
// A caller must not treat ErrUnknownSigningKey or ErrKeysStale as "forged": after a signing rotation a genuine
// signature under the new key is ErrUnknownSigningKey until this Client has fetched the new list. The raw-key
// Verify below knows nothing of states: it checks the bytes under the key it is given, revoked or not.
func (c *Client) Verify(ctx context.Context, profile string, data, sig, keyID []byte) (_ bool, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return false, err
	}
	k, fresh, err := c.sharedKeysOrFetched(ctx, profile)
	if err != nil {
		return false, err
	}
	return c.verify(ctx, scope{profile: profile, k: k, fresh: fresh}, data, sig, keyID)
}

// Verify checks an Ed25519 signature a shared profile's Sign made, under the signing public key its key id names.
// It runs locally: it needs no cipheron, no socket and no permission on the profile. It is STATE-AGNOSTIC: it checks
// the bytes under pub whatever state the profile gives that key — a revoked key's signature verifies here. That is on
// purpose (an application with trusted evidence of its own of when a signature was made applies its own policy
// with it); a verifier without such evidence uses VerifyWithKeys or Client.Verify, which refuse a revoked key.
func Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, data, sig)
}

// VerifyTenant checks a derived profile's signature for tenant over data (over transport.TenantSignedMessage), under
// the profile's signing public key its key id names. It runs locally, and is state-agnostic as Verify is.
func VerifyTenant(pub ed25519.PublicKey, profile, tenant string, data, sig []byte) bool {
	return transport.VerifyTenant(pub, profile, tenant, data, sig) == nil
}

// VerifyWithKeys checks a shared profile's signature over data under the key keyID names in keys (Keys.SigningKeys,
// kept by a verifier that has no cipheron), with Verify's answers: (true, nil) when the signature verifies under that
// key, active or verify-only; (false, nil) when it does not; and (false, an error) when nothing was verified —
// ErrSigningKeyRevoked for a key the list marks revoked (whatever the bytes), ErrUnknownSigningKey for a key id the
// list does not name (or not transport.SigningKeyIDLen bytes), and ErrInvalidKeyList for a list that is not one
// profile's (a key id twice, a key under an id that is not its public key's, a state that is not one of the three)
// whatever key id is asked about, or for a key of an algorithm this client does not implement. It decides on the list it is given:
// keep that list fresh (Keys) for a revocation to reach it, and pass it alone — never joined with an older one. It
// knows no tenancy: a list is only a list, so the caller chooses VerifyWithKeys for a SHARED profile's signature and
// VerifyTenantWithKeys for a DERIVED profile's — KeyStatement.Verify and VerifyTenant make that choice from the
// statement's tenancy, and refuse the other (ErrTenancy).
func VerifyWithKeys(keys []transport.SigningKey, data, sig, keyID []byte) (bool, error) {
	k, err := listedKey(keys, keyID)
	if err != nil {
		return false, err
	}
	return Verify(k.PublicKey, data, sig), nil
}

// VerifyTenantWithKeys is VerifyWithKeys for a derived profile's signature for tenant, with the same answers. Like
// VerifyWithKeys it knows no tenancy: the caller chooses it for a derived profile's signature (KeyStatement.VerifyTenant
// chooses from the statement).
func VerifyTenantWithKeys(keys []transport.SigningKey, profile, tenant string, data, sig, keyID []byte) (bool, error) {
	k, err := listedKey(keys, keyID)
	if err != nil {
		return false, err
	}
	return VerifyTenant(k.PublicKey, profile, tenant, data, sig), nil
}

// listedKey is the usable key keyID names in keys, for the offline verifications. The whole list is checked first
// (checkKeyList): with an id listed twice, the first match would decide, and list order whether a revoked key
// verifies.
func listedKey(keys []transport.SigningKey, keyID []byte) (transport.SigningKey, error) {
	if err := checkKeyList(keys); err != nil {
		return transport.SigningKey{}, err
	}
	k, ok := findKey(keys, keyID)
	if !ok {
		return k, fmt.Errorf("%w (key id %x): the list given does not name it", ErrUnknownSigningKey, keyID)
	}
	return k, keyUsable(k, "the list given", ErrInvalidKeyList)
}

// checkKeyList is ErrInvalidKeyList for a list that is not one profile's: a key id twice, a key whose id is not its
// public key's, or a key in a state that is not active, verifyOnly or revoked. It does not count active keys (a
// list this Client kept may have none: its active key revoked in a later list), nor the length (an empty list names
// nothing: ErrUnknownSigningKey).
func checkKeyList(keys []transport.SigningKey) error {
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		badLen := len(k.PublicKey) == 0 || len(k.PublicKey) > transport.MaxIdentityKeyLen ||
			(k.Alg() == transport.AlgorithmEd25519 && len(k.PublicKey) != ed25519.PublicKeySize)
		if badLen || !bytes.Equal(k.KeyID, transport.SigningKeyIDOf(k.Alg(), k.PublicKey)) {
			return fmt.Errorf("%w: key id %x is not the id of the public key listed under it", ErrInvalidKeyList, k.KeyID)
		}
		if !k.State.Valid() {
			return fmt.Errorf("%w: key id %x is in state %q, which is not active, verifyOnly or revoked", ErrInvalidKeyList,
				k.KeyID, k.State)
		}
		if _, dup := seen[string(k.KeyID)]; dup {
			return fmt.Errorf("%w: key id %x is listed twice (two lists joined?): pass one list, as Keys returns it",
				ErrInvalidKeyList, k.KeyID)
		}
		seen[string(k.KeyID)] = struct{}{}
	}
	return nil
}

// maxCiphertextOverhead is the most a ciphertext of any format this release reads adds to its plaintext: what a
// request's size check allows for before it knows the format cipheron writes.
func maxCiphertextOverhead() int {
	_, overhead, _ := format.Bounds(transport.Release(), transport.Ciphertexts())
	return overhead
}
