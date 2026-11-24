// Package cipheron is the Go library an application uses to talk to cipheron, the per-profile crypto service:
// as a sidecar on its host (a unix socket) or as a service on the network (mutual TLS). It is the whole
// client: the application calls Encrypt, Decrypt, ReEncrypt and Sign with a profile name and its bytes, and never
// deals with the API underneath (gRPC), with TLS, with HPKE, or with a key. Signatures are checked locally: with
// the Client's Verify, which fetches only the profile's public keys, or with the package-level Verify functions,
// anywhere, without cipheron.
//
//	// a sidecar: cipheron's image runs as uid 10443, a uid reserved for it
//	c, err := cipheron.New("/run/cipheron/private/cipheron.sock", cipheron.WithServerUID(10443),
//		cipheron.WithProfileFingerprint("credentials", "sha256:…")) // what `cipheron keygen ensure` printed
//	// or a sidecar the cipheron-sidecar chart installed: the same, from the environment it sets
//	c, err := cipheron.New("", cipheron.WithEnvironment())
//	// or a service
//	c, err := cipheron.New("cipheron.prod.svc:8443",
//		cipheron.WithTLSFiles("/etc/app/tls/tls.crt", "/etc/app/tls/tls.key", "/etc/app/tls/ca.crt"),
//		cipheron.WithServerSPIFFEID("spiffe://prod.example.org/cipheron"),
//		cipheron.WithRequestKeyFile("/etc/app/cipheron/request.key"), // made with OpenSSL 3
//		cipheron.WithProfileFingerprint("credentials", "sha256:…"))
//	if err != nil { ... }
//	defer c.Close()
//
//	ct, err := c.Encrypt(ctx, "credentials", plaintext) // store ct
//	pt, err := c.Decrypt(ctx, "credentials", ct)
//
//	sig, err := c.Sign(ctx, "credentials", document)   // store sig.Bytes AND sig.KeyID
//	ok, err := c.Verify(ctx, "credentials", document, sig.Bytes, sig.KeyID) // local
//	keys, err := c.Keys(ctx, "credentials")            // hand keys.SigningKeys to whoever verifies offline
//	ok, err := cipheron.VerifyWithKeys(keys.SigningKeys, document, sig.Bytes, sig.KeyID)
//
// A Client is safe for concurrent use and keeps a small pool of connections (WithConnections); create it once.
// New does not connect: the first call does, and waits for cipheron until its context ends, so an application
// may start before cipheron has unsealed its keys. A server that fails the checks below does not make a call
// wait: it fails with ErrServerIdentity. Nor does cipheron refusing this client's certificate on the network (a
// identity no profile lists): the call fails with ErrPermissionDenied as soon as the refusal arrives, and the next
// call tries a new connection.
//
// ONE CLIENT FOR THE PROCESS, NOT ONE PER REQUEST. Make it at start-up, share it, and Close it at shutdown. A new
// Client is not cheap: New reads its files again (the request key, the TLS certificate, key and CA bundle, the
// pins directory) and makes its gRPC channels (two, unless WithConnections says otherwise); its first call opens a
// connection — on the network a TCP and a mutual-TLS handshake, on the socket a connect and the check of
// cipheron's uid — and fetches the profile's keys (one PublicKey round trip per profile) before the call itself
// goes out; and nothing a previous Client learnt (a profile's keys, a signing rotation) is carried over. And a
// Client that is not closed keeps its connections: cipheron bounds the connections one caller may have open
// (maxConnectionsPerCaller, 32 unless configured) and closes the ones beyond it, without an answer — which to a
// client is a server that is not up yet. A process that makes a Client per request and does not close each one
// therefore runs into that bound, and from then on its calls do not fail: they wait, until their deadlines. Call
// Close (it is safe to call twice, and concurrently with calls).
//
// # Tenancy
//
// A profile is one of three tenancies, fixed for its life (Keys.Tenancy):
//   - shared (TenancyShared): one set of keys for every caller. The Client's own Encrypt, Decrypt, ReEncrypt,
//     Sign and Verify.
//   - perTenant WRAPPED (TenancyWrapped): every tenant has a key of its own — a storage key and an Ed25519
//     signing key — that cipheron makes (CreateTenantKey, operation provision) and returns WRAPPED, as a blob the
//     application stores with its tenant record; cipheron keeps nothing. Every call carries the tenant and its
//     blob: Tenant(profile, tenant, blob). Deleting a tenant's blobs erases the tenant (crypto-shredding).
//     Signatures are by the tenant key (Signature.KeyID is the blob's key id) and verify under the blob's signing
//     public key (ReadTenantKey).
//   - perTenant DERIVED (TenancyDerived): every tenant's keys are derived from the profile's keys and the tenant
//     id; nothing is stored anywhere. Every call carries the tenant only: Tenant(profile, tenant, nil). cipheron's
//     configuration names no tenant: which service may act for a tenant, and when a tenant is no longer served, is
//     the application's to decide. Signatures are by the PROFILE's signing keys over a tenant-bound message
//     (VerifyTenant): one made for one tenant never verifies as another's.
//
// The Client's own calls refuse a perTenant profile, and the tenant calls a shared one (ErrTenancy).
//
// # Rotation, from the application's side
//
// cipheron rotates keys by configuration only — new master key versions, signing-key versions — and the
// application has nothing to do:
//   - every ciphertext names the key it was made under (KeyID: the master version, or the tenant key):
//     old data keeps decrypting with no action, for as long as cipheron lists its key version. Decrypt never
//     needs a re-encryption first;
//   - ReEncrypt (operation reencrypt) moves a stored ciphertext to the current keys without the plaintext leaving
//     cipheron — optional, for a service that wants its rows on new keys (lazily on read, or a background sweep
//     that finds rows with KeyID). In a wrapped profile Tenant.ReEncrypt moves a row to another tenant key blob
//     (the tenant's new key, from CreateTenantKey), and RewrapTenantKey moves a blob to cipheron's current
//     wrapping key, the same tenant key inside;
//   - a pin (WithProfileFingerprint) names the profile's IDENTITY — its HPKE and response keys, which never rotate
//     — so pins survive every rotation. A signing rotation changes the profile's signing-key LIST, which the
//     response key signs: this library adopts a new list when it verifies under the pinned identity, and refuses
//     one that does not;
//   - a signature carries the id of the key that made it (Signature.KeyID): store it with the signature. Every
//     signing key ever used stays listed, so old signatures keep verifying — except under a key the operator
//     REVOKED (a compromise: SigningKeyRevoked), whose signatures Verify and VerifyWithKeys refuse with
//     ErrSigningKeyRevoked from then on. Verify fetches the profile's list again when it is older than
//     WithKeysMaxAge (5 minutes by default) so a revocation reaches it, and once it has seen a key revoked it never
//     un-revokes it;
//   - a ciphertext whose key version cipheron no longer lists (retired by its configuration) is
//     ErrKeyVersionUnavailable: the data is not lost and the ciphertext not corrupt — listing the version again
//     makes it decrypt.
//
// # What travels
//
// A plaintext to encrypt and data to sign leave this process sealed (HPKE) to the profile's HPKE public key; a
// decrypted plaintext comes back sealed to a key made for that one call; ReEncrypt and RewrapTenantKey carry no
// plaintext at all. Nothing readable crosses the socket or the network, and on the network that holds inside TLS
// too: a proxy that terminates TLS on the way sees sealed payloads only.
//
// # Request keys
//
// A caller may hold an Ed25519 request key (WithRequestKeyFile; in production whoever owns the caller's secrets
// makes the pair with OpenSSL 3, `cipheron keygen caller` being for development only, and the public half goes
// into the profile's caller entry). Every request but the key fetch then carries a signature by
// it over the profile, the operation, the time, a fresh nonce and the payload, which cipheron checks and accepts
// once: an intermediary that holds this process's connection identity — a proxy that terminates TLS, with a
// certificate of the same identity — can neither forge, replay nor redirect a request. On the network a request
// key is required (New refuses a network address without one); on the socket it is required when the profile's
// caller entry has one. The Client signs with ONE key; a caller entry may list two, so a caller rolls its key by
// adding the new public key to its entry, deploying the new private key, then removing the old public key.
//
// # Who is on the other end
//
// cipheron decides who may use a profile, and for which operations, from this process's identity — on the socket its
// user and group ids as the kernel reports them, on the network the identity of the client certificate it presents (a
// SPIFFE ID, a URI, a DNS name or an e-mail address, as cipheron's trust bundle for its CA reads it) — and from the
// request key's signature. In the other direction, this library checks the server three ways:
//   - the connection: on the socket, WithServerUID refuses any process on the socket path that does not run as
//     cipheron's uid (a socket address needs WithServerUID, or the explicit opt-out WithAnyServer); on the
//     network the server's certificate is verified against the CA bundle given (never the system's roots) — by
//     its hostname, or by its SPIFFE ID with WithServerSPIFFEID;
//   - the profile's keys: its identity is fetched once per profile and cached for the Client's life. With
//     WithProfileFingerprint it must match the fingerprint `cipheron keygen ensure` printed; without it the
//     identity first seen is trusted (trust on first use) — never with WithEnvironment in production, where a pin
//     is required for every profile (WithEnvironment). Either way, a later answer with another identity is
//     ErrServerKeyChanged and is never adopted. The signing-key list and the key-context digest must verify under
//     the identity's response key;
//   - every answer: signed by the profile's response key over this request (its nonce, its signature, its payload)
//     and the answer; a ciphertext checked for the format and key the profile's tenancy writes; a signature checked
//     under the key its key id names in the profile's authenticated list (a key id this Client does not know makes
//     it fetch the list again, once — a signing rotation); a tenant key blob checked to be the one asked for. An
//     answer that fails is never returned.
//
// With a pin, then, a party that is not the profile's cipheron — on the socket path or anywhere on the network —
// can neither read a payload nor have any answer of its own accepted.
//
// # The protocol version
//
// Everything signed or sealed — a request, an answer, a key list, a request's payload — is a transcript of
// wire/transport that binds the protocol's one transcript version (transport.TranscriptVersion). Nothing is
// negotiated: this library and cipheron are built from one API. An answer that holds what this protocol does not
// have — a tenancy, a signing-key state, a ciphertext format, a tenant key blob version — is refused
// (ErrBadResponse), and so is bytes the caller hands in of a format or version it does not have (ErrInvalidInput).
//
// # Errors
//
// A call's error is, with three exceptions, one of the values below, wrapped with the reason; test them with
// errors.Is, never by the message. Several hold at once where one is a kind of another: ErrBusy and ErrNoWriter
// are ErrUnavailable, ErrCertificateRefused is ErrPermissionDenied, ErrServerKeyChanged and ErrPinRequired are
// ErrServerIdentity, ErrTenantKey is ErrInvalidInput. The exceptions:
//   - New's errors are configuration errors — an option, a file, the environment — and are none of the values: a
//     plain error that names what is wrong. Nothing is to be retried; fix the configuration. One is a value:
//     WithEnvironment with pins required (WithRequiredPins, or a production environment) and no pin at all — an
//     empty pins directory, or none in production — is ErrPinRequired, the answer each call would have given;
//   - a call cut short by its own context returns the context's error BARE (context.DeadlineExceeded or
//     context.Canceled themselves; errors.Is and == both match). An answer cipheron gave (a refusal, a size) is
//     still reported as such when the context ended at the same moment; and a context that ended is not the answer
//     when the server was refused for its identity (ErrServerIdentity, not a timeout) or cipheron refused this
//     client's certificate (ErrPermissionDenied);
//   - an answer of a kind this package has no value for — a status code cipheron does not use — is an error that
//     wraps it, and none of the values.
//
// The error cipheron answered is kept in the chain: an error made from an answer still carries the gRPC status
// (google.golang.org/grpc/status.FromError and status.Code read it, with its details — the google.rpc.ErrorInfo
// and RetryInfo), and RetryAfter reads the delay cipheron asked for. An error answer is not signed by the
// profile's response key (only answers are): it is as trustworthy as the connection — WithServerUID on the socket,
// the server's certificate on the network — and no more.
//
// What a service does with each:
//   - ErrBusy: cipheron is at a limit; wait RetryAfter (a second, unless it says otherwise; bound it) and try again;
//   - ErrNoWriter: this cipheron writes nothing now (a write only); another replica may, and reads work — try
//     again on another connection, or later; waiting a second does not help by itself;
//   - ErrUnavailable otherwise: shutting down, a broken connection, or a RESOURCE_EXHAUSTED that is neither
//     cipheron's busy nor a size refusal (something on the way) — try again with a backoff;
//   - ErrTooLarge, ErrInvalidInput, ErrKeyVersionUnavailable, ErrTenancy, ErrTenantKey: the same call fails the
//     same way; do not retry it;
//   - ErrPermissionDenied: not until the configuration (or the certificate, ErrCertificateRefused) changes;
//   - ErrServerIdentity: do not retry blindly — an impostor may be answering. ErrPinRequired is a missing pin (this
//     application's configuration); ErrServerKeyChanged needs an operator, and a new Client; anything else is the
//     server's identity failing a check;
//   - ErrBadResponse, ErrInternal: a defect; report it;
//   - ErrUnsupported: the server does not have the call — retrying does not help;
//   - ErrSigningKeyRevoked (Verify, VerifyWithKeys): the signature is under a key the profile revoked: do not accept
//     it, whatever the bytes. Re-sign what must stay verifiable;
//   - ErrUnknownSigningKey (Verify): nothing was verified — not "forged"; try again in a few seconds;
//   - ErrKeysStale (Verify): the profile's key list was too old and cipheron could not be asked for a new one —
//     nothing was verified; try again when cipheron is reachable;
//   - ErrClosed: this Client was closed; make a new one.
package cipheron

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/internal/client"
	"github.com/nnicora/cipheron/wire/transport"
)

var (
	// ErrPermissionDenied: this process may not use the profile, or not for this operation, or its request
	// signature did not verify (a wrong request key, a replayed request, a clock too far off), or no such profile
	// exists — cipheron gives all of them the same answer, so a caller cannot learn which profiles exist. On the
	// network it is also cipheron refusing this client's certificate in the TLS handshake — an identity no profile
	// lists or outside its trust bundle's scope, a chain no trust bundle verifies — told by a TLS alert the server
	// this client verified sent (TLS 1.3); cipheron's log has the reason. That fails the call at once, not at
	// its deadline, and does not stick: the next call tries a new connection. (A TLS 1.2 server's alert is not
	// authenticated, so over TLS 1.2 the call waits for a connection as for a server not up yet.) That case is
	// ErrCertificateRefused too.
	ErrPermissionDenied = errors.New("cipheron: permission denied")
	// ErrCertificateRefused: cipheron refused this client's CERTIFICATE in the TLS handshake — not a call: no
	// profile lists its identity, the identity is outside its trust bundle's scope, or the chain does not verify
	// against cipheron's trust bundles (cipheron's log has the reason). Every error that is ErrCertificateRefused is
	// ErrPermissionDenied too; test this one to tell "the certificate" from "this call in this profile". It is
	// internal/client.ErrCertificateRefused, the same value.
	ErrCertificateRefused = client.ErrCertificateRefused
	// ErrInvalidInput: cipheron refused what it was given — a ciphertext that is not cipheron's, was modified,
	// or belongs to another profile, tenant or tenant key — or the library refused it before sending the operation
	// (bytes that are not a cipheron ciphertext: KeyID's refusal, which Decrypt and ReEncrypt apply after the
	// profile's keys were fetched; a ciphertext of a format this protocol does not have among them).
	// ErrKeyVersionUnavailable is not it; ErrTenantKey is.
	ErrInvalidInput = errors.New("cipheron: invalid input")
	// ErrKeyVersionUnavailable: the ciphertext (or tenant key blob) was made under a key version cipheron does not
	// have — a master key version its configuration no longer lists, or one not rolled out to this replica yet. The data is NOT lost and NOT corrupt: retirement only refuses, and listing the version
	// again (or finishing the rollout) makes it readable. KeyID names the version. It is not ErrInvalidInput.
	// cipheron answers it INVALID_ARGUMENT with the google.rpc.ErrorInfo of transport.ReasonKeyVersionUnavailable,
	// which is what this package maps — never the message.
	ErrKeyVersionUnavailable = errors.New("cipheron: the key version is not available")
	// ErrTooLarge: the data is larger than this Client sends or receives in one message (WithMaxMessageBytes),
	// refused before anything is sent; or larger than cipheron accepts in one call (its listener's
	// maxRequestBytes: by default room for one segment of the largest size, 64 MiB at most; or, for a request that
	// declares no size, its undeclaredMaxRequestBytes). cipheron's refusal is RESOURCE_EXHAUSTED with NO details and
	// gRPC's wording ("… larger than max …", "message too large") — gRPC's own, or cipheron's, which carries the same
	// words — the one place this package reads a message, because a size refusal has nothing else to be told by, and
	// the wording is the vendored gRPC's, pinned by a test. A RESOURCE_EXHAUSTED that is neither that
	// nor cipheron's busy answer is ErrUnavailable, not ErrTooLarge: a proxy or a mesh shedding load says the same
	// code, and must not read as "this data can never be sent".
	ErrTooLarge = client.ErrTooLarge
	// ErrUnavailable: cipheron cannot serve now: it is shutting down with its keys wiped, the connection to it
	// broke, it is busy (ErrBusy), it has no master key version to write with (ErrNoWriter), it started after the
	// call was signed (transport.ReasonStarting: the client signs a call so refused again and sends it once more by
	// itself, so this reaches the caller only when its clock lags cipheron's), or something answered
	// RESOURCE_EXHAUSTED that is neither cipheron's busy answer nor a size refusal (ErrTooLarge). ErrBusy and
	// ErrNoWriter are ErrUnavailable: a caller that only asks "may I retry" tests this one. (A server that is not
	// reachable at all makes a call wait until its context ends.)
	ErrUnavailable = errors.New("cipheron: unavailable")
	// ErrBusy: cipheron is at a limit — of requests in flight (its maxInFlight, or this caller's
	// maxInFlightPerCaller), of this caller's replay cache, of locked memory for a key — or could not hold the
	// request's key: RESOURCE_EXHAUSTED with the google.rpc.ErrorInfo of transport.ReasonBusy
	// (transport.ErrorDomain) and a google.rpc.RetryInfo; HTTP 429. The call was not served; retry it after
	// RetryAfter. Matched on the ErrorInfo, or on a RetryInfo alone (what an HTTP 429 without a readable body is
	// given). It is ErrUnavailable too.
	ErrBusy = kindOf(ErrUnavailable, "busy")
	// ErrNoWriter: a write (an Encrypt or a ReEncrypt whose new ciphertext is a shared or derived profile's,
	// CreateTenantKey, RewrapTenantKey; a wrapped profile's Encrypt and ReEncrypt use the tenant's own key and never
	// ask for the writer) reached a cipheron where no master key version writes at its clock — before every active
	// version's activateAt (a clock stepped back, or a configuration whose only writer is still to come): UNAVAILABLE
	// with the ErrorInfo of transport.ReasonNoWriter; HTTP 503. Nothing is wrong with the request, and reads still work there; another
	// replica, whose clock is right, may serve the write. Unlike ErrBusy a retry a second later does not help by
	// itself. It is ErrUnavailable too.
	ErrNoWriter = kindOf(ErrUnavailable, "no master key version writes now")
	// ErrProfileSealed: the profile is sealed on the cipheron that answered (its unseal.partial: the profile's master key
	// versions did not unseal at its start and are being unsealed again in the background), while its other profiles
	// serve: UNAVAILABLE with the ErrorInfo of transport.ReasonProfileSealed and a google.rpc.RetryInfo; HTTP 503.
	// Nothing was done; retry after RetryAfter, or on another replica. It is ErrUnavailable too (retryable).
	ErrProfileSealed = kindOf(ErrUnavailable, "the profile is sealed on this replica")
	// ErrUnsupported: the server does not have the call — gRPC UNIMPLEMENTED (over cipheron's HTTP API, a 404 of
	// the operation's route): something that is not cipheron, or a call it does not serve. The same call fails the
	// same way: not retryable.
	ErrUnsupported = errors.New("cipheron: not supported by this cipheron")
	// ErrSigningKeyRevoked: the signature names a signing key the profile REVOKED (wire/transport's value):
	// Verify (the Client's, a derived profile's Tenant.Verify) and VerifyWithKeys answer (false, ErrSigningKeyRevoked)
	// for it, whatever the bytes — never true, never a bare false. A Sign answer naming a revoked key (a cipheron
	// replica that has not learnt the revocation) is refused with it too. Once this Client has seen a key revoked in
	// a list the profile's identity signed, the key stays revoked for the Client's life, whatever a later list says.
	// KeyStatement answers it when the statements cipheron answered list as usable a key this Client holds revoked: no
	// statement is handed out. The raw-key Verify and VerifyTenant know nothing of states.
	ErrSigningKeyRevoked = client.ErrSigningKeyRevoked
	// ErrKeysStale: Verify needed the profile's signing-key list fetched again — it was older than WithKeysMaxAge — and
	// the fetch failed (or failed within the last few seconds). NOTHING WAS VERIFIED: the library does not decide on a
	// list that may miss a revocation. The error carries the fetch's too (ErrUnavailable, ErrPermissionDenied, ...).
	// KeyStatement answers it too when no statement this Client verified within WithKeysMaxAge agrees with the signing
	// keys it holds: nothing is handed out.
	ErrKeysStale = client.ErrKeysStale
	// ErrInternal: cipheron answered INTERNAL — a failure of its own it does not describe (its log does). The
	// call may or may not have been served; an Encrypt or a Sign is safe to repeat.
	ErrInternal = errors.New("cipheron: internal error")
	// ErrServerIdentity: the party that answered could not be shown to be the profile's cipheron — the socket's
	// process does not run as WithServerUID's uid, the server's certificate or SPIFFE ID did not verify, the
	// profile's identity does not match WithProfileFingerprint's pin, its signing-key list is not signed by its
	// identity, or an answer is not the profile's (its response signature, or a signature not under a key of the
	// profile's authenticated list). A PublicKey answer and a batch answer are authenticated before anything in them is
	// read, so a value changed in the path (a batch result dropped or added among them) is this error, and so is one
	// that cannot be authenticated at all (a tenancy or a response key algorithm this library does not have; an
	// hpke_suite or algorithm cipheron always writes, left out). Nothing it sent is returned, and nothing of it is
	// cached. It wraps the reason. The observer counts it (server_identity).
	ErrServerIdentity = client.ErrServerIdentity
	// ErrServerKeyChanged: cipheron answered another identity for the profile than the one this Client first
	// fetched (or pinned). A profile's identity never changes — rotations do not touch it: the profile was
	// re-created, or something else answers for it. The new identity is never adopted; the profile's calls fail
	// until a new Client is made (with a pin, after the new fingerprint was checked). It is also
	// ErrServerIdentity.
	ErrServerKeyChanged = client.ErrServerKeyChanged
	// ErrBadResponse: an answer signed by the profile's response key is not well formed (a ciphertext not in the
	// format or under the key expected, a plaintext that does not open, a tenant key that is not the one asked
	// for, a signed batch answer with another number of results than items), or holds what this protocol does not
	// have — a ciphertext format, a tenant key blob version, a signing-key state (signed: a state number changed in the
	// path is ErrServerIdentity), or an HPKE suite or a signing algorithm of a key it would use. The answer is never
	// returned. It points at a defect; the observer is not told of it.
	ErrBadResponse = client.ErrBadResponse
	// ErrTenancy: the call is not one of the profile's tenancy — the Client's own calls in a perTenant profile (use
	// Tenant), a Tenant's calls, CreateTenantKey or RewrapTenantKey in a shared profile, a blob (or
	// CreateTenantKey, RewrapTenantKey) in a derived one — a blob of the call's profile and tenant: another
	// profile's or tenant's is ErrTenantKey, checked first. Refused before the operation is sent: the tenancy is
	// read from the profile's keys, so the first call in a profile fetches them from cipheron (which carries
	// nothing of the call's data) before it can be refused. A key statement's Verify of a statement that is not a
	// shared profile's, and its VerifyTenant of one that is not a derived profile's, answer it too, with nothing verified.
	ErrTenancy = client.ErrTenancy
	// ErrTenantKey: a tenant id that is not one (1 to 2048 bytes of printable ASCII, 0x21 to 0x7E); a tenant key
	// blob that is not one, belongs to another tenant or profile than the call's, is not the key pinned for the
	// tenant (WithTenantFingerprint), or is missing in a wrapped profile — the handle's blob, or Tenant.ReEncrypt's
	// target blob (to), which a wrapped profile requires. Refused before the operation is sent: an invalid tenant id, a bad
	// blob and a pin that does not match with nothing sent at all; a blob missing for a wrapped profile after the
	// profile's keys were fetched (the first call in a profile). It is also ErrInvalidInput. (A blob cipheron itself
	// refuses — one that does not open — is ErrInvalidInput.)
	ErrTenantKey = client.ErrTenantKey
	// ErrPinRequired: the Client was made WithRequiredPins and the profile has no pin (WithProfileFingerprint, or a
	// "<profile>.fingerprint" file in the pins directory WithEnvironment reads). Nothing was asked of cipheron. It is
	// also ErrServerIdentity.
	ErrPinRequired = client.ErrPinRequired
	// ErrContextDigest: the key-context digest cipheron answered for the profile — authenticated by the profile's
	// response key, in a key fetch or in the response signature of any answer, which covers the digest of the replica
	// that made it — is not one WithContextDigestPin (or a "<profile>.contextDigest" pin file) names, or an answer made
	// new data under a master key version WithWriterVersionPin does not name: the replica serves another key context
	// than the one this application was deployed against. Nothing of the answer is used; the profile's calls fail until
	// a replica with a pinned context answers. It is not ErrServerIdentity.
	ErrContextDigest = client.ErrContextDigest
	// ErrUnknownSigningKey: Verify (the Client's, or a derived profile's Tenant's) was asked about a signature whose
	// key id names no signing key this Client knows, and could not resolve it: NOTHING WAS VERIFIED, and the error
	// is not a verdict on the signature. After a signing rotation a genuine signature under the new key gets it
	// until this Client has fetched the new key list — which it does for an unknown key id at most every few
	// seconds, so that key ids from a stranger do not each become a call to cipheron: try again then. It is also
	// the answer when that fetch failed (the error then carries the fetch's error too: ErrPermissionDenied,
	// ErrUnavailable, ...), when a list fetched now does not name the key either (another profile's signature, or a
	// corrupt or forged key id), and when the key id is not 16 bytes. A WRAPPED profile's Tenant.Verify never
	// answers it: a key id that is not the handle's blob's is (false, nil) there — the handle has one key and
	// nothing to learn.
	ErrUnknownSigningKey = client.ErrUnknownSigningKey
	// ErrClosed: the Client was closed. A call made after Close sends nothing; a call Close cut short answers it
	// too.
	ErrClosed = client.ErrClosed
	// ErrAssociatedData: the associated data does not match the ciphertext — one made with associated data (format 5
	// or 6) given without it, one made without (format 3 or 4) given with some, or associated data over 64 KiB — or a
	// re-encryption whose WithTargetAssociatedData is not its WithAssociatedData (a ReEncryptBatch item: ToAssociatedData
	// not its AssociatedData), which would drop or change the binding; refused here before anything is sent, or by
	// cipheron (CIPHERON_ASSOCIATED_DATA for a dropped one). Every error that is
	// ErrAssociatedData is ErrInvalidInput too. Associated data that is given but WRONG is not this error: the
	// ciphertext does not decrypt (ErrInvalidInput), exactly as a modified one — cipheron never returns other data.
	// It is transport.ErrAssociatedData, the same value.
	ErrAssociatedData = client.ErrAssociatedData
	// ErrSegmented: a segmented object (EncryptObject) that is not one, or whose segments do not decrypt as its own,
	// in their order, ending with its last segment — truncated, reordered, extended, spliced or modified. Nothing of
	// it is returned. It is transport.ErrSegmented.
	ErrSegmented = transport.ErrSegmented
	// ErrKeyStatement: a key statement that is not one, is not the profile's (its identity does not have the pinned
	// fingerprint, its signature is not its response key's), or is older than the verifier allows. It is
	// transport.ErrKeyStatement.
	ErrKeyStatement = client.ErrKeyStatement
	// ErrJSONField: the input of EncryptJSONFields or DecryptJSONFields is not what the call can use — a document
	// that is not one JSON value, a pointer that is not a JSON Pointer or names no value, pointers that repeat or nest,
	// a record id out of bounds, or (to decrypt) a value at an encrypted field's place that is not an encrypted field:
	// a field put back in clear is refused, never passed through. Refused before anything is sent. It is also
	// ErrInvalidInput, and is transport.ErrJSONField.
	ErrJSONField = transport.ErrJSONField
)

// kindOf is a value that is also parent: errors.Is(kindOf(parent, …), parent) holds, and so it holds for every
// error that wraps the value.
func kindOf(parent error, what string) error { return fmt.Errorf("%w: %s", parent, what) }

// errAssociatedDataInput is cipheron's CIPHERON_ASSOCIATED_DATA refusal's kind: ErrAssociatedData and ErrInvalidInput.
var errAssociatedDataInput = fmt.Errorf("%w: %w", ErrInvalidInput, ErrAssociatedData)

// The tenancies (Keys.Tenancy).
const (
	// TenancyShared is a profile whose keys serve every caller.
	TenancyShared = string(transport.TenancyShared)
	// TenancyWrapped is a perTenant profile whose tenants each have a key, stored by the application as a blob.
	TenancyWrapped = string(transport.TenancyPerTenantWrapped)
	// TenancyDerived is a perTenant profile whose tenants' keys are derived; nothing is stored.
	TenancyDerived = string(transport.TenancyPerTenantDerived)
)

// The signing key states (SigningKey.State).
const (
	// SigningKeyActive is the key Sign signs with: one per profile that has signing keys.
	SigningKeyActive = string(transport.SigningKeyActive)
	// SigningKeyVerifyOnly is a key listed so its signatures keep verifying.
	SigningKeyVerifyOnly = string(transport.SigningKeyVerifyOnly)
	// SigningKeyRevoked is a key the profile revoked for good: listed, never signs, and every signature under it is
	// refused (ErrSigningKeyRevoked).
	SigningKeyRevoked = string(transport.SigningKeyRevoked)
)

// Client is a connection pool to cipheron.
type Client struct {
	c *client.Client
}

// Signature is what Sign returns: the Ed25519 signature (Bytes, 64 bytes) and the id of the key that made it
// (KeyID, 16 bytes) — a signing key of the profile's list in a shared or derived profile, the tenant key in a
// wrapped one. Store both: the key id is how a verifier picks the key after a signing rotation.
type Signature = client.Signature

// SigningKey is one version of a profile's signing key.
type SigningKey struct {
	// KeyID names the key (16 bytes; Signature.KeyID).
	KeyID []byte
	// State is SigningKeyActive, SigningKeyVerifyOnly or SigningKeyRevoked. Only an active or verify-only key
	// verifies (VerifyWithKeys).
	State string
	// PublicKey is the Ed25519 public key.
	PublicKey ed25519.PublicKey
	// Algorithm is the key's algorithm, the API's SignatureAlgorithm number: AlgorithmEd25519 (0 is read as it). A key
	// of an algorithm this library does not implement is listed and used for nothing (the crypto-agility extension
	// point): Verify refuses it as ErrBadResponse, VerifyWithKeys as ErrInvalidInput.
	Algorithm uint32
}

// AlgorithmEd25519 is SigningKey.Algorithm's Ed25519 (the one algorithm this library implements).
const AlgorithmEd25519 = uint32(transport.AlgorithmEd25519)

// Keys are a profile's keys as cipheron answered them, authenticated: the identity matched the pin (or was the one
// first seen), and the signing keys and the context digest verified under the identity's response key.
type Keys struct {
	// Profile is the profile's name.
	Profile string
	// Tenancy is TenancyShared, TenancyWrapped or TenancyDerived.
	Tenancy string
	// HPKE is the HPKE public key requests are sealed to: an uncompressed P-256 point. Identity: never rotates.
	HPKE []byte
	// Response is the Ed25519 public key every answer is signed by. Identity: never rotates.
	Response ed25519.PublicKey
	// SigningKeys are every signing key the profile has ever signed with, ascending by key id, at most one active
	// (none in a wrapped profile, whose tenant keys sign). Signatures verify under the one their key id names, unless
	// it is revoked (ErrSigningKeyRevoked). A key this Client once saw revoked is revoked here, whatever cipheron
	// answers now.
	SigningKeys []SigningKey
	// ContextDigest is the profile's key-context digest ("sha256:…"): cipherons answering the same one read each
	// other's ciphertexts and publish the same signing keys. It changes when cipheron's key configuration of the
	// profile does (a master version listed, removed or resolving to another key, a signing key added or revoked) —
	// not when a master version is activated, nor when a signing key is
	// (signing.activeGeneration, signing.activateAt: an active and a verifyOnly key are one published state in it).
	// It is bound to this call's fresh nonce by the response key, so an older answer replayed is refused, never
	// adopted.
	ContextDigest string
	// Fingerprint is the identity's fingerprint: what WithProfileFingerprint pins, as `cipheron keygen ensure`
	// prints it. It survives every rotation.
	Fingerprint string
	// HPKESuite is the identity's HPKE suite, written "0xKEM/0xKDF/0xAEAD" ("0x0010/0x0001/0x0002" for every profile
	// of this release). A suite this library does not implement leaves HPKE empty: the profile's keys verify, and
	// every call that seals a payload is ErrBadResponse.
	HPKESuite string
	// FingerprintVersion is the fingerprint's derivation: 1 for a classical identity (every profile of this release),
	// 2 for an identity with another suite, algorithm or added keys.
	FingerprintVersion int
}

// Active is the profile's active signing key; false in a wrapped profile.
func (k Keys) Active() (SigningKey, bool) {
	for _, s := range k.SigningKeys {
		if s.State == SigningKeyActive {
			return s, true
		}
	}
	return SigningKey{}, false
}

// SigningKey is the listed signing key keyID names; false when none does.
func (k Keys) SigningKey(keyID []byte) (SigningKey, bool) {
	for _, s := range k.SigningKeys {
		if len(keyID) == transport.SigningKeyIDLen && bytes.Equal(s.KeyID, keyID) {
			return s, true
		}
	}
	return SigningKey{}, false
}

// Option configures a Client. A nil Option is skipped. An option that answers one question (WithServerUID,
// WithServerSPIFFEID, WithTLSFiles, WithRequestKeyFile, WithRequestKey, a profile's or a tenant's fingerprint) may
// be given twice with the same value; given twice with different values, New fails rather than let the last win.
type Option func(*options)

type options struct {
	c          []client.Option
	transports []Transport // every WithTransport given, in order
}

func opt(o client.Option) Option { return func(os *options) { os.c = append(os.c, o) } }

// WithServerUID makes the Client check, on every connection and before anything is sent, that the process
// listening on the socket runs as uid (as the kernel reports it), and refuse it otherwise with
// ErrServerIdentity. cipheron's image runs as uid 10443, which must be cipheron's alone on the host. A socket
// address needs it, or WithAnyServer; New refuses it with a network address. A uid that names no one in
// particular — 0 (root), 65534 and the kernel's overflow uid, 4294967294 and 4294967295 — is refused, as cipheron's
// server refuses it in a caller entry.
func WithServerUID(uid uint32) Option { return opt(client.WithServerUID(uid)) }

// WithAnyServer is the explicit opt-out of WithServerUID, FOR TESTS AND DEVELOPMENT: with it the Client does not
// authenticate the server. It talks to whatever process answers on the socket path and sends it its requests. If
// that process is not cipheron, nothing in this library notices unless the profile is pinned
// (WithProfileFingerprint): without a pin the profile's keys are whatever the process answers first, so it reads
// every plaintext given to Encrypt and all data given to Sign, and its answers are accepted; with a pin it can
// read and answer nothing, but still receives the (sealed) requests and can fail every call. cipheron's own checks
// of the socket's directory protect the path only while cipheron is the one listening.
//
// Production uses WithServerUID with the uid cipheron runs as (10443 in its image), a pin per profile and
// WithRequiredPins. New does not refuse WithAnyServer without a pin (tests, and a developer's machine where
// cipheron runs as the developer, use it so), so nothing but this comment keeps it out of a deployment. Socket only.
func WithAnyServer() Option { return opt(client.WithAnyServer()) }

// WithEnvironment configures the Client from the environment the cipheron-sidecar Helm chart sets in the
// application's container, and is the only option that reads the environment — nothing is read from it unless it
// is given. Pass "" as New's address:
//
//	c, err := cipheron.New("", cipheron.WithEnvironment())
//
// It reads:
//   - EnvSocket (CIPHERON_SOCKET), required: the socket, an absolute path;
//   - EnvServerUID (CIPHERON_SERVER_UID), required: WithServerUID;
//   - EnvRequestKey (CIPHERON_REQUEST_KEY), optional: WithRequestKeyFile;
//   - EnvPinsDir (CIPHERON_PINS_DIR): WithProfileFingerprint for each "<profile>.fingerprint" file in it,
//     WithContextDigestPin for each "<profile>.contextDigest" file (one digest per line) — REQUIRED in production;
//   - EnvEnvironment (CIPHERON_ENVIRONMENT), optional: the deployment's environment, the chart's
//     application.environment. Unset, or anything but exactly "development", is PRODUCTION.
//
// In production a pin is required: no pins directory is an error (ErrPinRequired) — never a silent fallback to trust
// on first use — and WithRequiredPins is implied, so a profile the directory does not pin fails its first call with
// ErrPinRequired before anything is asked of cipheron. CIPHERON_ENVIRONMENT=development, the chart's
// application.environment: development, is the one opt-out, for a development machine or cluster: there the pins
// directory is optional and, without WithRequiredPins, a profile with no pin is trusted on first use. No option lifts
// the rule in production.
//
// A variable that is set must not be empty. The pin files are read through the checked reader (owned by root or
// this user, writable by nobody else, at most 256 bytes for a fingerprint) from a directory nobody but root and this user can
// write, sticky or not — in a Kubernetes volume, the timestamped directory its "..data" link names, not the
// volume's root (1777) — in a directory chain nobody else can write unless sticky. Setting again, to something else,
// what the environment set — an address, WithAnyServer, WithServerUID of another uid, a request key other than
// CIPHERON_REQUEST_KEY's file while it is set, another fingerprint for a pinned profile — is an error; an option
// that equals the environment's value is accepted, and other options combine with it. Add WithRequiredPins to
// refuse a profile the pins directory has no fingerprint for (implied in production). A pins directory that cannot be
// read in full is an error; one that is read and holds no "<profile>.fingerprint" pins nothing — accepted in
// development without WithRequiredPins (every profile is then trusted on first use) and with required pins when an
// option pins a profile (WithProfileFingerprint; any other profile fails at its first call with ErrPinRequired), and
// refused by New with ErrPinRequired when pins are required and nothing pins any profile. The files are read first by
// New, and then again while the Client runs (every 10 seconds; a Kubernetes volume is read again only when its
// "..data" link moved): a key-context pin the kubelet updates — a widen, a narrow — is in force without a restart
// (owner decision D-P). An update that cannot be read in full or holds a pin the first read would refuse is not
// applied (the pins in force stay; WithObserver is told client.KindPinsReload), a profile whose pin file disappears
// keeps its pins, and a profile's fingerprint never changes. See internal/client.WithEnvironment.
func WithEnvironment() Option { return opt(client.WithEnvironment()) }

// WithPinsDir reads the profiles' pins from dir — "<profile>.fingerprint" and "<profile>.contextDigest" files, as
// WithEnvironment reads them from CIPHERON_PINS_DIR, under the same rules — and re-reads it while the Client runs
// (owner decision D-P): mount the pins ConfigMap and a key-context widen or narrow needs no restart of the
// application. For a client without WithEnvironment, such as a network client; with it, the same directory as
// CIPHERON_PINS_DIR or none. Add WithRequiredPins to refuse a profile it does not pin. See
// internal/client.WithPinsDir.
func WithPinsDir(dir string) Option { return opt(client.WithPinsDir(dir)) }

// WithRequiredPins makes a pin required for every profile the Client uses: a profile with no fingerprint
// (WithProfileFingerprint, or a "<profile>.fingerprint" file in the pins directory WithEnvironment reads) is not
// trusted on first use — its first call fails with ErrPinRequired, before anything is asked of cipheron. A pin from
// any source serves a profile. One case fails at New instead: with WithEnvironment, a pins directory that is set and
// holds no fingerprint, and no WithProfileFingerprint either — no profile could ever be used, and New returns
// ErrPinRequired (and ErrServerIdentity), what every call would.
func WithRequiredPins() Option { return opt(client.WithRequiredPins()) }

// The environment variables WithEnvironment reads, and the suffixes of the files in the pins directory: exactly
// the names the cipheron-sidecar chart writes.
const (
	EnvSocket              = client.EnvSocket
	EnvServerUID           = client.EnvServerUID
	EnvRequestKey          = client.EnvRequestKey
	EnvPinsDir             = client.EnvPinsDir
	EnvEnvironment         = client.EnvEnvironment
	PinFingerprintSuffix   = client.PinFingerprintSuffix
	PinContextDigestSuffix = client.PinContextDigestSuffix
	// DevelopmentEnvironment is the one value of EnvEnvironment that is not production.
	DevelopmentEnvironment = client.DevelopmentEnvironment
)

// WithTLSFiles is the client's TLS for a network address, from PEM files: certFile and keyFile are this
// client's certificate (its one identity SAN — a SPIFFE ID, a URI, a DNS name or an e-mail address, as cipheron's
// trust bundle for its CA reads it — is the identity cipheron authorizes) and key, read again on every
// handshake so a rotated certificate is picked up without a restart; caFile is the CA bundle the server's
// certificate must verify against, read once. Each file must be owned by root or this process's user and
// writable by no one else, the key readable by no one else (0400, 0440, 0600, 0640), all paths absolute, in a
// directory chain as WithRequestKeyFile's. The connection is TLS 1.3 at least.
func WithTLSFiles(certFile, keyFile, caFile string) Option {
	return opt(client.WithTLSFiles(certFile, keyFile, caFile))
}

// WithTLSConfig is the client's TLS for a network address, for a caller that already has a configuration —
// such as go-spiffe's Workload API configurations. It must present a client certificate (a non-empty chain
// with its private key, or GetClientCertificate) and verify the server with its own roots (RootCAs) or its own
// verification (VerifyConnection, VerifyPeerCertificate): a configuration that would fall back on the system's
// roots is refused. It is cloned. A configuration that sets no MinVersion gets TLS 1.3; one that sets
// tls.VersionTLS12 keeps it (for a cipheron whose network.tls.minVersion is "1.2"), and gives up, on a TLS 1.2
// connection, the immediate ErrPermissionDenied when cipheron refuses this client's certificate: a TLS 1.2 alert is
// not authenticated, so the call waits until its context ends instead.
func WithTLSConfig(cfg *tls.Config) Option { return opt(client.WithTLS(cfg)) }

// WithServerSPIFFEID makes the Client accept, on the network, only a server whose certificate verifies against
// the CA (WithTLSFiles' caFile, or the configuration's RootCAs) and carries exactly the SPIFFE ID id, instead of
// checking the address's hostname.
func WithServerSPIFFEID(id string) Option { return opt(client.WithServerSPIFFEID(id)) }

// WithRequestKeyFile is this application's request key, read from path when the Client is made: the PEM
// PKCS #8 Ed25519 private key OpenSSL 3 writes (`openssl genpkey -algorithm ed25519`, run in production by whoever
// owns the caller's secrets; `cipheron keygen caller` in development only), owned by root or this process's user
// and readable by no one else (0400, 0440, 0600, 0640), at an absolute path. The directory chain: every directory from / down
// to the file's (after symbolic links are resolved) must be owned by root or this process's user, and writable by
// no one else — except a directory with the sticky bit (/tmp; a Kubernetes volume's root, mode 1777), which is
// accepted although others can write it: there they can add files, but cannot rename or remove this one, and the
// file's own owner is checked. Its bytes are wiped once parsed. Every request but the key fetch is signed with
// it: Encrypt, Decrypt, Sign, ReEncrypt, a Tenant's calls, CreateTenantKey and RewrapTenantKey. The fetch of a
// profile's public keys (Keys, ContextDigest, and the first call in a profile) is not signed, and Verify sends
// nothing. Required with a network address.
func WithRequestKeyFile(path string) Option { return opt(client.WithRequestKeyFile(path)) }

// WithRequestKey is WithRequestKeyFile for a key the application already holds. It is copied when the option is
// made — the application may wipe its own slice as soon as WithRequestKey returns — and each Client made with the
// option holds a copy of its own, which its Close wipes; the option keeps its copy while it is reachable.
func WithRequestKey(key ed25519.PrivateKey) Option { return opt(client.WithRequestKey(key)) }

// WithProfileFingerprint pins profile's identity to fp, the fingerprint `cipheron keygen ensure` printed for it
// ("sha256:" and 64 lowercase hex digits). An identity that does not match is refused, and every call in the profile fails
// with ErrServerIdentity. The identity never rotates, so the pin survives every key rotation. Without a pin a
// profile's identity is trusted on first use. Repeat it per profile.
func WithProfileFingerprint(profile, fp string) Option {
	return opt(client.WithProfileFingerprint(profile, fp))
}

// WithContextDigestPin pins profile's key context to digests — each a key-context digest as `cipheron keygen ensure`
// printed contextDigest ("sha256:" and 64 lowercase hex digits); more than one while a key-context change rolls
// out, at most client.MaxContextDigestPins. The profile's keys are accepted only when the digest cipheron answers
// (signed by the profile's response key) is one of them; any other is ErrContextDigest — a replica serving a drifted
// or stale key context (master versions, signing keys) — and nothing of it is used. With WithEnvironment,
// a "<profile>.contextDigest" file in the pins directory gives them. See internal/client.WithContextDigestPin.
func WithContextDigestPin(profile string, digests ...string) Option {
	return opt(client.WithContextDigestPin(profile, digests...))
}

// WithWriterVersionPin pins the master key versions profile's NEW data may be made under — master version ids as the
// configuration lists them, at most client.MaxWriterVersionPins: an Encrypt or ReEncrypt answer (their batches, the
// object, stream and JSON-field helpers) whose ciphertext names another version, or a CreateTenantKey or
// RewrapTenantKey answer whose blob is wrapped under another, is ErrContextDigest. The key-context digest does not
// cover which listed version writes, so this is what refuses a replica that lags a writer switch: a writer switch is
// then a pin change too (widen, switch, narrow). Reads are not held to it. See internal/client.WithWriterVersionPin.
func WithWriterVersionPin(profile string, versions ...string) Option {
	return opt(client.WithWriterVersionPin(profile, versions...))
}

// WithTenantFingerprint pins tenant's key in the wrapped profile to fp, the fingerprint CreateTenantKey answered
// for it. A Tenant handle (or RewrapTenantKey) given a blob of another key fails with ErrTenantKey, before
// anything is sent; without a pin, the blob the application hands over is the tenant's key. A rewrap keeps the
// fingerprint. Repeat it per tenant.
//
// Tenant pins are fixed for the Client's life: none can be added, changed or dropped afterwards (the pins directory
// of WithEnvironment is re-read live; pins given in code, a profile's and a tenant's, are not). A tenant whose key the service rotates (CreateTenantKey again makes a NEW key, with another
// fingerprint) is refused by a Client that pins the old fingerprint until a Client is made with the new one. A
// service that rotates tenant keys either does not pin them (and protects the blobs where it stores them), or
// makes a new Client when a tenant's pin changes. The target blob of Tenant.ReEncrypt is not held to the pin.
func WithTenantFingerprint(profile, tenant, fp string) Option {
	return opt(client.WithTenantFingerprint(profile, tenant, fp))
}

// WithMaxMessageBytes is the largest message the Client sends or receives (default
// client.DefaultMaxMessageBytes: cipheron's largest limit, 64 MiB, and some room). Larger data is refused before
// anything is sent, with ErrTooLarge.
func WithMaxMessageBytes(n int) Option { return opt(client.WithMaxMessageBytes(n)) }

// WithConnections is how many connections the Client keeps to cipheron, from 1 to 16 (client.MaxConnections; default
// 2, client.DefaultConnections); calls take them in turn, many at once on each gRPC connection. With TransportHTTP it
// is how many connections, idle ones included, the Client opens at most (default 8, client.DefaultHTTPConnections),
// each carrying one call at a time. Each is opened and checked like the first. cipheron bounds the connections of one caller (maxConnectionsPerCaller, 32 unless configured):
// every Client of a process, and every process under the same identity, counts against it.
func WithConnections(n int) Option { return opt(client.WithConnections(n)) }

// WithRoundRobin spreads a NETWORK client's calls over every address its host name resolves to: gRPC's DNS resolver
// and round_robin, one verified connection per resolved address per WithConnections connection. Use it with the
// cipheron chart's headless Service (service.headless), whose name resolves to the pods: every replica then serves
// this client, where an L4 Service balances only the connections, once each. A replica added is used from the next
// re-resolution — when a connection closes, at every replica's maxConnectionAge at the latest. Trust is unchanged:
// each connection is verified as one is. gRPC (New) only; a socket address refuses it. See
// internal/client.WithRoundRobin.
func WithRoundRobin() Option { return opt(client.WithRoundRobin()) }

// WithObserver has f told, at the end of every call that failed with an integrity or drift error, the call's profile
// and the error's kind — one of ObserverKinds: context_digest (ErrContextDigest), server_key_changed
// (ErrServerKeyChanged), server_identity (ErrServerIdentity), keys_stale (ErrKeysStale). These are errors only a client sees: export them as a
// counter (docs/client-library.md: cipheron_client_errors_total{profile,kind}) so the operator does. It is also told
// retry (a call WithRetry sends again; not an error) and pins_reload_failed (an update of the pins directory that was
// not applied, profile "", or a profile whose pin file disappeared). f runs on the calling goroutine, or the pins
// directory's: keep it fast and safe for concurrent use. See internal/client.WithObserver.
func WithObserver(f func(profile, kind string)) Option { return opt(client.WithObserver(f)) }

// RetryPolicy is WithRetry's policy: MaxAttempts (the first included; 2 to client.MaxRetryAttempts, 3 when 0),
// InitialBackoff (100 ms when 0) and MaxBackoff (2 s when 0; also the longest RetryInfo honoured). So by default a
// profile sealed on the replica (ErrProfileSealed, whose RetryInfo is 5 s) fails fast; a MaxBackoff above 5 s waits for
// its unseal, within the call's deadline.
type RetryPolicy = client.RetryPolicy

// WithRetry makes the Client send an idempotent call again after a transient refusal: cipheron busy (ErrBusy), its
// audit trail unavailable, the profile sealed or without a writer on that replica, the connection lost or the replica
// draining. Each attempt is a fresh request (a new nonce, signed again) on the pool's next connection, after a
// jittered exponential backoff and never sooner than the RetryInfo cipheron answered, never past the call's
// deadline; every attempt carries the call's one request id (RequestIDOf). Encrypt, Decrypt, ReEncrypt, Sign (the
// Client's and a Tenant's), ReEncryptAcross, their batch forms — each batch of an object or stream on its own — and
// the key fetch are retried; CreateTenantKey, RewrapTenantKey and RewrapTenantKeyBatch never are (a second execution is a second key or
// blob). An identity, integrity or drift error, a permission refusal, an invalid argument and ErrClosed are never
// retried. Off unless given. WithObserver is told "retry" per retry. See internal/client.WithRetry.
func WithRetry(p RetryPolicy) Option { return opt(client.WithRetry(p)) }

// ObserverKinds are the kinds WithObserver's function is told of: a fixed set.
var ObserverKinds = client.ObserverKinds

// RequestIDOf is the request id of the call that failed with err: every call carries one (x-request-id — the
// caller's own when its context's outgoing gRPC metadata has one, metadata.AppendToOutgoingContext, else a random
// one), cipheron logs it on the refusal or failure and records it in the audit event. "" when err carries none.
func RequestIDOf(err error) string { return client.RequestIDOf(err) }

// WithKeysMaxAge is how old, at most, a profile's signing-key list may be when Verify (the Client's, a derived
// profile's Tenant.Verify) decides on a signature, and when Sign judges the key its answer names: from 5 seconds to
// 24 hours, 5 minutes unless given. An older list is fetched again first, so a key the operator revoked is refused
// here at most d after the revocation reached the cipheron that answers. When that fetch fails Verify fails closed,
// (false, ErrKeysStale), and Sign returns ErrKeysStale and no signature: online verification and online signing
// need cipheron reachable at least once every d. A failed fetch is not tried again for 5 seconds (the calls
// meanwhile answer ErrKeysStale). The other calls do not look at the list's age. Given twice with different values,
// New fails.
func WithKeysMaxAge(d time.Duration) Option { return opt(client.WithKeysMaxAge(d)) }

// Transport is the protocol a Client speaks to cipheron (WithTransport).
type Transport int

const (
	// TransportGRPC is gRPC, the default: on the socket without TLS, on the network over mutual TLS (HTTP/2).
	TransportGRPC Transport = iota + 1
	// TransportHTTP is cipheron's JSON API (POST /v1/cipher/{profile}/{operation}) over HTTP/1.1: on the socket
	// without TLS, on the network over mutual TLS. It does not wait for a connection (a call fails UNAVAILABLE at
	// once), an HTTP/1.1 connection carries one call at a time, and WithRoundRobin is refused. The payloads are
	// sealed and signed as gRPC's are; trust is unchanged.
	TransportHTTP
)

// String is the transport's name: "grpc" or "http".
func (t Transport) String() string {
	switch t {
	case TransportGRPC:
		return "grpc"
	case TransportHTTP:
		return "http"
	}
	return fmt.Sprintf("Transport(%d)", int(t))
}

// WithTransport is the protocol the Client speaks (TransportGRPC unless given). Given twice with different values,
// or with a value that is not a Transport, New fails.
func WithTransport(t Transport) Option {
	return func(o *options) { o.transports = append(o.transports, t) }
}

// transport is the one transport the options name: TransportGRPC when none does.
func (o *options) transport() (Transport, error) {
	t := TransportGRPC
	for i, v := range o.transports {
		if v != TransportGRPC && v != TransportHTTP {
			return 0, fmt.Errorf("cipheron: WithTransport(%v): not a transport (TransportGRPC, TransportHTTP)", v)
		}
		if i > 0 && v != t {
			return 0, fmt.Errorf("cipheron: WithTransport given twice: %v and %v", t, v)
		}
		t = v
	}
	return t, nil
}

// IsSocketAddress reports whether address names a unix socket (a path, or unix:///path) rather than a network
// address (host:port), as New reads it; an address New would refuse is an error.
func IsSocketAddress(address string) (bool, error) { return client.IsSocket(address) }

// New returns a Client for cipheron at address: a unix socket ("/run/cipheron/private/cipheron.sock", or
// "unix:///run/cipheron/private/cipheron.sock"), which needs WithServerUID or WithAnyServer, or a network address
// ("cipheron.prod.svc:8443"), which needs WithTLSFiles or WithTLSConfig (one of them) and a request key — or "",
// with WithEnvironment, which reads them from the sidecar chart's environment. It speaks gRPC unless WithTransport
// says otherwise. It reads the files the options name and does not connect.
//
// New's errors are configuration errors and none of the package's Err values: an option that is refused or given
// twice with different values, an address that does not match its options, a file that cannot be read or is not
// safe to read, an environment variable — except ErrPinRequired (WithRequiredPins, and no pin at all: see
// WithRequiredPins). Nothing was contacted.
func New(address string, opts ...Option) (*Client, error) {
	var o options
	for _, f := range opts {
		if f != nil { // a nil Option is skipped
			f(&o)
		}
	}
	t, err := o.transport()
	if err != nil {
		return nil, err
	}
	dial := client.DialGRPC
	if t == TransportHTTP {
		dial = client.DialHTTP
	}
	c, err := dial(address, o.c...)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Close closes the connections and wipes the request key the Client holds (crypto/ed25519's own cache of the
// key's expansion stays until the collector reclaims the key; see internal/client.Client.Close). Afterwards
// every call fails with ErrClosed and sends nothing; a call in flight is cut short and fails with ErrClosed too.
// It is safe to call more than once (the later calls return nil) and concurrently with calls: no request is ever
// signed with a wiped key.
func (c *Client) Close() error { return c.c.Close() }

// Encrypt encrypts plaintext in the shared profile and returns the ciphertext to store: format 4, naming the master
// key version it was made under (KeyID). Decrypt in the same profile reads it back, after any rotation.
//
// WithAssociatedData binds associated data into the ciphertext (format 5): Decrypt then needs exactly it.
func (c *Client) Encrypt(ctx context.Context, profile string, plaintext []byte, opts ...CallOption) ([]byte, error) {
	ct, err := c.c.Encrypt(ctx, profile, plaintext, opts...)
	return ct, mapErr(ctx, err)
}

// Decrypt decrypts a ciphertext of the shared profile: one Encrypt or ReEncrypt returned, of any format the profile
// reads (made before key versions, or naming its key version). A key version cipheron no longer lists is
// ErrKeyVersionUnavailable.
//
// A ciphertext made with associated data needs it (WithAssociatedData): without it, or with associated data for one
// made without, ErrAssociatedData; with other associated data it does not decrypt (ErrInvalidInput).
func (c *Client) Decrypt(ctx context.Context, profile string, ciphertext []byte, opts ...CallOption) ([]byte, error) {
	pt, err := c.c.Decrypt(ctx, profile, ciphertext, opts...)
	return pt, mapErr(ctx, err)
}

// ReEncrypt has cipheron decrypt a stored ciphertext of the shared profile and encrypt the same plaintext under the
// current master version — the plaintext never leaves cipheron — and returns the new ciphertext, to
// store in place of the old. The caller's entry needs the reencrypt operation. It is optional: old ciphertexts
// keep decrypting.
//
// WithAssociatedData is the stored ciphertext's associated data, WithTargetAssociatedData the new one's, which must be
// the same: a re-encryption keeps the binding. Anything else — one without the other, or other bytes — is refused
// before anything is sent (ErrAssociatedData). Moving a value to another row or binding is a Decrypt and an Encrypt.
func (c *Client) ReEncrypt(ctx context.Context, profile string, ciphertext []byte, opts ...CallOption) ([]byte, error) {
	ct, err := c.c.ReEncrypt(ctx, profile, ciphertext, opts...)
	return ct, mapErr(ctx, err)
}

// Sign signs data with the shared profile's active signing key and returns the signature and its key id,
// verified here before it is returned: the answer is signed by the profile's response key, and the signature
// verifies under the key its id names in the profile's authenticated list.
func (c *Client) Sign(ctx context.Context, profile string, data []byte) (Signature, error) {
	s, err := c.c.Sign(ctx, profile, data)
	return s, mapErr(ctx, err)
}

// Keys returns the profile's keys: its identity, tenancy, signing keys and context digest. It asks cipheron, and
// returns what this Client holds afterwards — the identity first fetched (or pinned; another is
// ErrServerKeyChanged) and the newest signing-key list that verified under it. An operator compares the
// fingerprint with the one `cipheron keygen ensure` printed before pinning it; an offline verifier keeps
// SigningKeys (VerifyWithKeys).
func (c *Client) Keys(ctx context.Context, profile string) (Keys, error) {
	k, err := c.c.Keys(ctx, profile)
	if err != nil {
		return Keys{}, mapErr(ctx, err)
	}
	out := Keys{Profile: k.Profile, Tenancy: string(k.Tenancy), Response: k.Response,
		ContextDigest: k.ContextDigest,
		Fingerprint:   k.Fingerprint,
		HPKESuite:     k.HPKESuite.String(),
		FingerprintVersion: transport.FingerprintVersion(transport.Identity{Tenancy: k.Tenancy, HPKESuite: k.HPKESuite,
			ResponseAlgorithm: k.ResponseAlgorithm, Additional: k.Additional})}
	if k.HPKE != nil {
		out.HPKE = bytes.Clone(k.HPKE.Bytes())
	}
	for _, s := range k.SigningKeys {
		out.SigningKeys = append(out.SigningKeys, SigningKey{KeyID: s.KeyID, State: string(s.State), PublicKey: s.PublicKey,
			Algorithm: uint32(s.Alg())})
	}
	return out, nil
}

// ContextDigest is the profile's key-context digest, as Keys returns it: what a group of services sharing the
// profile compares (cipheron's expectContext).
func (c *Client) ContextDigest(ctx context.Context, profile string) (string, error) {
	k, err := c.c.Keys(ctx, profile)
	if err != nil {
		return "", mapErr(ctx, err)
	}
	return k.ContextDigest, nil
}

// Verify reports whether signature is the shared profile's signature over data under its signing key keyID
// (Signature.KeyID). The check is local: the only thing ever fetched from cipheron is the profile's public keys —
// the same cache Encrypt and Sign use, fetched again when it is older than WithKeysMaxAge (5 minutes by default), and
// (at most every few seconds) when keyID is not in it — and neither data nor signature leaves this process.
//
// It has three answers, and a caller must keep them apart:
//   - (true, nil): the signature is the profile's over data, under an active or verify-only key;
//   - (false, nil): keyID names a usable key of the profile this Client knows, and the signature does NOT verify
//     under it;
//   - (false, an error): the signature must not be accepted, and in most cases NOTHING WAS VERIFIED.
//     ErrSigningKeyRevoked when keyID names a key the profile revoked (in the current list or any earlier one this
//     Client verified), whatever the bytes; ErrBadResponse when it names a key of an algorithm this library does not
//     implement;
//     ErrKeysStale when the list was older than the maximum age and could not be fetched again (the error is also the
//     fetch's); ErrUnknownSigningKey when keyID names no key this Client knows and it could not be resolved now —
//     the key list was fetched within the last few seconds and is not fetched again yet (try again in a few
//     seconds: a signing rotation is learnt then), the fetch failed (the error is then also the fetch's:
//     ErrPermissionDenied, ErrUnavailable, ErrServerIdentity, ...), or a list fetched now does not name it either (by
//     choice an error too, not false: another profile's signature, or a corrupt or forged key id); ErrTenancy for a
//     perTenant profile (use Tenant); ErrPinRequired and the other ErrServerIdentity, ErrBadResponse, or
//     ErrPermissionDenied and ErrUnavailable, when the profile's keys could not be fetched the first time;
//     ErrClosed; the context's error.
//
// So an error is never a bare "forged", and never a reason to accept. A verifier without cipheron uses
// VerifyWithKeys (the same answers, on a list it keeps), or Verify with the key — which knows nothing of states.
func (c *Client) Verify(ctx context.Context, profile string, data, signature, keyID []byte) (bool, error) {
	ok, err := c.c.Verify(ctx, profile, data, signature, keyID)
	if err != nil {
		return false, mapErr(ctx, err)
	}
	return ok, nil
}

// Verify reports whether signature is an Ed25519 signature over data under publicKey: a shared profile's signing
// key (the one the signature's key id names), or a wrapped tenant's key. It runs locally, with no cipheron and
// no Client. It is STATE-AGNOSTIC: it checks the bytes under the key it is given, and a signature under a key the
// profile revoked verifies here. That is deliberate — the escape hatch of an application with trusted evidence of
// its own of when a signature was made (an append-only store's commit time, a timestamp authority's countersignature)
// — and nothing else should use it on a profile's keys: VerifyWithKeys and Client.Verify refuse a revoked key.
func Verify(publicKey ed25519.PublicKey, data, signature []byte) bool {
	return client.Verify(publicKey, data, signature)
}

// VerifyTenant reports whether signature is a derived profile's signature for tenant over data, under publicKey —
// the profile signing key the signature's key id names: the signature is over a message that binds the profile and
// the tenant (transport.TenantSignedMessage), so one made for another tenant never verifies. It runs locally, and
// is state-agnostic as Verify is: VerifyTenantWithKeys and Tenant.Verify refuse a revoked key.
func VerifyTenant(publicKey ed25519.PublicKey, profile, tenant string, data, signature []byte) bool {
	return client.VerifyTenant(publicKey, profile, tenant, data, signature)
}

// VerifyWithKeys reports whether signature is a shared profile's signature over data under the key keyID names in
// keys (Keys.SigningKeys, kept by a verifier that has no cipheron), with Client.Verify's answers:
//   - (true, nil): it verifies under that key, active or verify-only;
//   - (false, nil): it does not;
//   - (false, an error): nothing was verified, and the signature must not be accepted — ErrSigningKeyRevoked for a
//     key keys marks revoked (whatever the bytes), ErrUnknownSigningKey for a key id keys does not name (or not 16
//     bytes), ErrInvalidInput for a list that is not one profile's — a key id twice (lists joined: their order would
//     decide whether a revoked key verifies), an id that is not its key's, a state that is not one of the three —
//     whatever key id is asked about, and for a key of an algorithm this library does not implement.
//
// It decides on the list it is given: a revocation reaches it when the list is refreshed (Keys, again). Pass the
// refreshed list alone, never joined with an older one. It knows no tenancy: the caller chooses VerifyWithKeys for a
// SHARED profile's signature and VerifyTenantWithKeys for a DERIVED profile's (Keys.Tenancy says which); a key
// statement's Verify and VerifyTenant choose from the statement, and refuse the other (ErrTenancy).
func VerifyWithKeys(keys []SigningKey, data, signature, keyID []byte) (bool, error) {
	ok, err := client.VerifyWithKeys(transportKeys(keys), data, signature, keyID)
	return ok, keyListErr(err)
}

// VerifyTenantWithKeys is VerifyWithKeys for a derived profile's signature for tenant, with the same answers. Like
// VerifyWithKeys it knows no tenancy: the caller chooses it for a derived profile's signature.
func VerifyTenantWithKeys(keys []SigningKey, profile, tenant string, data, signature, keyID []byte) (bool, error) {
	ok, err := client.VerifyTenantWithKeys(transportKeys(keys), profile, tenant, data, signature, keyID)
	return ok, keyListErr(err)
}

// keyListErr is a list VerifyWithKeys refused (client.ErrInvalidKeyList: not one profile's, or a key it cannot use) as
// ErrInvalidInput: the caller's input. Nothing was verified.
func keyListErr(err error) error {
	if errors.Is(err, client.ErrInvalidKeyList) {
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return err
}

// transportKeys is keys as the protocol client takes them.
func transportKeys(keys []SigningKey) []transport.SigningKey {
	out := make([]transport.SigningKey, len(keys))
	for i, k := range keys {
		out[i] = transport.SigningKey{KeyID: k.KeyID, State: transport.SigningKeyState(k.State), PublicKey: k.PublicKey,
			Algorithm: transport.SignatureAlgorithm(k.Algorithm)}
	}
	return out
}

// CiphertextKey names the key a ciphertext was made under (KeyID): Format (3, 4, 5 or 6); MasterVersion for format
// 4 or 5; TenantKeyID for a wrapped tenant's (format 3 or 6: the id of the tenant key blob it needs). String()
// writes it for a log line: "tenant-key:<hex>" or the master version id.
type CiphertextKey = transport.KeyID

// KeyID reads a stored ciphertext's header and names the key it was made under — what a service needs to find
// the rows a migration still has to move (ReEncrypt), and which tenant key blob a wrapped tenant's row needs. It
// runs locally and decrypts nothing: the header is authenticated only when cipheron opens the ciphertext. Bytes
// that are not a cipheron ciphertext — cipheron's magic with a format this protocol does not have included
// (wire/transport.ErrCiphertextFormat in the chain) — are ErrInvalidInput.
func KeyID(ciphertext []byte) (CiphertextKey, error) {
	k, err := transport.ParseKeyID(transport.Release(), ciphertext)
	if err != nil {
		return CiphertextKey{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return k, nil
}

// hasReason reports whether s carries cipheron's google.rpc.ErrorInfo of reason (transport.ErrorDomain) — the
// machine-readable reason of a refusal; the message is for humans and is never matched.
func hasReason(s *status.Status, reason string) bool {
	for _, d := range s.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.GetDomain() == transport.ErrorDomain && ei.GetReason() == reason {
			return true
		}
	}
	return false
}

// isBusy reports cipheron's "busy, retry later": its ErrorInfo of transport.ReasonBusy, or a RetryInfo (which
// cipheron's busy answers carry too, and gRPC's own "message larger than the limit" never does).
func isBusy(s *status.Status) bool {
	if hasReason(s, transport.ReasonBusy) {
		return true
	}
	for _, d := range s.Details() {
		if _, ok := d.(*errdetails.RetryInfo); ok {
			return true
		}
	}
	return false
}

// isSizeRefusal reports gRPC's own refusal of a message over a size limit — cipheron's maxRequestBytes (its
// server's MaxRecvMsgSize) or this client's WithMaxMessageBytes: RESOURCE_EXHAUSTED with no details and the
// wording grpc-go gives every such refusal (rpc_util.go, stream.go, server.go: "grpc: received message larger than
// max (%d vs. %d)", "trying to send message larger than max (%d vs. %d)", "… after decompression larger than max …",
// "grpc: message too large (%d bytes)"). gRPC tells a size refusal by nothing else, so the wording is read here
// and nowhere else in this package; TestSizeRefusalIsGRPCsOwn pins it against the vendored gRPC, end to end.
func isSizeRefusal(s *status.Status) bool { return client.SizeRefusal(s) }

// RetryAfter is the delay cipheron asked for before the call is tried again: the google.rpc.RetryInfo of the
// answer err was made from. cipheron's busy answer (ErrBusy) carries one, of a second. False when err carries
// none: no error, an error this library decided itself, or an answer without a RetryInfo — choose a backoff then.
//
// The delay is the server's word in an answer that is not signed: use it as a hint and bound it (a ceiling of
// your own, jitter across callers); a zero delay is "at once".
//
//	if errors.Is(err, cipheron.ErrBusy) {
//		wait, ok := cipheron.RetryAfter(err)
//		if !ok || wait > maxWait {
//			wait = maxWait
//		}
//		…
//	}
func RetryAfter(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	s, ok := status.FromError(err)
	if !ok {
		return 0, false
	}
	for _, d := range s.Details() {
		ri, ok := d.(*errdetails.RetryInfo)
		if !ok {
			continue
		}
		delay := ri.GetRetryDelay()
		if delay == nil || delay.CheckValid() != nil || delay.AsDuration() < 0 {
			return 0, false
		}
		return delay.AsDuration(), true
	}
	return 0, false
}

// answered is an error cipheron answered, as this package returns it: the package's value for it (kind — what
// errors.Is is asked; a kind of another, as ErrBusy of ErrUnavailable, wraps it), the message this package has
// always shown (the value's, then the answer's), and the error the protocol client returned, whole. So errors.Is
// also finds what that error is (client.ErrCertificateRefused, ErrUnknownSigningKey), and status.FromError its
// gRPC status with the details (RetryAfter).
type answered struct {
	kind error // nil: an answer this package has no value for
	msg  string
	err  error
}

func (e *answered) Error() string { return e.msg }

func (e *answered) Unwrap() []error {
	if e.kind == nil {
		return []error{e.err}
	}
	return []error{e.kind, e.err}
}

// mapErr turns an error of the protocol client into this package's: a value of this package first, the client's
// error kept in the chain behind it (answered). What the client decided itself (ErrServerIdentity,
// ErrServerKeyChanged, ErrPinRequired, ErrBadResponse, ErrTooLarge, ErrTenancy, ErrClosed, ErrSigningKeyRevoked, and
// ErrUnknownSigningKey and ErrKeysStale when no fetch failed under them) is already one. A status cipheron answered
// is mapped before the context is looked at, so a refusal that arrived as the context ended is still a refusal; a
// call cut short by its context returns the context's error, bare.
//
// The message of a mapped status is what it has always been — the value's text, then the status's message — for
// the values that existed before the chain was kept; only errors.Is, errors.As and status.FromError see more.
func mapErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSigningKeyRevoked) {
		return err
	}
	// The party on the other end, or its answer, before the caller's input: an identity failure or a malformed answer
	// whose cause names an input layout (a forged key statement in a key fetch is also ErrKeyStatement) is never the
	// caller's invalid input.
	for _, sentinel := range []error{ErrServerIdentity, ErrServerKeyChanged, ErrPinRequired, ErrContextDigest,
		ErrBadResponse} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	if errors.Is(err, ErrTenantKey) || errors.Is(err, transport.ErrCiphertext) || errors.Is(err, ErrAssociatedData) ||
		errors.Is(err, ErrSegmented) || errors.Is(err, ErrKeyStatement) || errors.Is(err, ErrJSONField) {
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	for _, sentinel := range []error{ErrTooLarge, ErrTenancy, ErrClosed} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	s, ok := status.FromError(err)
	if !ok {
		if (errors.Is(err, ErrUnknownSigningKey) || errors.Is(err, ErrKeysStale)) &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err // the Client's own decision: nothing was cut short
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("cipheron: %w", err)
	}
	// lead is the value whose text opens the message; kind the value the error is (lead, or a kind of it).
	var lead, kind error
	switch s.Code() {
	case codes.PermissionDenied:
		lead = ErrPermissionDenied // a refused certificate too: err is then client.ErrCertificateRefused, kept
	case codes.InvalidArgument:
		lead = ErrInvalidInput
		switch {
		case hasReason(s, transport.ReasonKeyVersionUnavailable):
			lead = ErrKeyVersionUnavailable
		case hasReason(s, transport.ReasonAssociatedData):
			kind = errAssociatedDataInput
		}
	case codes.ResourceExhausted:
		// Three things answer this code. cipheron's "busy" carries its reason and a RetryInfo; gRPC's refusal of a
		// message over a limit carries no details and gRPC's wording; anything else (a proxy or a mesh shedding
		// load, an HTTP/2 stream reset as ENHANCE_YOUR_CALM) is neither, and is not a verdict on the data's size:
		// unavailable, to be retried.
		switch {
		case isBusy(s):
			lead, kind = ErrUnavailable, ErrBusy
		case isSizeRefusal(s):
			lead = ErrTooLarge
		default:
			lead = ErrUnavailable
		}
	case codes.Unavailable:
		lead = ErrUnavailable
		switch {
		case hasReason(s, transport.ReasonNoWriter):
			kind = ErrNoWriter
		case hasReason(s, transport.ReasonProfileSealed):
			kind = ErrProfileSealed
		}
	case codes.Unimplemented:
		lead = ErrUnsupported
	case codes.Internal:
		lead = ErrInternal
	case codes.DeadlineExceeded, codes.Canceled:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// Not this call's context: a deadline or a cancellation of gRPC's own, or of the server's.
		kind = context.DeadlineExceeded
		if s.Code() == codes.Canceled {
			kind = context.Canceled
		}
		return &answered{kind: kind, msg: fmt.Sprintf("cipheron: %s: %s", s.Message(), kind), err: err}
	default:
		return &answered{msg: fmt.Sprintf("cipheron: %s (%s)", s.Message(), s.Code()), err: err}
	}
	if kind == nil {
		kind = lead
	}
	return &answered{kind: kind, msg: lead.Error() + ": " + s.Message(), err: err}
}
