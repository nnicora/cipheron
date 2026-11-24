// Package cipherontest is a CipherService a test controls — for package cipheron's own tests and for an application's:
// it holds a profile's keys — an identity (HPKE and response keys), versioned signing keys, master key versions,
// tenant keys — checks request auth and signs its answers as the protocol says (wire/transport), and
// can be switched into the ways an impostor or a broken server answers (SetMode), or the ways cipheron answers when it
// cannot serve (Fail: busy, no writer, internal, unimplemented). It is as strict as cipheron on the wire, with
// cipheron's messages (transport's constants): a request carrying a field cipheron does not know is refused
// (strictfields.go), a request auth that does not verify is refused, a tenant key blob it did not make — its header
// or its sealed part altered by a byte — is refused as cipheron refuses a blob that does not open, associated data over
// 64 KiB is refused, a
// re-encryption (a ReEncrypt, a ReEncryptBatch item) with associated_data and no to_associated_data is refused, one
// to other associated data is served only where decrypt and encrypt are granted, a batch is held to batch.maxItems and
// batch.maxBytes counted as cipheron counts them (batch.go), the JSON API refuses what cipheron's gateway refuses
// (http.go), and every answer is signed the way a client must verify it — over the profile's key-context digest, as
// cipheron signs it (AnswerOtherContext: a replica on another context). What it does NOT model: caller entries and
// their identities (every connection is the profile's caller) — its grants are all operations unless Grant restricts a
// profile's, with cipheron's rules (a cross-profile ReEncrypt is export on the source, import on the target, and
// retenant on the source when it changes the tenant; its target tenant is held to the target profile's tenancy with
// cipheron's answers; a re-binding needs decrypt on the source and encrypt on the target) and cipheron's order (a
// profile with a request key verifies the request's auth before its grant).
//
// It is not cipheron (the server) and shares no code with it, so a client's tests do not depend on the server's. Its
// ciphertexts and tenant key blobs are made as cipheron makes them — the stored layouts and their cryptography are
// wire/transport's (NewCiphertextSealer, NewCiphertextOpener, SealTenantKey), which cipheron uses too — under
// keys the fake makes per test (New), which no cipheron holds: never store or ship anything it encrypted. Its socket
// lives in the test's temporary directory. Import it from tests only (it takes a testing.TB).
package cipherontest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/types/known/durationpb"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

// Mode is how the fake answers.
type Mode int

const (
	// Honest answers as cipheron does.
	Honest Mode = iota
	// JunkCiphertext answers Encrypt and ReEncrypt with random bytes, signed by the profile's response key.
	JunkCiphertext
	// GarbledPlaintext answers Decrypt with a sealed plaintext that does not open, signed by the response key.
	GarbledPlaintext
	// ForeignResponseSignature signs every answer but PublicKey's with a key that is not the profile's.
	ForeignResponseSignature
	// NoResponseSignature answers every call but PublicKey without a response signature.
	NoResponseSignature
	// ShortSignature answers Sign with 63 bytes of a real signature, the answer signed.
	ShortSignature
	// ForeignSignature answers Sign with a signature by a key that is not the profile's (nor the tenant's), under
	// the right key id, the answer signed.
	ForeignSignature
	// UnknownKeyID answers Sign with a real signature under a key id no listed key has, the answer signed.
	UnknownKeyID
	// OtherListedKeyID answers Sign with the active key's signature under another listed key's id, the answer
	// signed (a profile with at least two signing keys).
	OtherListedKeyID
	// OtherTenantBlob answers CreateTenantKey with a blob of another tenant, signed by the response key.
	OtherTenantBlob
	// OtherKeyIDCiphertext answers a wrapped tenant's Encrypt and ReEncrypt with a format-3 ciphertext of another
	// tenant key id, signed.
	OtherKeyIDCiphertext
	// WrongFormatCiphertext answers Encrypt and ReEncrypt with a well-formed ciphertext of the other family —
	// format 3 in a shared or derived profile, format 4 in a wrapped one — signed.
	WrongFormatCiphertext
	// ForgedKeysSignature answers PublicKey with keys_signature by a key that is not the profile's response key.
	ForgedKeysSignature
	// KeysForOtherProfile answers PublicKey with keys_signature over another profile's transcript.
	KeysForOtherProfile
	// KeysForOtherContext answers PublicKey with keys_signature over another context digest than the one answered.
	KeysForOtherContext
	// KeysOfAnotherIdentity answers PublicKey with the profile's identity but another identity's signing keys,
	// context digest and keys_signature (a valid list, signed — by another response key).
	KeysOfAnotherIdentity
	// UnsignedExtraKey answers PublicKey with a signing key added to the list after it was signed.
	UnsignedExtraKey
	// ForgetVerifyOnlyKeys answers PublicKey with a list, validly signed, that leaves out every verify-only key: an
	// older list replayed, or a server forgetting keys.
	ForgetVerifyOnlyKeys
	// RewrapOtherKeyID answers RewrapTenantKey with a blob of another key id, signed.
	RewrapOtherKeyID
	// RewrapOtherSigningKey answers RewrapTenantKey with a blob of another signing key, signed.
	RewrapOtherSigningKey
	// RewrapOtherFingerprint answers RewrapTenantKey with the right blob but another fingerprint, signed.
	RewrapOtherFingerprint
	// RewrapOtherCreated answers RewrapTenantKey with a blob of another creation time, signed.
	RewrapOtherCreated
	// LongCiphertext answers Encrypt and ReEncrypt with the honest ciphertext and one byte more, signed.
	LongCiphertext
	// UnknownTenancy answers PublicKey with a tenancy number this protocol does not have (9): a client refuses the
	// answer.
	UnknownTenancy
	// UnknownFormatCiphertext answers Encrypt and ReEncrypt with the honest ciphertext under cipheron's magic and a
	// format byte this protocol does not have (UnknownFormat), of the honest length, signed: a client refuses it.
	UnknownFormatCiphertext
	// UnknownVersionBlob answers CreateTenantKey and RewrapTenantKey with the key's blob under a layout version this
	// protocol does not have (UnknownBlobVersion), signed: a client refuses it.
	UnknownVersionBlob
	// SignRevoked answers a shared or derived profile's Sign with a revoked signing key's signature under its key id,
	// signed: a replica that has not learnt the revocation (a profile with a revoked key) — every answer signed under
	// that replica's key context, the one before the revocation.
	SignRevoked
	// ForgedKeyStatement answers PublicKey with a key statement signed by a key that is not the profile's.
	ForgedKeyStatement
	// MismatchedKeyStatement answers PublicKey with a key statement, validly signed, that leaves out a signing key
	// the (fresh, signed) answer lists.
	MismatchedKeyStatement
	// NoHPKESuite answers PublicKey without hpke_suite.
	NoHPKESuite
	// AdditionalIdentityKey answers PublicKey with an additional identity key of a suite no client implements (its
	// identity's fingerprint is version 2): tolerated, never used.
	AdditionalIdentityKey
	// UnknownHPKESuite answers PublicKey with the identity's HPKE suite a suite no client implements (fingerprint
	// version 2): the keys verify, and a sealed request is refused by the client.
	UnknownHPKESuite
	// UnknownSigningAlgorithm answers PublicKey with one more verify-only signing key of an algorithm no client
	// implements (UnknownAlgorithm), its id the algorithm's (transport.SigningKeyIDOf), the list validly signed.
	UnknownSigningAlgorithm
	// NoSecondSignature answers a cross-profile ReEncrypt without to_response_signature.
	NoSecondSignature
	// ShortBatch answers every batch with its last result left out, the response signature made over what it answers:
	// a cipheron answering one result too few (a client refuses it as ErrBadResponse).
	ShortBatch
	// BatchResultDropped answers every batch with its last result removed AFTER the response signature was made, as a
	// party in the path would drop it (a client refuses it as ErrServerIdentity: the signature does not verify).
	BatchResultDropped
	// AnswerOtherContext signs every answer but PublicKey's, with the profile's response key, under a key-context digest
	// PublicKey does not answer: a replica of the profile on another (drifted or stale) key context answering a data
	// call. A client refuses the answer: it verifies only under a digest the client pins or, unpinned, one the profile's
	// verified keys answered (transport.ResponseTranscript).
	AnswerOtherContext
	// AssociatedDataDropped answers an Encrypt or a ReEncrypt made with associated data with a ciphertext made without
	// it — format 4 in a shared or derived profile, format 3 in a wrapped one — signed: a client refuses it
	// (ErrBadResponse), since its row would no longer be bound to the associated data it asked for.
	AssociatedDataDropped
	// UnknownSigningKeyState answers PublicKey with one more signing key in a state this protocol does not have
	// (UnknownStateNumber), the list validly signed over that number: a client refuses the whole answer
	// (ErrBadResponse).
	UnknownSigningKeyState
	// ReplayedKeys answers PublicKey with the profile's honest answer to another request nonce — a recorded answer
	// replayed: a client refuses it (ErrServerIdentity: keys_signature does not verify over the nonce it sent).
	ReplayedKeys
	// AnsweredOtherSigningKey answers CreateTenantKey and RewrapTenantKey with the honest blob and its fingerprint but
	// a signing_public_key the blob's header does not name, the answer signed over what it answers: a client refuses
	// it (ErrBadResponse), since it would check the tenant's signatures under a key the blob does not hold.
	AnsweredOtherSigningKey
)

// UnknownStateNumber is the signing-key state number UnknownSigningKeyState answers: none of this protocol's (1 to 3).
const UnknownStateNumber = 4

// UnknownAlgorithm is the signing-key algorithm UnknownSigningAlgorithm answers, as a client reports it
// (cipheron.SigningKey.Algorithm); UnknownSuite the HPKE suite UnknownHPKESuite and AdditionalIdentityKey answer, as a
// client reports it (cipheron.Keys.HPKESuite).
const (
	UnknownAlgorithm uint32 = 77
	UnknownSuite            = "0x0647/0x0001/0x0002"
)

// The protocol's values of UnknownAlgorithm and UnknownSuite, which the fake answers.
var (
	unknownAlgorithm = transport.SignatureAlgorithm(UnknownAlgorithm)
	unknownSuite     = transport.HPKESuite{KEM: 0x0647, KDF: 0x0001, AEAD: 0x0002}
)

// UnknownTenancyNumber, UnknownFormat and UnknownBlobVersion are the numbers UnknownTenancy, UnknownFormatCiphertext
// and UnknownVersionBlob answer: none is a tenancy, a ciphertext format or a tenant key blob version of this protocol.
const (
	UnknownTenancyNumber = 9
	UnknownFormat        = 9
	UnknownBlobVersion   = transport.TenantKeyVersion + 1
)

// Fault is an answer the fake gives in place of serving a call (Fail, FailPublicKey): what cipheron answers when
// it cannot serve, with the status code and the details cipheron gives it (the server).
type Fault int

const (
	// NoFault serves the call.
	NoFault Fault = iota
	// Busy answers RESOURCE_EXHAUSTED with the ErrorInfo of transport.ReasonBusy and a RetryInfo of BusyRetryDelay —
	// cipheron at a limit of requests in flight. Answered before the request's auth is looked at (cipheron's limit
	// is checked before a request is read), so the request's nonce is not used up.
	Busy
	// NoWriter answers a WRITE UNAVAILABLE with the ErrorInfo of transport.ReasonNoWriter — no master key version
	// writes at cipheron's clock. A write is an Encrypt or a ReEncrypt whose new ciphertext is a shared or derived
	// profile's, CreateTenantKey and RewrapTenantKey, and their batches. A wrapped profile's Encrypt and ReEncrypt use
	// the tenant's own key and are served, as cipheron serves them; for a cross-profile ReEncrypt, the target's
	// tenancy decides. Reads (Decrypt, Sign) are served. Answered after the request's auth verified, as cipheron
	// answers it.
	NoWriter
	// Internal answers INTERNAL "internal error", after the request's auth verified.
	Internal
	// Unimplemented answers UNIMPLEMENTED: a cipheron that does not have the call (an older version).
	Unimplemented
	// Overloaded answers RESOURCE_EXHAUSTED with no details and a message of its own: not cipheron's busy answer
	// and not gRPC's size refusal — what a proxy shedding load in front of cipheron answers.
	Overloaded
	// ProfileSealed answers UNAVAILABLE with the ErrorInfo of transport.ReasonProfileSealed and a RetryInfo of
	// ProfileSealedRetryDelay — the profile is sealed on that replica (cipheron's unseal.partial). Answered before the
	// request's auth is looked at (cipheron answers it at the profile's lookup), and to PublicKey too (FailPublicKey).
	ProfileSealed
)

// ProfileSealedRetryDelay is the delay of the ProfileSealed fault's RetryInfo: cipheron's (5 s).
const ProfileSealedRetryDelay = 5 * time.Second

// BusyRetryDelay is the delay of the Busy fault's RetryInfo: cipheron's (a second).
const BusyRetryDelay = time.Second

// BusyMessage, NoWriterMessage and InternalMessage are the messages of the faults' answers.
const (
	BusyMessage     = "cipheron is busy: too many requests in flight; retry later"
	NoWriterMessage = "no master key version writes now"
	InternalMessage = "internal error"
)

func withDetails(code codes.Code, msg string, details ...protoadapt.MessageV1) error {
	st, err := status.New(code, msg).WithDetails(details...)
	if err != nil {
		panic(err) // constant details of registered types: cannot fail
	}
	return st.Err()
}

// answer is the fault's answer; nil for NoFault.
func (f Fault) answer() error {
	switch f {
	case Busy:
		return withDetails(codes.ResourceExhausted, BusyMessage,
			&errdetails.ErrorInfo{Reason: transport.ReasonBusy, Domain: transport.ErrorDomain},
			&errdetails.RetryInfo{RetryDelay: durationpb.New(BusyRetryDelay)})
	case NoWriter:
		return withDetails(codes.Unavailable, NoWriterMessage,
			&errdetails.ErrorInfo{Reason: transport.ReasonNoWriter, Domain: transport.ErrorDomain})
	case ProfileSealed:
		return withDetails(codes.Unavailable, "the profile is sealed on this replica",
			&errdetails.ErrorInfo{Reason: transport.ReasonProfileSealed, Domain: transport.ErrorDomain},
			&errdetails.RetryInfo{RetryDelay: durationpb.New(ProfileSealedRetryDelay)})
	case Internal:
		return status.Error(codes.Internal, InternalMessage)
	case Unimplemented:
		return status.Error(codes.Unimplemented, "unknown method for service cipheron.v1.CipherService")
	case Overloaded:
		return status.Error(codes.ResourceExhausted, "upstream is overloaded")
	}
	return nil
}

// MaxMessageBytes is the largest message the fake accepts or sends.
const MaxMessageBytes = 96 << 20

// skew is how far a request's timestamp may be from the fake's clock.
const skew = 30 * time.Second

// KeyVersionUnavailable is the fake's INVALID_ARGUMENT message for a ciphertext of a master key version it does not
// list (RetireVersion) — cipheron's.
const KeyVersionUnavailable = "the key version of this ciphertext is not available"

// tenantKeyVersionUnavailable is cipheron's message for a tenant key blob wrapped under such a version.
const tenantKeyVersionUnavailable = "the key version of this tenant key is not available"

// cipheron's INVALID_ARGUMENT answers to a cross-profile ReEncrypt whose target side does not fit the target profile's
// tenancy (targetTenancy): a perTenant target without a valid tenant id (or a wrapped one without to_tenant_key, a
// derived one with it), and a shared target named a to_tenant or sent a to_tenant_key.
const (
	toTenantMessage = "the target profile is perTenant: to_tenant (or the request's tenant) names a tenant id, and a " +
		"wrapped target needs to_tenant_key"
	toSharedMessage = "the target profile is shared: the request names no to_tenant and carries no to_tenant_key for it"
)

// targetTenancy is cipheron's check of a cross-profile ReEncrypt's target side against the target profile's tenancy
// (its admitTarget, with authorizeTenant's rules for one side): toTenant is the request's to_tenant, or the source's
// tenant for a perTenant target; toBlob is to_tenant_key.
func targetTenancy(tenancy transport.Tenancy, toTenant string, toBlob []byte) error {
	switch tenancy {
	case transport.TenancyShared:
		if toTenant != "" || len(toBlob) > 0 {
			return status.Error(codes.InvalidArgument, toSharedMessage)
		}
		return nil
	case transport.TenancyPerTenantDerived:
		if toTenant == "" || len(toBlob) > 0 {
			return status.Error(codes.InvalidArgument, toTenantMessage)
		}
	default:
		if toTenant == "" || len(toBlob) == 0 {
			return status.Error(codes.InvalidArgument, toTenantMessage)
		}
	}
	if !transport.ValidTenant(toTenant) {
		return status.Error(codes.InvalidArgument, toTenantMessage)
	}
	return nil
}

type signingKey struct {
	priv  ed25519.PrivateKey
	state transport.SigningKeyState
	// code is the state number PublicKey answers instead of state's (MarkSigningKeyUnknown, SignSigningKeyUnknown);
	// 0: state's own. signed: keys_signature is made over code (SignSigningKeyUnknown), not over state's number.
	code   uint32
	signed bool
}

func (s *signingKey) public() ed25519.PublicKey { return publicHalf(s.priv) }

// publicHalf is key's public half.
func publicHalf(key ed25519.PrivateKey) ed25519.PublicKey {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		panic("cipherontest: an Ed25519 private key's public half is not an ed25519.PublicKey") // Public answers one: cannot happen
	}
	return pub
}

type profileKeys struct {
	tenancy      transport.Tenancy
	hpke         hpke.PrivateKey
	response     ed25519.PrivateKey
	signing      []*signingKey
	versions     []string // the listed master version ids
	writeVersion string
	data         map[string][]byte // master version → the fake's data key
	formats      *format.Policy    // the fake's (Server.formats)
}

// tenantKeys are a tenant key the fake made: its blob's id indexes them. The fake's blob is a blob as cipheron makes
// one (blobOf), wrapped under the fake's key of its wrapping version; the fake keeps the keys itself and opens no blob.
type tenantKeys struct {
	profile, tenant string
	keyID           []byte
	signing         ed25519.PrivateKey
	storage         []byte
	created         time.Time
}

func newProfileKeys(tb testing.TB, p *format.Policy) *profileKeys {
	tb.Helper()
	sk, err := transport.NewOneTimeKey()
	if err != nil {
		tb.Fatal(err)
	}
	_, response, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	k := &profileKeys{tenancy: transport.TenancyShared, hpke: sk, response: response, versions: []string{"v1"},
		writeVersion: "v1", data: map[string][]byte{}, formats: p}
	k.addSigningKey()
	return k
}

// addSigningKey adds a new active signing key; the others become verify-only.
func (k *profileKeys) addSigningKey() *signingKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	for _, o := range k.signing {
		o.state = transport.SigningKeyVerifyOnly
	}
	n := &signingKey{priv: priv, state: transport.SigningKeyActive}
	k.signing = append(k.signing, n)
	return n
}

func (k *profileKeys) active() *signingKey {
	for _, s := range k.signing {
		if s.state == transport.SigningKeyActive {
			return s
		}
	}
	return nil
}

func (k *profileKeys) identity() transport.Identity {
	return transport.Identity{Tenancy: k.tenancy, HPKE: k.hpke.PublicKey().Bytes(),
		Response: publicHalf(k.response)}
}

// list is the signing-key list PublicKey answers, in canonical order: none in a wrapped profile.
func (k *profileKeys) list() []transport.SigningKey {
	if !k.tenancy.HasSigningKeys() {
		return nil
	}
	out := make([]transport.SigningKey, 0, len(k.signing))
	for _, s := range k.signing {
		out = append(out, transport.SigningKey{KeyID: transport.SigningKeyID(s.public()), State: s.state,
			PublicKey: s.public()})
	}
	transport.SortSigningKeys(out)
	return out
}

// byID is the profile's signing key whose id is keyID, nil when none.
func (k *profileKeys) byID(keyID []byte) *signingKey {
	for _, s := range k.signing {
		if bytes.Equal(transport.SigningKeyID(s.public()), keyID) {
			return s
		}
	}
	return nil
}

// fakeKCV is the fake's check value of a key named name: a function of the name only (the fake has no masters).
func fakeKCV(name string) []byte {
	sum := sha256.Sum256([]byte("fakecipheron|kcv|" + name))
	return sum[:transport.KeyCheckValueLen]
}

func (k *profileKeys) contextDigest(profile string) string {
	return k.contextDigestOf(profile, k.list())
}

// unrevokedContextDigest is the context digest of a replica that has not learnt the profile's signing-key revocations:
// every revoked key still published (SignRevoked's replica).
func (k *profileKeys) unrevokedContextDigest(profile string) string {
	list := k.list()
	for i := range list {
		if list[i].State == transport.SigningKeyRevoked {
			list[i].State = transport.SigningKeyVerifyOnly
		}
	}
	return k.contextDigestOf(profile, list)
}

func (k *profileKeys) contextDigestOf(profile string, list []transport.SigningKey) string {
	c := transport.KeyContext{Profile: profile, Tenancy: k.tenancy, KeysetFingerprint: transport.Fingerprint(profile, k.identity()),
		SigningKeys: list}
	for _, v := range k.versions {
		c.MasterVersions = append(c.MasterVersions, transport.MasterVersionCheck{ID: v, KCV: fakeKCV(v)})
	}
	d, err := transport.ContextDigest(c)
	if err != nil {
		panic(err)
	}
	return d
}

// answer is the honest PublicKey answer to a request with request_nonce nonce: keys_signature over the list — each
// key's state its own number, or the number SignSigningKeyUnknown answers it under.
func (k *profileKeys) answer(profile string, nonce []byte) transport.ProfileKeys {
	list, digest := k.list(), k.contextDigest(profile)
	signed := map[string]uint32{}
	for _, s := range k.signing {
		if s.signed {
			signed[string(transport.SigningKeyID(s.public()))] = s.code
		}
	}
	tr := keysTranscript(k.formats, profile, k.tenancy, digest, nonce, list)
	if len(signed) > 0 {
		received := make([]transport.ReceivedSigningKey, len(list))
		for i, sk := range list {
			code, ok := signed[string(sk.KeyID)]
			if !ok {
				code = sk.State.Code()
			}
			received[i] = transport.ReceivedSigningKey{KeyID: sk.KeyID, State: code, PublicKey: sk.PublicKey}
		}
		tr = transport.ReceivedSigningKeysTranscript(k.formats, profile, k.tenancy, digest, nonce, received)
	}
	return transport.ProfileKeys{Identity: k.identity(), SigningKeys: list, ContextDigest: digest,
		KeysSignature: ed25519.Sign(k.response, tr)}
}

// wireStates is the state number PublicKey answers for each key whose number is not its state's
// (MarkSigningKeyUnknown, SignSigningKeyUnknown), by key id.
func (k *profileKeys) wireStates() map[string]uint32 {
	out := map[string]uint32{}
	for _, s := range k.signing {
		if s.code != 0 {
			out[string(transport.SigningKeyID(s.public()))] = s.code
		}
	}
	return out
}

// keysTranscript is the signing-keys transcript the fake signs a PublicKey answer under.
func keysTranscript(p *format.Policy, profile string, tenancy transport.Tenancy, digest string, nonce []byte, keys []transport.SigningKey,
) []byte {
	t, err := transport.SigningKeysTranscript(p, profile, tenancy, digest, nonce, keys)
	if err != nil {
		panic(err) // the fake's keys are in one of the three states
	}
	return t
}

func (k *profileKeys) listed(version string) bool {
	return slices.Contains(k.versions, version)
}

// available reports whether data made under version is read: the version is listed — cipheron's keyring
// (Profile.available, and wrapFor for a blob).
func (k *profileKeys) available(version string) bool { return k.listed(version) }

// dataKey is the fake's data key of master version version, made on first use.
func (k *profileKeys) dataKey(version string) []byte {
	if d, ok := k.data[version]; ok {
		return d
	}
	d := make([]byte, 32)
	_, _ = rand.Read(d)
	k.data[version] = d
	return d
}

// Server is the fake CipherService.
type Server struct {
	cipheronv1.UnimplementedCipherServiceServer

	tb testing.TB

	mu         sync.Mutex
	profiles   map[string]*profileKeys
	other      map[string]*profileKeys // KeysOfAnotherIdentity's identities
	tenantKeys map[string]*tenantKeys  // by key id
	// blobs are the tenant key blobs the fake made, whole (header and sealed part): cipheron opens a blob with its
	// header as the additional data, so a blob with one byte changed anywhere does not open — the fake refuses any
	// blob it did not make (tenantOf), as cipheron does.
	blobs       map[string]bool
	requestKeys map[string]ed25519.PublicKey
	grants      map[string]map[transport.Operation]bool // Grant: a profile absent grants every operation
	nonces      map[string]bool
	start       time.Time // the instant the fake's "process" started (New, Restart): the start barrier (checkAuth)
	mode        Mode
	fault       Fault // every call but PublicKey (Fail)
	keysFault   Fault // PublicKey (FailPublicKey)
	gate        chan struct{}
	perConn     map[int64]int // Encrypt calls per connection
	batchMax    int           // SetBatchMaxItems; 0: DefaultBatchMaxItems
	// batchMaxBytes: SetBatchMaxBytes; 0: DefaultBatchMaxBytes.
	batchMaxBytes int64
	batchCalls    atomic.Int64
	batchRefusals atomic.Int64

	publicKeyCalls atomic.Int64
	authVerified   atomic.Int64
	authAbsent     atomic.Int64
	authRefused    atomic.Int64
	authIgnored    atomic.Int64
	connSeq        atomic.Int64
	foreign        ed25519.PrivateKey
	socketPath     string
	// formats is what the fake reads and writes: the protocol's release (New), a test's policy (newServer).
	formats *format.Policy
}

// New is a fake serving profiles, each shared, with keys of its own: an identity (HPKE and response keys), one
// active signing key, and the master version "v1" (active).
func New(tb testing.TB, profiles ...string) *Server {
	tb.Helper()
	return newServer(tb, transport.Release(), profiles...)
}

// newServer is New reading and writing what p does.
func newServer(tb testing.TB, p *format.Policy, profiles ...string) *Server {
	tb.Helper()
	s := &Server{tb: tb, formats: p, profiles: map[string]*profileKeys{}, other: map[string]*profileKeys{},
		requestKeys: map[string]ed25519.PublicKey{}, grants: map[string]map[transport.Operation]bool{},
		nonces: map[string]bool{}, perConn: map[int64]int{},
		tenantKeys: map[string]*tenantKeys{}, blobs: map[string]bool{},
		start: time.Now().Truncate(time.Millisecond)}
	for _, d := range profiles {
		s.profiles[d] = newProfileKeys(tb, s.formats)
	}
	_, s.foreign, _ = ed25519.GenerateKey(rand.Reader)
	return s
}

func (s *Server) profile(profile string) *profileKeys {
	k := s.profiles[profile]
	if k == nil {
		s.tb.Fatalf("cipherontest: no profile %q", profile)
	}
	return k
}

// ProfileKeys is a profile's keys as the fake holds them: what a client's Keys must report for it.
type ProfileKeys struct {
	// Tenancy is the profile's tenancy as a client reports it (cipheron.TenancyShared, …).
	Tenancy string
	// HPKE is the HPKE public key requests are sealed to; Response the key every answer is signed by.
	HPKE     []byte
	Response ed25519.PublicKey
	// ContextDigest is the profile's key-context digest ("sha256:…").
	ContextDigest string
	// SigningKeys are the profile's signing keys, in the order the fake publishes them.
	SigningKeys []ProfileSigningKey
}

// ProfileSigningKey is one of a profile's signing keys: its id, its state ("active", "verifyOnly", "revoked") and its
// public key.
type ProfileSigningKey struct {
	KeyID     []byte
	State     string
	PublicKey ed25519.PublicKey
}

// ProfileKeys is the profile's keys, as its PublicKey answer carries them.
func (s *Server) ProfileKeys(profile string) ProfileKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.profile(profile).answer(profile, nil)
	out := ProfileKeys{Tenancy: string(a.Tenancy), HPKE: bytes.Clone(a.HPKE), Response: bytes.Clone(a.Response),
		ContextDigest: a.ContextDigest}
	for _, k := range a.SigningKeys {
		out.SigningKeys = append(out.SigningKeys, ProfileSigningKey{KeyID: bytes.Clone(k.KeyID), State: string(k.State),
			PublicKey: bytes.Clone(k.PublicKey)})
	}
	return out
}

// RevokeSigning marks the profile's signing key keyID revoked — listed, never signing (but under SignRevoked), every
// signature under it refused by a client. The active key cannot be revoked. The context digest changes.
func (s *Server) RevokeSigning(profile string, keyID []byte) {
	s.setSigningState(profile, keyID, transport.SigningKeyRevoked, 0, false)
}

// UnrevokeSigning marks the profile's signing key keyID verify-only again: what a stale replica (or a forged history)
// answers after a revocation, which a client that saw the revocation must not honour.
func (s *Server) UnrevokeSigning(profile string, keyID []byte) {
	s.setSigningState(profile, keyID, transport.SigningKeyVerifyOnly, 0, false)
}

// MarkSigningKeyUnknown answers the profile's signing key keyID in PublicKey under the state number code, which is no
// state of this protocol (above 3), while keys_signature is over the key's own state: the number changed after the
// answer was signed, as a party in the path would change it. A client refuses the whole answer as not cipheron's
// (ErrServerIdentity: keys_signature does not verify over what it received). The key stays verify-only in the fake's
// own list, context digest and key statement. The active key cannot be marked.
func (s *Server) MarkSigningKeyUnknown(profile string, keyID []byte, code uint32) {
	s.markSigningKeyUnknown(profile, keyID, code, false)
}

// SignSigningKeyUnknown is MarkSigningKeyUnknown with keys_signature made over code: a cipheron answering, and
// signing, a state this protocol does not have. A client refuses the whole answer as ErrBadResponse (it never lists,
// verifies under or accepts a signature by a key in such a state).
func (s *Server) SignSigningKeyUnknown(profile string, keyID []byte, code uint32) {
	s.markSigningKeyUnknown(profile, keyID, code, true)
}

func (s *Server) markSigningKeyUnknown(profile string, keyID []byte, code uint32, signed bool) {
	if code <= transport.SigningKeyRevoked.Code() {
		s.tb.Fatalf("cipherontest: %d is not past the signing-key state numbers", code)
	}
	s.setSigningState(profile, keyID, transport.SigningKeyVerifyOnly, code, signed)
}

func (s *Server) setSigningState(profile string, keyID []byte, st transport.SigningKeyState, code uint32, signed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := s.profile(profile).byID(keyID)
	switch {
	case sk == nil:
		s.tb.Fatalf("cipherontest: profile %q has no signing key %x", profile, keyID)
	case sk.state == transport.SigningKeyActive:
		s.tb.Fatalf("cipherontest: signing key %x is the active one", keyID)
	}
	sk.state, sk.code, sk.signed = st, code, signed
}

// identity is the profile's identity.
func (s *Server) identity(profile string) transport.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile(profile).identity()
}

// Fingerprint is the profile's fingerprint.
func (s *Server) Fingerprint(profile string) string {
	return transport.Fingerprint(profile, s.identity(profile))
}

// ContextDigest is the profile's key-context digest.
func (s *Server) ContextDigest(profile string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile(profile).contextDigest(profile)
}

// ActiveKeyID is the id of the profile's active signing key.
func (s *Server) ActiveKeyID(profile string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return transport.SigningKeyID(s.profile(profile).active().public())
}

// MakePerTenant makes profile a perTenant wrapped profile: no signing keys of its own, calls name a tenant and a blob
// the fake made (CreateTenantKey), shared calls refused. Its identity changes (the tenancy is in it).
func (s *Server) MakePerTenant(profile string) {
	s.setTenancy(profile, transport.TenancyPerTenantWrapped)
}

// MakeDerived makes profile a perTenant derived profile: calls name a tenant and no blob, Sign signs
// transport.TenantSignedMessage with the profile's active signing key.
func (s *Server) MakeDerived(profile string) {
	s.setTenancy(profile, transport.TenancyPerTenantDerived)
}

func (s *Server) setTenancy(profile string, t transport.Tenancy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profile(profile)
	k.tenancy = t
}

// RotateSigning adds a new active signing key to profile (the others become verify-only) — a signing rotation:
// the identity does not change, the signed list does. It returns the new key's id.
func (s *Server) RotateSigning(profile string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return transport.SigningKeyID(s.profile(profile).addSigningKey().public())
}

// AddSigningKey publishes a new signing key in profile, VERIFY-ONLY — what one more signing.generations does in
// cipheron (keygen ensure appends the key to the keyset): listed, so the context digest changes, while Sign goes on
// signing with the active key. ActivateSigning makes it sign. It returns the new key's id.
func (s *Server) AddSigningKey(profile string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profile(profile)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.tb.Fatal(err)
	}
	n := &signingKey{priv: priv, state: transport.SigningKeyVerifyOnly}
	k.signing = append(k.signing, n)
	return transport.SigningKeyID(n.public())
}

// ActivateSigning makes the profile's published signing key keyID the one Sign signs with, and the key that signed
// verify-only — what signing.activeGeneration (or signing.active) does in cipheron. Both stay listed, so a signature
// under either verifies. The context digest does not change: it binds which keys are published and which revoked, not
// which one signs. A key the profile does not list, or revoked, fails the test.
func (s *Server) ActivateSigning(profile string, keyID []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profile(profile)
	sk := k.byID(keyID)
	switch {
	case sk == nil:
		s.tb.Fatalf("cipherontest: profile %q has no signing key %x", profile, keyID)
	case sk.state == transport.SigningKeyRevoked:
		s.tb.Fatalf("cipherontest: signing key %x is revoked: it never signs again", keyID)
	}
	for _, o := range k.signing {
		if o.state == transport.SigningKeyActive {
			o.state = transport.SigningKeyVerifyOnly
		}
	}
	sk.state = transport.SigningKeyActive
}

// SetWriteVersion makes version (listed if it was not) the profile's active master version: new ciphertexts and
// blobs are made under it. The context digest changes when the listing does.
func (s *Server) SetWriteVersion(profile, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profile(profile)
	if !k.listed(version) {
		k.versions = append(k.versions, version)
	}
	k.writeVersion = version
}

// RetireVersion removes version from the profile's listing: its ciphertexts and blobs are refused as cipheron refuses
// them (KeyVersionUnavailable for a ciphertext; package cipheron's ErrKeyVersionUnavailable). ListVersion puts it back.
func (s *Server) RetireVersion(profile, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profile(profile)
	k.versions = slices.DeleteFunc(k.versions, func(v string) bool { return v == version })
}

// ListVersion lists version again (un-retiring it).
func (s *Server) ListVersion(profile, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profile(profile)
	if !k.listed(version) {
		k.versions = append(k.versions, version)
	}
}

// RequireRequestKey makes every request in profile but PublicKey carry auth by pub's private key.
func (s *Server) RequireRequestKey(profile string, pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requestKeys[profile] = pub
}

// SetMode switches how the fake answers.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// Fail makes every call but PublicKey answer f instead of being served (NoFault: serve again). NoWriter fails the
// writes only.
func (s *Server) Fail(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = f
}

// FailPublicKey makes PublicKey answer f (NoFault: serve again). NoWriter is not a PublicKey answer: it serves.
func (s *Server) FailPublicKey(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keysFault = f
}

// early is the fault answered before a request's auth is looked at (Busy, Unimplemented, Overloaded), and late the
// one answered after it verified (NoWriter for a write, Internal). write is whether the call asks for the writer:
// not a wrapped profile's Encrypt or ReEncrypt, which uses the tenant's own key.
func (s *Server) early() error {
	s.mu.Lock()
	f := s.fault
	s.mu.Unlock()
	switch f {
	case Busy, Unimplemented, Overloaded, ProfileSealed:
		return f.answer()
	}
	return nil
}

func (s *Server) late(write bool) error {
	s.mu.Lock()
	f := s.fault
	s.mu.Unlock()
	switch {
	case f == Internal, f == NoWriter && write:
		return f.answer()
	}
	return nil
}

// Rekey gives profile a new identity and new signing keys, its tenancy kept: PublicKey answers them, requests
// sealed to the old HPKE key no longer open, and answers are signed by the new response key.
func (s *Server) Rekey(profile string) {
	k := newProfileKeys(s.tb, s.formats)
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.profile(profile)
	k.tenancy = old.tenancy
	s.profiles[profile] = k
}

// HoldPublicKey makes PublicKey wait until the returned function is called.
func (s *Server) HoldPublicKey() (release func()) {
	ch := make(chan struct{})
	s.mu.Lock()
	s.gate = ch
	s.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// PublicKeyCalls is how many PublicKey calls the fake answered or held.
func (s *Server) PublicKeyCalls() int64 { return s.publicKeyCalls.Load() }

// Auth is how many requests carried auth that verified, carried none, and were refused for their auth.
func (s *Server) Auth() (verified, absent, refused int64) {
	return s.authVerified.Load(), s.authAbsent.Load(), s.authRefused.Load()
}

// AuthIgnored is how many requests carried an auth to a profile with no request key: not checked against anything,
// and served (as cipheron serves a socket entry without a request key).
func (s *Server) AuthIgnored() int64 { return s.authIgnored.Load() }

// EncryptsPerConnection is how many Encrypt calls each connection carried.
func (s *Server) EncryptsPerConnection() map[int64]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int64]int{}
	for k, v := range s.perConn {
		out[k] = v
	}
	return out
}

func (s *Server) state(profile string) (*profileKeys, Mode, ed25519.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.profiles[profile]
	if k == nil {
		return nil, 0, nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	return k, s.mode, s.requestKeys[profile], nil
}

// Grant restricts what the profile's caller may do to ops (transport.GrantableOperations), as a caller entry's
// operations do in cipheron: a request for an operation not granted is PERMISSION_DENIED, after the profile — and,
// for a profile with a request key (RequireRequestKey), after the request's auth verified — as cipheron's admission.
// Import is a write grant into its profile (transport.OpImport). A profile Grant was never called for grants every
// operation (the fake's default). A cross-profile ReEncrypt needs OpExport on its source profile and OpImport on its
// target profile — OpReEncrypt is within a profile only, as in cipheron (D-A) — and, when it changes the tenant
// (transport.ChangesTenant), OpRetenant on its source profile. Grant with no ops grants nothing. OpRetenant without
// OpExport fails the test, as cipheron refuses such a caller entry at load: retenant only widens a cross-profile
// ReEncrypt out of the profile, which export allows, so alone it grants nothing.
func (s *Server) Grant(profile string, ops ...transport.Operation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := map[transport.Operation]bool{}
	for _, op := range ops {
		if !op.Grantable() {
			s.tb.Fatalf("cipherontest: %q is not a grantable operation", op)
		}
		g[op] = true
	}
	if g[transport.OpRetenant] && !g[transport.OpExport] {
		s.tb.Fatalf("cipherontest: Grant(%q) lists %s but not %s: cipheron refuses such a caller entry at load (%s only "+
			"widens a cross-profile ReEncrypt out of the profile, which %s allows); add %s, or remove %s", profile,
			transport.OpRetenant, transport.OpExport, transport.OpRetenant, transport.OpExport, transport.OpExport,
			transport.OpRetenant)
	}
	s.grants[profile] = g
}

// granted is cipheron's grant check: grant (a grantable operation) is the profile's, else PERMISSION_DENIED.
func (s *Server) granted(profile string, grant transport.Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.grants[profile]; ok && !g[grant] {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// checkAuth checks a request's auth as cipheron does: required when the profile has a request key, the
// timestamp within the skew, the signature over the transcript, the nonce once. A profile with no request key (a
// socket entry without one) checks the nonce's length only: an auth sent anyway is not checked against anything
// and not refused (cipheron's authenticate) — the answer is still signed over that auth's signature, as the
// response transcript says.
//
// THE ORDER OF THE FAKE'S CHECKS, in every handler (admit): the profile (state); for a profile with a request key the
// request's auth (here) BEFORE the grant (granted), as cipheron verifies a keyed entry's signature before its grant, so
// a request that does not verify is refused alike whatever is granted; for a profile without one the grant, then the
// nonce (here); then the request's tenancy and tenant fields (tenantOf, or the "not a wrapped profile" refusal of the
// tenant-key calls). cipheron authenticates before the tenancy checks too.
func (s *Server) checkAuth(profile string, op transport.Operation, nonce []byte, auth *cipheronv1.RequestAuth,
	key ed25519.PublicKey, digest [32]byte) error {
	if key == nil {
		if len(nonce) != transport.NonceLen {
			return status.Error(codes.InvalidArgument, "request_nonce is not 16 bytes")
		}
		if auth == nil {
			s.authAbsent.Add(1)
		} else {
			s.authIgnored.Add(1)
		}
		return nil
	}
	if auth == nil {
		s.authRefused.Add(1)
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	ts := time.UnixMilli(auth.GetTimestampMs())
	if time.Since(ts).Abs() > skew || !transport.EachRequestTranscript(s.formats, profile, op, auth.GetTimestampMs(), nonce, digest,
		func(tr []byte) bool { return transport.VerifyRequest(key, tr, auth.GetSignature()) == nil }) {
		s.authRefused.Add(1)
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if len(nonce) != transport.NonceLen {
		// After the signature, as cipheron: only the key's holder learns that its nonce is malformed.
		return status.Error(codes.InvalidArgument, "request_nonce is not 16 bytes")
	}
	s.mu.Lock()
	start := s.start
	s.mu.Unlock()
	if ts.Before(start) {
		// cipheron's start barrier: signed before this "process" started — refused, retryable, the nonce not recorded.
		return startingAnswer(start.Sub(ts))
	}
	s.mu.Lock()
	seen := s.nonces[profile+"|"+string(nonce)] // per profile: a cross-profile request's two auths share the nonce
	s.nonces[profile+"|"+string(nonce)] = true
	s.mu.Unlock()
	if seen {
		s.authRefused.Add(1)
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	s.authVerified.Add(1)
	return nil
}

// Restart makes the fake act as a cipheron process started at start, as a restarted or newly scaled-out replica
// does: its replay cache is empty, and a request whose signature verifies but whose timestamp is before start is
// refused as cipheron's start barrier refuses it — UNAVAILABLE with the ErrorInfo of transport.ReasonStarting and a
// RetryInfo of how far before start it was signed (rounded up to a millisecond) — with its nonce not recorded. The
// client library signs such a call again and sends it once more by itself. New's fake started at the millisecond it
// was made (a request's timestamp has a millisecond's precision); a start ahead of the clock stands for a caller
// whose clock lags cipheron's.
func (s *Server) Restart(start time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.start = start
	s.nonces = map[string]bool{}
}

// startingAnswer is cipheron's start barrier refusal of a request signed wait before the start.
func startingAnswer(wait time.Duration) error {
	return withDetails(codes.Unavailable, "this cipheron process started after the request was signed: sign it again "+
		"and send it again", &errdetails.ErrorInfo{Reason: transport.ReasonStarting, Domain: transport.ErrorDomain},
		&errdetails.RetryInfo{RetryDelay: durationpb.New((wait + time.Millisecond - 1).Truncate(time.Millisecond))})
}

// admit is a request's admission in cipheron's order (checkAuth's comment): for a profile with a request key (key) its
// auth under the transcript label op, then the grant; for one without, the grant, then the nonce.
func (s *Server) admit(profile string, grant, op transport.Operation, nonce []byte, auth *cipheronv1.RequestAuth,
	key ed25519.PublicKey, digest [32]byte) error {
	if key != nil {
		if err := s.checkAuth(profile, op, nonce, auth, key, digest); err != nil {
			return err
		}
		return s.granted(profile, grant)
	}
	if err := s.granted(profile, grant); err != nil {
		return err
	}
	return s.checkAuth(profile, op, nonce, auth, key, digest)
}

// respSig is the answer's response signature: over the response transcript with the profile's key-context digest as
// the fake holds it now (AnswerOtherContext: a context PublicKey never answers, as a replica on a drifted context
// signs), by the profile's response key (or the mode's other key).
func (s *Server) respSig(k *profileKeys, m Mode, profile string, op transport.Operation, nonce []byte,
	auth *cipheronv1.RequestAuth, reqDigest, respDigest [32]byte) []byte {
	s.mu.Lock()
	digest := k.contextDigest(profile)
	if m == SignRevoked {
		digest = k.unrevokedContextDigest(profile) // a replica that has not learnt the revocation: its context is older
	}
	s.mu.Unlock()
	if m == AnswerOtherContext {
		sum := sha256.Sum256([]byte("drifted|" + digest))
		digest = transport.FingerprintPrefix + hex.EncodeToString(sum[:])
	}
	tr := transport.ResponseTranscript(s.formats, profile, digest, op, nonce, auth.GetSignature(), reqDigest, respDigest)
	switch m {
	case NoResponseSignature:
		return nil
	case ForeignResponseSignature:
		return ed25519.Sign(s.foreign, tr)
	}
	return ed25519.Sign(k.response, tr)
}

func tenancyEnum(t transport.Tenancy) cipheronv1.Tenancy {
	switch t {
	case transport.TenancyShared:
		return cipheronv1.Tenancy_TENANCY_SHARED
	case transport.TenancyPerTenantWrapped:
		return cipheronv1.Tenancy_TENANCY_PER_TENANT_WRAPPED
	case transport.TenancyPerTenantDerived:
		return cipheronv1.Tenancy_TENANCY_PER_TENANT_DERIVED
	}
	return cipheronv1.Tenancy_TENANCY_UNSPECIFIED
}

// stateEnum is a signing key's state as the API's enum carries it: its number, or the number wire gives it
// (MarkSigningKeyUnknown).
func stateEnum(k transport.SigningKey, wire map[string]uint32) cipheronv1.SigningKeyState {
	if code, ok := wire[string(k.KeyID)]; ok {
		return cipheronv1.SigningKeyState(code)
	}
	return cipheronv1.SigningKeyState(k.State.Code())
}

// otherIdentity is KeysOfAnotherIdentity's: another identity of profile's tenancy, made once.
func (s *Server) otherIdentity(profile string, k *profileKeys) *profileKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.other[profile]
	if o == nil {
		o = newProfileKeys(s.tb, s.formats)
		o.tenancy = k.tenancy
		s.other[profile] = o
	}
	return o
}

// PublicKey answers the profile's identity, signing keys and context digest, the latter two signed.
func (s *Server) PublicKey(ctx context.Context, r *cipheronv1.PublicKeyRequest) (*cipheronv1.PublicKeyResponse, error) {
	s.publicKeyCalls.Add(1)
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	profile, nonce := r.GetProfile(), r.GetRequestNonce()
	s.mu.Lock()
	kf := s.keysFault
	s.mu.Unlock()
	if kf != NoWriter {
		if err := kf.answer(); err != nil {
			return nil, err
		}
	}
	k, m, _, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	// As cipheron: after the profile, a nonce of any other length than transport.NonceLen — none included — is refused
	// (an answer over no nonce could be replayed for the identity's life).
	if len(nonce) != transport.NonceLen {
		return nil, status.Error(codes.InvalidArgument, "request_nonce must be 16 random bytes, new for every request")
	}
	s.mu.Lock()
	answered := nonce
	if m == ReplayedKeys {
		answered = bytes.Clone(nonce)
		answered[0] ^= 0xff // the answer to another request
	}
	a := k.answer(profile, answered)
	wire := k.wireStates()
	s.mu.Unlock()
	switch m {
	case ForgedKeysSignature:
		a.KeysSignature = ed25519.Sign(s.foreign, keysTranscript(s.formats, profile, a.Tenancy, a.ContextDigest, nonce, a.SigningKeys))
	case KeysForOtherProfile:
		a.KeysSignature = ed25519.Sign(k.response, keysTranscript(s.formats, profile+"x", a.Tenancy, a.ContextDigest, nonce, a.SigningKeys))
	case KeysForOtherContext:
		sum := sha256.Sum256([]byte(a.ContextDigest))
		a.ContextDigest = transport.FingerprintPrefix + hex.EncodeToString(sum[:])
	case KeysOfAnotherIdentity:
		o := s.otherIdentity(profile, k)
		s.mu.Lock()
		list, digest := o.list(), o.contextDigest(profile)
		s.mu.Unlock()
		a.SigningKeys, a.ContextDigest = list, digest
		a.KeysSignature = ed25519.Sign(o.response, keysTranscript(s.formats, profile, a.Tenancy, digest, nonce, list))
	case UnsignedExtraKey:
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		a.SigningKeys = append(a.SigningKeys, transport.SigningKey{KeyID: transport.SigningKeyID(pub),
			State: transport.SigningKeyVerifyOnly, PublicKey: pub})
	case ForgetVerifyOnlyKeys:
		var kept []transport.SigningKey
		for _, sk := range a.SigningKeys {
			if sk.State != transport.SigningKeyVerifyOnly { // the active key and the revoked ones stay
				kept = append(kept, sk)
			}
		}
		a.SigningKeys = kept
		a.KeysSignature = ed25519.Sign(k.response, keysTranscript(s.formats, profile, a.Tenancy, a.ContextDigest, nonce, kept))
	case UnknownSigningAlgorithm:
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		a.SigningKeys = append(a.SigningKeys, transport.SigningKey{KeyID: transport.SigningKeyIDOf(unknownAlgorithm, pub),
			State: transport.SigningKeyVerifyOnly, PublicKey: pub, Algorithm: unknownAlgorithm})
		transport.SortSigningKeys(a.SigningKeys)
		a.KeysSignature = ed25519.Sign(k.response, keysTranscript(s.formats, profile, a.Tenancy, a.ContextDigest, nonce, a.SigningKeys))
	case UnknownSigningKeyState:
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		extra := transport.SigningKeyID(pub)
		a.SigningKeys = append(a.SigningKeys, transport.SigningKey{KeyID: extra, State: transport.SigningKeyVerifyOnly, PublicKey: pub})
		transport.SortSigningKeys(a.SigningKeys)
		wire[string(extra)] = UnknownStateNumber
		received := make([]transport.ReceivedSigningKey, len(a.SigningKeys))
		for i, sk := range a.SigningKeys {
			received[i] = transport.ReceivedSigningKey{KeyID: sk.KeyID, State: uint32(stateEnum(sk, wire)), PublicKey: sk.PublicKey}
		}
		a.KeysSignature = ed25519.Sign(k.response, transport.ReceivedSigningKeysTranscript(s.formats, profile, a.Tenancy, a.ContextDigest,
			nonce, received))
	case AdditionalIdentityKey:
		a.Additional = []transport.IdentityKey{{Role: transport.RoleHPKE, Suite: unknownSuite, PublicKey: make([]byte, 1184)}}
	case UnknownHPKESuite:
		a.HPKESuite = unknownSuite
	}
	resp := &cipheronv1.PublicKeyResponse{HpkePublicKey: a.HPKE,
		ResponsePublicKey: a.Response, Tenancy: tenancyEnum(a.Tenancy), KeysSignature: a.KeysSignature,
		ContextDigest: a.ContextDigest, ResponseKeyAlgorithm: cipheronv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519}
	if m != NoHPKESuite {
		su := a.Suite()
		resp.HpkeSuite = &cipheronv1.HpkeSuite{KemId: uint32(su.KEM), KdfId: uint32(su.KDF), AeadId: uint32(su.AEAD)}
	}
	for _, e := range a.Additional {
		resp.AdditionalIdentityKeys = append(resp.AdditionalIdentityKeys, &cipheronv1.IdentityKey{
			Role: cipheronv1.IdentityKeyRole(e.Role), PublicKey: e.PublicKey,
			HpkeSuite: &cipheronv1.HpkeSuite{KemId: uint32(e.Suite.KEM), KdfId: uint32(e.Suite.KDF), AeadId: uint32(e.Suite.AEAD)}})
	}
	if m == UnknownTenancy {
		resp.Tenancy = cipheronv1.Tenancy(UnknownTenancyNumber)
	}
	for _, sk := range a.SigningKeys {
		resp.SigningKeys = append(resp.SigningKeys, &cipheronv1.SigningKey{KeyId: sk.KeyID, State: stateEnum(sk, wire),
			PublicKey: sk.PublicKey, Algorithm: cipheronv1.SignatureAlgorithm(sk.Alg())})
	}
	// The key statement: the answer's identity, digest and list, nonce-free, signed by the response key.
	st := transport.KeyStatement{Profile: profile, IssuedAtMS: time.Now().UnixMilli(), ContextDigest: a.ContextDigest,
		Identity: a.Identity, SigningKeys: a.SigningKeys}
	if m == MismatchedKeyStatement && len(st.SigningKeys) > 0 {
		st.SigningKeys = slices.Clone(st.SigningKeys)
		st.SigningKeys[0].State = transport.SigningKeyRevoked
	}
	raw, err := transport.MarshalKeyStatement(s.formats, &st)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	signer := k.response
	if m == ForgedKeyStatement {
		signer = s.foreign
	}
	resp.KeyStatement, resp.KeyStatementSignature = raw, ed25519.Sign(signer, raw)
	return resp, nil
}

// errNotWrapped is CreateTenantKey's and RewrapTenantKey's answer in a profile that is not perTenant wrapped, as
// cipheron answers it: INVALID_ARGUMENT (its errNotWrapped), not FAILED_PRECONDITION.
var errNotWrapped = status.Error(codes.InvalidArgument,
	"the profile is not perTenant wrapped: it has no tenant key blobs to create or rewrap")

// unavailable is cipheron's refusal of data under a key version it does not list:
// INVALID_ARGUMENT with the ErrorInfo of transport.ReasonKeyVersionUnavailable (what the client decides on), and msg —
// KeyVersionUnavailable for a ciphertext, tenantKeyVersionUnavailable for a blob — for humans.
func unavailable(msg string) error {
	st, err := status.New(codes.InvalidArgument, msg).
		WithDetails(&errdetails.ErrorInfo{Reason: transport.ReasonKeyVersionUnavailable, Domain: transport.ErrorDomain})
	if err != nil {
		panic(err) // a constant detail of a registered type: cannot fail
	}
	return st.Err()
}

// tenantOf checks a request's tenant fields against the profile's tenancy and returns the wrapped tenant's keys
// (nil in a shared or derived profile).
func (s *Server) tenantOf(k *profileKeys, profile, tenant string, blob []byte) (*tenantKeys, error) {
	switch k.tenancy {
	case transport.TenancyShared:
		if tenant != "" || len(blob) > 0 {
			return nil, status.Error(codes.InvalidArgument, "the profile is shared")
		}
		return nil, nil //nolint:nilnil // tenantOf's contract: a shared profile has no tenant keys
	case transport.TenancyPerTenantDerived:
		if !transport.ValidTenant(tenant) || len(blob) > 0 {
			return nil, status.Error(codes.InvalidArgument, "a derived profile's request names a tenant and no tenant key")
		}
		return nil, nil //nolint:nilnil // tenantOf's contract: a derived profile has no tenant keys
	}
	h, err := transport.CheckTenantKey(s.formats, blob, profile, tenant)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "tenant_key is not a key of this tenant in this profile")
	}
	s.mu.Lock()
	tk := s.tenantKeys[string(h.KeyID)]
	made := s.blobs[string(blob)]
	available := k.available(h.WrappingVersion)
	s.mu.Unlock()
	// A blob the fake did not make — another key's, or one of its own with its header (or sealed part) altered: the key
	// id kept, another signing public key, tenant, creation time or salt — does not open in cipheron, which answers the
	// same refusal.
	if tk == nil || tk.tenant != tenant || tk.profile != profile || !made {
		return nil, status.Error(codes.InvalidArgument, "tenant_key is not a key of this tenant in this profile")
	}
	if !available {
		return nil, unavailable(tenantKeyVersionUnavailable)
	}
	return tk, nil
}

// CreateTenantKey makes a tenant key the fake keeps, and answers a blob of its id.
func (s *Server) CreateTenantKey(_ context.Context, r *cipheronv1.CreateTenantKeyRequest) (*cipheronv1.CreateTenantKeyResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	profile, tenant := r.GetProfile(), r.GetTenant()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	reqDigest := transport.ProvisionDigest(tenant)
	if err := s.admit(profile, transport.OpProvision, transport.OpProvision, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if !k.tenancy.Wrapped() {
		return nil, errNotWrapped
	}
	if err := s.late(true); err != nil {
		return nil, err
	}
	blob, pub := s.newTenantKey(profile, tenant)
	if m == OtherTenantBlob {
		blob, pub = s.newTenantKey(profile, tenant+"x")
	}
	h, _ := transport.ParseTenantKey(s.formats, blob)
	fp := h.Fingerprint()
	switch m {
	case UnknownVersionBlob:
		blob[len(transport.TenantKeyMagic)] = UnknownBlobVersion
	case AnsweredOtherSigningKey:
		pub, _, _ = ed25519.GenerateKey(rand.Reader)
	}
	return &cipheronv1.CreateTenantKeyResponse{TenantKey: blob, SigningPublicKey: pub, Fingerprint: fp,
		ResponseSignature: s.respSig(k, m, profile, transport.OpProvision, r.GetRequestNonce(), r.GetAuth(), reqDigest,
			transport.TenantKeyResponseDigest(blob, pub, fp))}, nil
}

// NewTenantKey is a tenant key the fake made for tenant in profile, as CreateTenantKey would answer it.
func (s *Server) NewTenantKey(profile, tenant string) []byte {
	blob, _ := s.newTenantKey(profile, tenant)
	return blob
}

func (s *Server) makeTenantKeys(profile, tenant string, created time.Time) *tenantKeys {
	keyID := make([]byte, transport.TenantKeyIDLen)
	_, _ = rand.Read(keyID)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	storage := make([]byte, 32)
	_, _ = rand.Read(storage)
	tk := &tenantKeys{profile: profile, tenant: tenant, keyID: keyID, signing: priv, storage: storage, created: created}
	s.mu.Lock()
	s.tenantKeys[string(keyID)] = tk
	s.mu.Unlock()
	return tk
}

// blobOf is a blob of tk, with a fresh salt, under the profile's current wrapping version: tk's storage and signing
// keys wrapped as cipheron wraps them (transport.SealTenantKey), under the fake's key of that version. The fake keeps
// its tenant keys (tenantOf finds them by the blob's key id) and opens no blob; pub is the header's signing public
// key, which a mode may make another than tk's.
func (s *Server) blobOf(k *profileKeys, tk *tenantKeys, pub ed25519.PublicKey, created time.Time) []byte {
	s.mu.Lock()
	wrapping := k.writeVersion
	wrapKey := k.dataKey(wrapping)
	s.mu.Unlock()
	blob, err := transport.SealTenantKey(s.formats, wrapKey, &transport.TenantKeyHeader{KeyID: tk.keyID, Profile: tk.profile,
		Tenant: tk.tenant, SigningPublicKey: pub, WrappingVersion: wrapping, Created: created},
		append(bytes.Clone(tk.storage), tk.signing...))
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.blobs[string(blob)] = true
	s.mu.Unlock()
	return blob
}

func (s *Server) newTenantKey(profile, tenant string) ([]byte, ed25519.PublicKey) {
	tk := s.makeTenantKeys(profile, tenant, time.Now().UTC().Truncate(time.Second))
	s.mu.Lock()
	k := s.profile(profile)
	s.mu.Unlock()
	pub := publicHalf(tk.signing)
	return s.blobOf(k, tk, pub, tk.created), pub
}

// RewrapTenantKey answers the same tenant key in a new blob under the current wrapping version.
func (s *Server) RewrapTenantKey(_ context.Context, r *cipheronv1.RewrapTenantKeyRequest) (*cipheronv1.RewrapTenantKeyResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	profile, tenant, blob := r.GetProfile(), r.GetTenant(), r.GetTenantKey()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	reqDigest := transport.RewrapTenantKeyDigest(tenant, blob)
	if err := s.admit(profile, transport.OpProvision, transport.OpRewrapTenantKey, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if !k.tenancy.Wrapped() {
		return nil, errNotWrapped
	}
	if err := s.late(true); err != nil {
		return nil, err
	}
	nb, pub, fp, err := s.rewrap(k, m, profile, tenant, blob)
	if err != nil {
		return nil, err
	}
	return &cipheronv1.RewrapTenantKeyResponse{TenantKey: nb, SigningPublicKey: pub, Fingerprint: fp,
		ResponseSignature: s.respSig(k, m, profile, transport.OpRewrapTenantKey, r.GetRequestNonce(), r.GetAuth(), reqDigest,
			transport.TenantKeyResponseDigest(nb, pub, fp))}, nil
}

// rewrap is RewrapTenantKey's work for one (tenant, blob), bent by the mode: the new blob, its signing public key
// and its fingerprint.
func (s *Server) rewrap(k *profileKeys, m Mode, profile, tenant string, blob []byte) ([]byte, ed25519.PublicKey, string, error) {
	tk, err := s.tenantOf(k, profile, tenant, blob)
	if err != nil {
		return nil, nil, "", err
	}
	h, _ := transport.ParseTenantKey(s.formats, blob)
	pub, created := ed25519.PublicKey(bytes.Clone(h.SigningPublicKey)), h.Created
	same := *tk
	switch m {
	case RewrapOtherKeyID:
		same.keyID = make([]byte, transport.TenantKeyIDLen)
		_, _ = rand.Read(same.keyID)
	case RewrapOtherSigningKey:
		pub, _, _ = ed25519.GenerateKey(rand.Reader)
	case RewrapOtherCreated:
		created = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	}
	nb := s.blobOf(k, &same, pub, created)
	nh, _ := transport.ParseTenantKey(s.formats, nb)
	fp := nh.Fingerprint()
	switch m {
	case RewrapOtherFingerprint:
		fp = transport.TenantFingerprint(profile, tenant, nh.KeyID, publicHalf(s.foreign))
	case UnknownVersionBlob:
		nb[len(transport.TenantKeyMagic)] = UnknownBlobVersion
	case AnsweredOtherSigningKey:
		pub, _, _ = ed25519.GenerateKey(rand.Reader)
	}
	return nb, pub, fp, nil
}

// encryptVersioned is a ciphertext of tenant ("" in a shared profile) under the profile's current version, as cipheron
// makes one (transport.NewCiphertextSealer: the format the ciphertext family writes for a master version — 4, or 5
// with associated data aad), under the fake's data key of that version.
func (s *Server) encryptVersioned(k *profileKeys, profile, tenant string, pt, aad []byte) []byte {
	s.mu.Lock()
	version := k.writeVersion
	key := k.dataKey(version)
	s.mu.Unlock()
	sealer, err := transport.NewCiphertextSealer(s.formats, transport.NamesMasterVersion, key, transport.KeyID{MasterVersion: version},
		profile, tenant, aad)
	if err != nil {
		panic(err)
	}
	return sealer.Seal(pt)
}

// encryptTenant is a ciphertext under tk's storage key carrying keyID, as cipheron makes one: the format the
// ciphertext family writes for a tenant key — 3, or 6 with associated data.
func encryptTenant(p *format.Policy, tk *tenantKeys, keyID []byte, profile string, pt, aad []byte) []byte {
	sealer, err := transport.NewCiphertextSealer(p, transport.NamesTenantKey, tk.storage, transport.KeyID{TenantKeyID: keyID},
		profile, tk.tenant, aad)
	if err != nil {
		panic(err)
	}
	return sealer.Seal(pt)
}

// errFakeOpen is the fake's refusal of a ciphertext that does not decrypt.
var errFakeOpen = status.Error(codes.InvalidArgument, "the ciphertext could not be decrypted")

// errAssociatedData is cipheron's refusal of associated data that does not match the ciphertext's format, or of
// associated data over transport.MaxAssociatedDataLen — cipheron's message (transport.AssociatedDataMessage).
func errAssociatedData() error { return associatedDataStatus(transport.AssociatedDataMessage) }

// errTargetAssociatedData is cipheron's refusal of a re-encryption with associated data for the stored ciphertext and
// none for the new one (transport.CheckReEncryptAssociatedData): cipheron's code, reason and message
// (transport.TargetAssociatedDataMessage).
func errTargetAssociatedData() error {
	return associatedDataStatus(transport.TargetAssociatedDataMessage)
}

// associatedDataStatus is INVALID_ARGUMENT with msg and the ErrorInfo of transport.ReasonAssociatedData.
func associatedDataStatus(msg string) error {
	st, err := status.New(codes.InvalidArgument, msg).
		WithDetails(&errdetails.ErrorInfo{Reason: transport.ReasonAssociatedData, Domain: transport.ErrorDomain})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

// reencryptAAD is cipheron's shape check of a re-encryption's associated data — a ReEncrypt, or a ReEncryptBatch
// item — before anything is opened: each side at most transport.MaxAssociatedDataLen (errAssociatedData), and the
// stored ciphertext's associated data only with the new one's (errTargetAssociatedData). Other associated data for the
// new ciphertext is no shape refusal: the grants decide it (rebinds, grantedRebind).
func reencryptAAD(aad, toAAD []byte) error {
	if len(aad) > transport.MaxAssociatedDataLen || len(toAAD) > transport.MaxAssociatedDataLen {
		return errAssociatedData()
	}
	if errors.Is(transport.CheckReEncryptAssociatedData(aad, toAAD), transport.ErrTargetAssociatedData) {
		return errTargetAssociatedData()
	}
	return nil
}

// rebinds reports whether a re-encryption asks for its new ciphertext bound to other associated data than the stored
// one's (transport.ErrAssociatedDataChanged).
func rebinds(aad, toAAD []byte) bool {
	return errors.Is(transport.CheckReEncryptAssociatedData(aad, toAAD), transport.ErrAssociatedDataChanged)
}

// grantedRebind is cipheron's grant check of a re-binding: decrypt on the stored ciphertext's profile and encrypt on
// the profile the new ciphertext is made in (the same profile within one), else PERMISSION_DENIED — reencrypt, export
// and import alone never re-bind.
func (s *Server) grantedRebind(profile, toProfile string) error {
	if err := s.granted(profile, transport.OpDecrypt); err != nil {
		return err
	}
	return s.granted(toProfile, transport.OpEncrypt)
}

// sealAAD is cipheron's check of the associated data a new ciphertext is made with, before it is made: over
// transport.MaxAssociatedDataLen it is errAssociatedData.
func (s *Server) sealAAD(aad []byte) error {
	if len(aad) > transport.MaxAssociatedDataLen {
		return errAssociatedData()
	}
	return nil
}

// seal is what Encrypt and ReEncrypt answer for pt: format 4 in a shared or derived profile, format 3 under to in a
// wrapped one, bent by the mode.
func (s *Server) seal(k *profileKeys, m Mode, profile, tenant string, to *tenantKeys, pt, aad []byte) []byte {
	if m == AssociatedDataDropped {
		aad = nil
	}
	var ct []byte
	switch {
	case to != nil && m == WrongFormatCiphertext:
		ct = s.encryptVersioned(k, profile, tenant, pt, aad)
	case to != nil:
		keyID := to.keyID
		if m == OtherKeyIDCiphertext {
			keyID = make([]byte, transport.TenantKeyIDLen)
		}
		ct = encryptTenant(s.formats, to, keyID, profile, pt, aad)
	case m == WrongFormatCiphertext:
		fake := &tenantKeys{tenant: tenant, storage: make([]byte, 32), keyID: make([]byte, transport.TenantKeyIDLen)}
		ct = encryptTenant(s.formats, fake, fake.keyID, profile, pt, aad)
	default:
		ct = s.encryptVersioned(k, profile, tenant, pt, aad)
	}
	switch m {
	case JunkCiphertext:
		_, _ = rand.Read(ct)
	case LongCiphertext:
		ct = append(ct, 0)
	case UnknownFormatCiphertext:
		ct[len(transport.CiphertextMagic)] = UnknownFormat
	}
	return ct
}

// open decrypts a ciphertext of any format the profile reads: 3 (wrapped, tk's) and 4 (shared or derived, a listed
// version), and their associated-data forms 6 and 5.
func (s *Server) open(k *profileKeys, profile, tenant string, tk *tenantKeys, ct, callerAAD []byte) ([]byte, error) {
	if len(callerAAD) > transport.MaxAssociatedDataLen {
		return nil, errAssociatedData()
	}
	kid, err := transport.ParseKeyID(s.formats, ct)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "not a ciphertext")
	}
	if transport.CheckAssociatedData(kid, callerAAD) != nil {
		return nil, errAssociatedData()
	}
	var key []byte
	names := transport.NamesOf(s.formats, kid)
	switch {
	case names == transport.NamesTenantKey && tk != nil:
		if !transport.SameKeyID(kid.TenantKeyID, tk.keyID) {
			return nil, status.Error(codes.InvalidArgument, "the ciphertext belongs to another tenant key")
		}
		key, tenant = tk.storage, tk.tenant
	case names == transport.NamesMasterVersion && k.tenancy.HasSigningKeys():
		s.mu.Lock()
		available := k.available(kid.MasterVersion)
		key = k.dataKey(kid.MasterVersion)
		s.mu.Unlock()
		if !available {
			return nil, unavailable(KeyVersionUnavailable)
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "not a ciphertext of this profile")
	}
	o, err := transport.NewCiphertextOpener(s.formats, key, kid, profile, tenant, ct, callerAAD)
	if err != nil {
		return nil, errFakeOpen
	}
	plaintext, err := o.Open()
	if err != nil {
		return nil, errFakeOpen
	}
	return plaintext, nil
}

// Encrypt opens the sealed plaintext and answers it in cipheron's format (its keys are the fake's own).
func (s *Server) Encrypt(ctx context.Context, r *cipheronv1.EncryptRequest) (*cipheronv1.EncryptResponse, error) {
	if id, ok := ctx.Value(connKey{}).(int64); ok {
		s.mu.Lock()
		s.perConn[id]++
		s.mu.Unlock()
	}
	if err := s.early(); err != nil {
		return nil, err
	}
	profile, tenant := r.GetProfile(), r.GetTenant()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	reqDigest := transport.EncryptDigestAAD(r.GetEnc(), r.GetSealedPlaintext(), tenant, r.GetTenantKey(), r.GetAssociatedData())
	if err := s.admit(profile, transport.OpEncrypt, transport.OpEncrypt, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(!k.tenancy.Wrapped()); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, r.GetTenantKey())
	if err != nil {
		return nil, err
	}
	if len(r.GetAssociatedData()) > transport.MaxAssociatedDataLen {
		return nil, errAssociatedData() // before anything is opened, as cipheron
	}
	// Bound to the requester as cipheron binds it (transport.RequestSealInfo): the profile's required request key, or
	// none when the profile requires none.
	pt, err := transport.OpenRequestPayload(s.formats, k.hpke, profile, transport.OpEncrypt, tenant, key, r.GetEnc(),
		r.GetSealedPlaintext())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the sealed plaintext could not be opened")
	}
	if err := s.sealAAD(r.GetAssociatedData()); err != nil {
		return nil, err
	}
	ct := s.seal(k, m, profile, tenant, tk, pt, r.GetAssociatedData())
	return &cipheronv1.EncryptResponse{Ciphertext: ct, ResponseSignature: s.respSig(k, m, profile, transport.OpEncrypt,
		r.GetRequestNonce(), r.GetAuth(), reqDigest, transport.CiphertextResponseDigest(ct))}, nil
}

// Decrypt opens a ciphertext of the fake's and answers the plaintext sealed to the recipient key.
func (s *Server) Decrypt(_ context.Context, r *cipheronv1.DecryptRequest) (*cipheronv1.DecryptResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	profile, tenant := r.GetProfile(), r.GetTenant()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	reqDigest := transport.DecryptDigestAAD(r.GetRecipientPublicKey(), r.GetCiphertext(), tenant, r.GetTenantKey(),
		r.GetAssociatedData())
	if err := s.admit(profile, transport.OpDecrypt, transport.OpDecrypt, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(false); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, r.GetTenantKey())
	if err != nil {
		return nil, err
	}
	pt, err := s.open(k, profile, tenant, tk, r.GetCiphertext(), r.GetAssociatedData())
	if err != nil {
		return nil, err
	}
	pk, err := transport.ParsePublicKey(r.GetRecipientPublicKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "recipient_public_key")
	}
	enc, sealed, err := transport.Seal(pk, transport.ResponseInfoTenant(s.formats, profile, transport.OpDecrypt, tenant), pt)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if m == GarbledPlaintext {
		sealed[0] ^= 1
	}
	return &cipheronv1.DecryptResponse{Enc: enc, SealedPlaintext: sealed,
		ResponseSignature: s.respSig(k, m, profile, transport.OpDecrypt, r.GetRequestNonce(), r.GetAuth(), reqDigest,
			transport.Digest(r.GetRecipientPublicKey(), enc, sealed))}, nil
}

// ReEncrypt decrypts a stored ciphertext and answers it encrypted again: under the current version, or
// under to_tenant_key in a wrapped profile — or, with to_profile, in another profile of the fake (cross-profile: the
// target's request key checks to_auth, and the answer carries the target's response signature too).
func (s *Server) ReEncrypt(_ context.Context, r *cipheronv1.ReEncryptRequest) (*cipheronv1.ReEncryptResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	profile, tenant := r.GetProfile(), r.GetTenant()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	grant := transport.OpReEncrypt // within the profile; a cross-profile source is granted export (D-A)
	if r.GetToProfile() != "" && r.GetToProfile() != profile {
		grant = transport.OpExport
	}
	ext := transport.ReEncryptExt{AssociatedData: r.GetAssociatedData(), ToAssociatedData: r.GetToAssociatedData(),
		ToProfile: r.GetToProfile(), ToTenant: r.GetToTenant()}
	reqDigest := transport.ReEncryptDigestExt(r.GetCiphertext(), tenant, r.GetTenantKey(), r.GetToTenantKey(), ext)
	if err := s.admit(profile, grant, transport.OpReEncrypt, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	cross := ext.ToProfile != "" && ext.ToProfile != profile
	tk2, toProfile, toTenant := k, profile, tenant
	if cross {
		var toKey ed25519.PublicKey
		if tk2, _, toKey, err = s.state(ext.ToProfile); err != nil {
			return nil, err
		}
		auth := func() error {
			return s.checkAuth(ext.ToProfile, transport.OpReEncrypt, r.GetRequestNonce(), r.GetToAuth(), toKey, reqDigest)
		}
		// cipheron's admitTarget order: a target with a request key is authenticated FIRST — before its import and the
		// source's retenant are judged, and before its tenancy — so without the target's key a request is refused alike
		// whatever is granted; a target without one is authenticated (its nonce) last.
		if toKey != nil {
			if err := auth(); err != nil {
				return nil, err
			}
		}
		if err := s.granted(ext.ToProfile, transport.OpImport); err != nil {
			return nil, err
		}
		toProfile = ext.ToProfile
		if toTenant = ext.ToTenant; toTenant == "" && tk2.tenancy.PerTenant() {
			toTenant = tenant
		}
		// A move to another tenant needs retenant on the SOURCE profile, decided with the grants: after the target's
		// import and before the target's tenancy, as cipheron's admitTarget.
		if transport.ChangesTenant(k.tenancy, tenant, tk2.tenancy, toTenant) {
			if err := s.granted(profile, transport.OpRetenant); err != nil {
				return nil, err
			}
		}
		if err := targetTenancy(tk2.tenancy, toTenant, r.GetToTenantKey()); err != nil {
			return nil, err
		}
		if toKey == nil {
			if err := auth(); err != nil {
				return nil, err
			}
		}
	} else if ext.ToTenant != "" || r.GetToAuth() != nil {
		return nil, status.Error(codes.InvalidArgument, "to_tenant and to_auth are cross-profile fields")
	}
	// The associated data's shape, after admission and before anything is opened, as cipheron decides it; then a
	// re-binding (other associated data for the new ciphertext), decided with the grants: decrypt on the source profile
	// and encrypt on the profile the new ciphertext is made in (cipheron's grantedRebind).
	if err := reencryptAAD(ext.AssociatedData, ext.ToAssociatedData); err != nil {
		return nil, err
	}
	if rebinds(ext.AssociatedData, ext.ToAssociatedData) {
		if err := s.grantedRebind(profile, toProfile); err != nil {
			return nil, err
		}
	}
	// The new ciphertext's profile decides: a wrapped target writes under the tenant's own key, not the writer.
	if err := s.late(!tk2.tenancy.Wrapped()); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, r.GetTenantKey())
	if err != nil {
		return nil, err
	}
	var to *tenantKeys
	if tk2.tenancy.Wrapped() {
		if to, err = s.tenantOf(tk2, toProfile, toTenant, r.GetToTenantKey()); err != nil {
			return nil, err
		}
	} else if len(r.GetToTenantKey()) > 0 {
		return nil, status.Error(codes.InvalidArgument, "to_tenant_key is a wrapped profile's")
	}
	pt, err := s.open(k, profile, tenant, tk, r.GetCiphertext(), ext.AssociatedData)
	if err != nil {
		return nil, err
	}
	if err := s.sealAAD(ext.ToAssociatedData); err != nil {
		return nil, err
	}
	ct := s.seal(tk2, m, toProfile, toTenant, to, pt, ext.ToAssociatedData)
	respDigest := transport.CiphertextResponseDigest(ct)
	resp := &cipheronv1.ReEncryptResponse{Ciphertext: ct, ResponseSignature: s.respSig(k, m, profile, transport.OpReEncrypt,
		r.GetRequestNonce(), r.GetAuth(), reqDigest, respDigest)}
	if cross && m != NoSecondSignature {
		resp.ToResponseSignature = s.respSig(tk2, m, toProfile, transport.OpReEncrypt, r.GetRequestNonce(), r.GetAuth(),
			reqDigest, respDigest)
	}
	return resp, nil
}

// Sign opens the sealed data and signs it: a shared profile's active key over the data, a derived profile's over
// transport.TenantSignedMessage, a wrapped tenant's key over the data.
func (s *Server) Sign(_ context.Context, r *cipheronv1.SignRequest) (*cipheronv1.SignResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	profile, tenant := r.GetProfile(), r.GetTenant()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	reqDigest := transport.SignDigest(r.GetEnc(), r.GetSealedData(), tenant, r.GetTenantKey())
	if err := s.admit(profile, transport.OpSign, transport.OpSign, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(false); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, r.GetTenantKey())
	if err != nil {
		return nil, err
	}
	data, err := transport.OpenRequestPayload(s.formats, k.hpke, profile, transport.OpSign, tenant, key, r.GetEnc(), r.GetSealedData())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "the sealed data could not be opened")
	}
	s.mu.Lock()
	var signing ed25519.PrivateKey
	var keyID, otherID []byte
	msg := data
	switch {
	case tk != nil:
		signing, keyID = tk.signing, tk.keyID
	default:
		a := k.active()
		if m == SignRevoked {
			for _, o := range k.signing {
				if o.state == transport.SigningKeyRevoked {
					a = o
					break
				}
			}
		}
		signing, keyID = a.priv, transport.SigningKeyID(a.public())
		for _, o := range k.signing {
			if o != a {
				otherID = transport.SigningKeyID(o.public())
			}
		}
		if k.tenancy == transport.TenancyPerTenantDerived {
			msg = transport.TenantSignedMessage(profile, tenant, data)
		}
	}
	s.mu.Unlock()
	sig := ed25519.Sign(signing, msg)
	switch m {
	case ShortSignature:
		sig = sig[:len(sig)-1]
	case ForeignSignature:
		sig = ed25519.Sign(s.foreign, msg)
	case UnknownKeyID:
		keyID = make([]byte, transport.SigningKeyIDLen)
		_, _ = rand.Read(keyID)
	case OtherListedKeyID:
		if otherID != nil {
			keyID = otherID
		}
	}
	return &cipheronv1.SignResponse{Signature: sig, KeyId: keyID, ResponseSignature: s.respSig(k, m, profile, transport.OpSign,
		r.GetRequestNonce(), r.GetAuth(), reqDigest, transport.SignResponseDigest(sig, keyID))}, nil
}

type connKey struct{}

// connTagger numbers the fake's connections (EncryptsPerConnection).
type connTagger struct{ s *Server }

func (t connTagger) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }
func (t connTagger) HandleRPC(context.Context, stats.RPCStats)                       {}
func (t connTagger) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return context.WithValue(ctx, connKey{}, t.s.connSeq.Add(1))
}
func (t connTagger) HandleConn(context.Context, stats.ConnStats) {}

func (s *Server) grpcServer(extra ...grpc.ServerOption) *grpc.Server {
	// strictFields: a request with a field the API does not have is refused, as cipheron's gRPC server refuses it.
	opts := append([]grpc.ServerOption{grpc.MaxRecvMsgSize(MaxMessageBytes), grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.StatsHandler(connTagger{s}), grpc.ChainUnaryInterceptor(strictFields())}, extra...)
	g := grpc.NewServer(opts...)
	cipheronv1.RegisterCipherServiceServer(g, s)
	return g
}

// SocketDir is a new directory for a socket, short enough for a socket path on every platform, removed when
// the test ends.
func SocketDir(tb testing.TB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("", "cph")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	return dir
}

// ServeSocket serves gRPC on a new unix socket and returns its path; the server stops when the test ends.
func (s *Server) ServeSocket(tb testing.TB) string {
	tb.Helper()
	return s.serveSocket(tb)
}

// ServeSocketMax is ServeSocket with a server that accepts requests of at most maxRequestBytes, as cipheron's
// listener does with its maxRequestBytes: a larger one is refused by gRPC itself (RESOURCE_EXHAUSTED, no details).
func (s *Server) ServeSocketMax(tb testing.TB, maxRequestBytes int) string {
	tb.Helper()
	return s.serveSocket(tb, grpc.MaxRecvMsgSize(maxRequestBytes))
}

func (s *Server) serveSocket(tb testing.TB, extra ...grpc.ServerOption) string {
	tb.Helper()
	path := filepath.Join(SocketDir(tb), "c.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		tb.Fatal(err)
	}
	g := s.grpcServer(extra...)
	go func() { _ = g.Serve(l) }()
	tb.Cleanup(g.Stop)
	s.mu.Lock()
	s.socketPath = path
	s.mu.Unlock()
	return path
}

// SocketPath is the socket ServeSocket last returned.
func (s *Server) SocketPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.socketPath
}

// ServeHTTPSocket serves the JSON API (the gRPC gateway over the fake) on a new unix socket and returns its
// path.
func (s *Server) ServeHTTPSocket(tb testing.TB) string {
	tb.Helper()
	path := filepath.Join(SocketDir(tb), "h.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		tb.Fatal(err)
	}
	hs := &http.Server{Handler: s.HTTPHandler(tb), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.Serve(l) }()
	tb.Cleanup(func() { _ = hs.Close() })
	return path
}

// ServeTLS serves gRPC with mutual TLS on a loopback port: the server presents leaf and requires a client
// certificate issued by clientCA. It returns the address.
func (s *Server) ServeTLS(tb testing.TB, leaf *Leaf, clientCA *CA) string {
	tb.Helper()
	return s.ServeTLSConfig(tb, leaf, clientCA, nil)
}

// ServeTLSConfig is ServeTLS with its TLS configuration passed to configure (nil: none) before it is used: a
// test sets a VerifyConnection that refuses clients, or the versions.
func (s *Server) ServeTLSConfig(tb testing.TB, leaf *Leaf, clientCA *CA, configure func(*tls.Config)) string {
	tb.Helper()
	pair, err := tls.X509KeyPair(leaf.ChainPEM, leaf.KeyPEM)
	if err != nil {
		tb.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA.Pool,
		MinVersion:   tls.VersionTLS12,
	}
	if configure != nil {
		configure(cfg)
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	g := s.grpcServer(grpc.Creds(credentials.NewTLS(cfg)))
	go func() { _ = g.Serve(l) }()
	tb.Cleanup(g.Stop)
	return l.Addr().String()
}

// ClientTLS is a client TLS configuration presenting a certificate for id issued by ca, verifying the server
// against roots.
func ClientTLS(tb testing.TB, ca *CA, id string, roots *x509.CertPool) *tls.Config {
	tb.Helper()
	leaf := ca.Client(tb, id)
	pair, err := tls.X509KeyPair(leaf.ChainPEM, leaf.KeyPEM)
	if err != nil {
		tb.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// RequestKey is a new request key pair, and the private key written as `cipheron keygen caller` writes it, to
// dir/name with mode 0600.
func RequestKey(tb testing.TB, dir, name string) (ed25519.PrivateKey, string) {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	privPEM, _, err := transport.MarshalRequestKeys(priv)
	if err != nil {
		tb.Fatal(err)
	}
	return priv, Write(tb, dir, name, privPEM, 0o600)
}
