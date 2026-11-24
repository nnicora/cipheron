package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/nnicora/cipheron/internal/secpath"
	"github.com/nnicora/cipheron/internal/zeroize"
	"github.com/nnicora/cipheron/peercred"
	"github.com/nnicora/cipheron/wire/transport"
)

const (
	// DefaultMaxMessageBytes is the largest message a client sends or receives unless WithMaxMessageBytes says
	// otherwise: cipheron's largest accepted maxRequestBytes (64 MiB) plus room for what a message adds to its
	// payload.
	DefaultMaxMessageBytes = 64<<20 + 64<<10
	// minMaxMessageBytes is the smallest WithMaxMessageBytes accepted.
	minMaxMessageBytes = 4 << 10
	// wireOverhead bounds what a request or an answer adds to its payload: the profile's name aside, the HPKE
	// enc (65), the AEAD tag (16), the nonce (16), RequestAuth (8 + 64), a response signature (64), a recipient
	// key (65) and the protobuf framing of each field — about 350 bytes, rounded up.
	wireOverhead = 1 << 10

	// DefaultConnections is how many connections a gRPC client keeps unless WithConnections says otherwise. Each
	// carries any number of calls at once.
	DefaultConnections = 2
	// DefaultHTTPConnections is how many connections an HTTP client (DialHTTP) opens at most unless WithConnections
	// says otherwise: an HTTP/1.1 connection carries one call at a time, so this is how many of its calls run at
	// once — a batch's pipelined segments (EncryptStream, EncryptObject) among them. Under cipheron's default cap of
	// connections per caller (32, maxConnectionsPerCaller), which every Client and process of one identity shares.
	DefaultHTTPConnections = 8
	// MaxConnections is the most WithConnections accepts.
	MaxConnections = 16

	// maxRequestKeyFileBytes bounds a request private key file.
	maxRequestKeyFileBytes = 16 << 10

	// DefaultKeysMaxAge is how old a profile's signing-key list may be when Verify uses it, unless WithKeysMaxAge
	// says otherwise; MinKeysMaxAge and MaxKeysMaxAge bound WithKeysMaxAge.
	DefaultKeysMaxAge = 5 * time.Minute
	MinKeysMaxAge     = 5 * time.Second
	MaxKeysMaxAge     = 24 * time.Hour
)

// Option configures a client. A nil Option is skipped. An option that answers one question — WithServerUID,
// WithServerSPIFFEID, WithTLSFiles, WithRequestKeyFile, WithRequestKey, a profile's or a tenant's fingerprint — may be
// given again with the SAME value; given again with another, the client is refused (DialGRPC, DialHTTP): which of
// two answers was meant is not guessed, and the last one does not silently win.
type Option func(*options)

type options struct {
	serverUID      *uint32
	anyServer      bool
	env            bool // WithEnvironment (env.go)
	tls            *tls.Config
	tlsFiles       *[3]string
	serverSPIFFEID string
	requestKey     ed25519.PrivateKey
	requestKeyFile string
	pins           map[string]string
	contextPins    map[string][]string // WithContextDigestPin: profile → the accepted key-context digests
	writerPins     map[string][]string // WithWriterVersionPin: profile → the master versions new data may be made under
	requirePins    bool                // WithRequiredPins
	tenantPins     map[tenantRef]string
	maxMessage     int
	connections    int
	roundRobin     bool                       // WithRoundRobin
	keysMaxAge     time.Duration              // WithKeysMaxAge; 0: unset
	observer       func(profile, kind string) // WithObserver; nil: none
	retry          *RetryPolicy               // WithRetry; nil: no retry (retry.go)
	pinsDirOption  string                     // WithPinsDir; "": none
	// The pins directory of WithEnvironment (EnvPinsDir) as first read, and the pins the options gave before it was
	// read: what the live re-read of the directory starts from (livepins.go). pinsDir "": no directory.
	pinsDir       string
	dirPins       dirPins
	inlinePins    map[string]string
	inlineContext map[string][]string
	errs          []error
}

// tenantRef names one tenant of one profile.
type tenantRef struct{ profile, tenant string }

// WithServerUID makes the client check, on every connection it opens to a unix socket, that the process
// listening on the socket runs as uid — the kernel's word (SO_PEERCRED on Linux, LOCAL_PEERCRED on Darwin),
// read before anything is sent — and refuse the connection otherwise, so no sealed payload and no request
// reaches a process that took cipheron's socket path. A refused connection fails the call with
// ErrServerIdentity, at once, rather than leaving it waiting for its deadline.
//
// A socket address needs it, or WithAnyServer. cipheron's image runs as uid 10443, a uid reserved for it: an
// impostor needs that uid, or root, to pass. On other platforms than Linux and Darwin a client with it cannot
// connect at all. It is refused with a network address, where there is no kernel to ask.
//
// A uid that names no one in particular is refused (peercred.RefusedID, the list cipheron's server refuses in its
// caller entries): 0 — every root process would pass —, 65534 and the kernel's overflow uid — every process whose
// uid is unmapped in this user namespace is seen with it —, and 4294967294/4294967295.
func WithServerUID(uid uint32) Option {
	return func(o *options) {
		if why := peercred.RefusedID(uid, true); why != "" {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithServerUID(%d) is refused: %s; pin the uid cipheron runs as "+
				"(10443 in cipheron's image)", uid, why))
			return
		}
		if o.serverUID != nil && *o.serverUID != uid {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithServerUID(%d) and WithServerUID(%d) are two answers to one "+
				"question; pass one", *o.serverUID, uid))
			return
		}
		o.serverUID = &uid
	}
}

// WithAnyServer is the explicit opt-out of WithServerUID, FOR TESTS AND DEVELOPMENT: the client does not
// authenticate the server at all — it talks to whatever process answers on the socket path, and sends it its
// requests. Nothing in this library then tells cipheron from a process that took its socket path: cipheron's own
// checks of the socket's directory chain (it refuses to listen where anyone else could replace the socket) are the
// SERVER's, and do not run when it is not the server that listens; and without a pin (WithProfileFingerprint) the
// profile's keys are whatever that process answers first (trust on first use), so it reads every plaintext sent to
// Encrypt and all data sent to Sign, and its answers are accepted. With a pin an impostor can answer nothing and
// open nothing, but it still receives the requests (sealed), and can make every call fail.
//
// In production give WithServerUID the uid cipheron runs as (10443 in its image), pin every profile, and add
// WithRequiredPins so that a missing pin is an error. WithAnyServer is neither refused nor warned about when
// there is no pin: tests, and a developer's own machine where cipheron runs as the developer, use it so. Socket only.
func WithAnyServer() Option {
	return func(o *options) { o.anyServer = true }
}

// WithTLS is the TLS configuration of a client of cipheron's network listener: it must present a client
// certificate (Certificates, with a parsable leaf and a private key, or GetClientCertificate) whose one SPIFFE
// ID a profile lists, and it must verify the server with roots of its own — RootCAs, for the hostname
// verification or WithServerSPIFFEID — or with its own VerifyConnection or VerifyPeerCertificate. A
// configuration that would verify the server against the system's roots, or not at all, is refused. The
// configuration is cloned; later changes to cfg do not reach the client. Required (or WithTLSFiles) with a
// network address, refused with a socket.
//
// TLS VERSION. A configuration that sets no MinVersion gets TLS 1.3 (cipheron's listener serves it, and requires it
// unless its network.tls.minVersion says "1.2"). A MinVersion the caller wrote is kept — write tls.VersionTLS12 only
// for a cipheron configured for it — and costs the fail-fast below on a connection that negotiates 1.2: cipheron
// refusing this client's certificate is told by a TLS alert, which only TLS 1.3 authenticates (refusal.go), so over
// TLS 1.2 a refused client's call waits until its context ends instead of failing at once with PERMISSION_DENIED.
// Given twice, the last configuration is used (two configurations are not compared).
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) { o.tls = cfg }
}

// WithTLSFiles is WithTLS with the configuration TLSFromFiles reads from certFile, keyFile and caFile, read
// when the client is made — after the address was found to be a network one. TLS 1.3 at least. Given again with
// other files, the client is refused.
func WithTLSFiles(certFile, keyFile, caFile string) Option {
	return func(o *options) {
		files := [3]string{certFile, keyFile, caFile}
		if o.tlsFiles != nil {
			for i := range files {
				if filepath.Clean(o.tlsFiles[i]) != filepath.Clean(files[i]) {
					o.errs = append(o.errs, fmt.Errorf("cipheron: WithTLSFiles is given twice, with different files (%q and %q); "+
						"pass one", o.tlsFiles[i], files[i]))
					return
				}
			}
		}
		o.tlsFiles = &files
	}
}

// WithServerSPIFFEID makes the client accept, on the network, only a server whose certificate chain verifies
// against the TLS configuration's RootCAs for serverAuth and whose certificate carries exactly one URI SAN, the
// SPIFFE ID id — instead of checking a hostname. Refused with a socket. Given again with another id, the client
// is refused.
func WithServerSPIFFEID(id string) Option {
	return func(o *options) {
		if o.serverSPIFFEID != "" && id != o.serverSPIFFEID {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithServerSPIFFEID(%q) and WithServerSPIFFEID(%q) are two answers "+
				"to one question; pass one", o.serverSPIFFEID, id))
			return
		}
		o.serverSPIFFEID = id
	}
}

// WithRequestKey is the caller's request key: every request but the key fetch is signed with it (RequestAuth) —
// Encrypt, Decrypt, Sign and ReEncrypt, a Tenant's too, CreateTenantKey and RewrapTenantKey; PublicKey (Keys, and
// the fetch every first call in a profile makes) is not, and Verify sends nothing to sign — and cipheron checks the
// signature with the public key of the caller entry the connection's identity matched. Required with a network
// address; on a socket, required when the profile's caller entry has a request key.
//
// The key is copied HERE, when the option is made: the caller may wipe or reuse its slice as soon as WithRequestKey
// returns. The option holds that copy for as long as the option value is reachable (it may make more than one
// client), and each client made with it holds a copy of its own, which its Close wipes. Given again with another
// key, the client is refused.
func WithRequestKey(key ed25519.PrivateKey) Option {
	if len(key) != ed25519.PrivateKeySize {
		n := len(key)
		return func(o *options) {
			o.errs = append(o.errs, fmt.Errorf("cipheron: a request key is an Ed25519 private key of %d bytes, not %d",
				ed25519.PrivateKeySize, n))
		}
	}
	own := bytes.Clone(key)
	return func(o *options) {
		if o.requestKey != nil && subtle.ConstantTimeCompare(o.requestKey, own) != 1 {
			o.errs = append(o.errs, errors.New("cipheron: WithRequestKey is given twice, with different keys; pass one"))
			return
		}
		o.requestKey = own
	}
}

// WithRequestKeyFile is WithRequestKey with the key read from path when the client is made: one PEM "PRIVATE
// KEY" block (PKCS #8, Ed25519), as `cipheron keygen caller` writes it. The file goes through the checked
// reader (secpath.ReadFile, Private): an absolute path, owned by root or this process's user, readable by no
// one else (0400, 0440, 0600, 0640), in a directory chain no one else can write — every directory above it owned
// by root or this user and writable by no one else, EXCEPT a directory with the sticky bit (/tmp, a Kubernetes
// volume's root): others can add files there but cannot replace this one, so it is accepted
// (secpath.CheckDirectory). Its bytes are wiped once parsed. Given again with another path, the client is refused.
func WithRequestKeyFile(path string) Option {
	return func(o *options) {
		if o.requestKeyFile != "" && filepath.Clean(o.requestKeyFile) != filepath.Clean(path) {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithRequestKeyFile(%q) and WithRequestKeyFile(%q) are two answers "+
				"to one question; pass one", o.requestKeyFile, path))
			return
		}
		o.requestKeyFile = path
	}
}

// WithProfileFingerprint pins the profile's public keys to fp, the fingerprint `cipheron keygen` printed for it
// ("sha256:" and 64 lowercase hex digits; transport.Fingerprint). Keys cipheron answers that do not match are
// refused, and every call in the profile fails with ErrServerIdentity: with a pin, HPKE and the response
// signatures make Encrypt, Decrypt and Sign end-to-end against anyone who is not the profile's cipheron — a proxy
// that terminates TLS, a process that took the socket path. Without a pin the keys first fetched are trusted
// (trust on first use). Repeat it for each profile to pin.
func WithProfileFingerprint(profile, fp string) Option {
	return func(o *options) {
		switch {
		case profile == "":
			o.errs = append(o.errs, errors.New("cipheron: WithProfileFingerprint: no profile"))
		case !transport.ValidFingerprint(fp):
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithProfileFingerprint(%q): %q is not a fingerprint "+
				"(%s and 64 lowercase hex digits, as `cipheron keygen` prints it)", profile, fp, transport.FingerprintPrefix))
		case o.pins[profile] != "" && o.pins[profile] != fp:
			o.errs = append(o.errs, fmt.Errorf("cipheron: profile %q is pinned to two fingerprints", profile))
		default:
			if o.pins == nil {
				o.pins = map[string]string{}
			}
			o.pins[profile] = fp
		}
	}
}

// MaxContextDigestPins is the most key-context digests one profile may be pinned to (WithContextDigestPin): one,
// or a few while a key-context change rolls out.
const MaxContextDigestPins = 8

// WithContextDigestPin pins the profile's key context to digests, each a key-context digest as `cipheron keygen
// ensure` prints it (contextDigest: "sha256:" and 64 lowercase hex digits): the profile's keys are accepted only when
// the key-context digest cipheron answers — which its PublicKey answer signs under the profile's response key
// (keys_signature) — is one of them, and EVERY ANSWER only when it verifies under one of them: the response
// signature covers the key-context digest of the replica that made the answer (transport.ResponseTranscript), so a
// data call answered by a replica on another context is refused as surely as its key fetch. A signing activation
// does not change it (D-Q). Anything else is ErrContextDigest (or, for an answer whose context this client never saw
// a PublicKey answer give, ErrServerIdentity: the answer verifies under no context it knows), and nothing of that
// answer is used or cached.
//
// WHY. The fingerprint pin (WithProfileFingerprint) names the profile's identity, which never changes; the key context
// does: the master versions and their check values, the published signing keys, the keyset. A replica serving a
// drifted or stale shared key-context file — another master version list, another keyset — answers with the right
// identity, and its digest is the only thing that tells it apart. cipheron's own expectContext refuses such a
// file at start, when the operator set it; this pin makes the client refuse it too, answer by answer, so the check
// does not depend on every replica's configuration, nor on which replica a path party routes a call to.
//
// More than one digest is for a rollout: the old and the new, while replicas are moved from one key context to the
// other (docs: the rollout order). Given twice for a profile, the lists are joined; at most MaxContextDigestPins.
// Pins given here are fixed for the client's life. With WithEnvironment, a "<profile>.contextDigest" file in the pins
// directory gives them, one per line, and that file is RE-READ while the client runs (livepins.go, owner decision
// D-P): the widen (old and new) and the narrow (new only) of a rollout reach a running client without a restart.
func WithContextDigestPin(profile string, digests ...string) Option {
	return func(o *options) {
		switch {
		case profile == "":
			o.errs = append(o.errs, errors.New("cipheron: WithContextDigestPin: no profile"))
			return
		case len(digests) == 0:
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithContextDigestPin(%q): no digest", profile))
			return
		}
		for _, d := range digests {
			if !transport.ValidFingerprint(d) {
				o.errs = append(o.errs, fmt.Errorf("cipheron: WithContextDigestPin(%q): %q is not a key-context digest "+
					"(%s and 64 lowercase hex digits, as `cipheron keygen ensure` prints contextDigest)", profile, d,
					transport.FingerprintPrefix))
				return
			}
		}
		if o.contextPins == nil {
			o.contextPins = map[string][]string{}
		}
		joined := o.contextPins[profile]
		for _, d := range digests {
			if !slices.Contains(joined, d) {
				joined = append(joined, d)
			}
		}
		if len(joined) > MaxContextDigestPins {
			o.errs = append(o.errs, fmt.Errorf("cipheron: profile %q is pinned to %d key-context digests; at most %d",
				profile, len(joined), MaxContextDigestPins))
			return
		}
		o.contextPins[profile] = joined
	}
}

// MaxWriterVersionPins is the most master key versions one profile's writer may be pinned to (WithWriterVersionPin):
// one, or two while the writer switches.
const MaxWriterVersionPins = 8

// WithWriterVersionPin pins the master key versions the profile's NEW data may be made under: versions are master
// version ids as the configuration lists them (profiles.<profile>.versions). An answer that makes new data — Encrypt,
// ReEncrypt and their batches, the object, stream and JSON-field helpers built on them, in a shared or derived profile:
// the ciphertext's master version; CreateTenantKey and RewrapTenantKey and its batch in a wrapped profile: the blob's
// wrapping version — is accepted only when that version is one of them. Anything else is ErrContextDigest, and nothing
// of the answer is returned. Reads are not held to it: a ciphertext of any listed version still decrypts.
//
// WHY. The key-context digest (WithContextDigestPin) covers which master versions are listed and the key each
// unseals to, not which one writes: a writer switch (a version made active, or its activateAt passing) does not move
// it, so a replica that lags the switch — or one a path party prefers because it still writes under a version retired
// after a compromise — answers under a pinned digest. This pin names the writer itself. A writer switch is then a pin
// change too: widen (old and new), switch, narrow (new only).
//
// Given twice for a profile, the lists are joined; at most MaxWriterVersionPins. Pins given here are fixed for the
// client's life.
func WithWriterVersionPin(profile string, versions ...string) Option {
	return func(o *options) {
		switch {
		case profile == "":
			o.errs = append(o.errs, errors.New("cipheron: WithWriterVersionPin: no profile"))
			return
		case len(versions) == 0:
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithWriterVersionPin(%q): no master key version", profile))
			return
		}
		for _, v := range versions {
			if !transport.ValidMasterVersionID(v) {
				o.errs = append(o.errs, fmt.Errorf("cipheron: WithWriterVersionPin(%q): %q is not a master key version id",
					profile, v))
				return
			}
		}
		if o.writerPins == nil {
			o.writerPins = map[string][]string{}
		}
		joined := o.writerPins[profile]
		for _, v := range versions {
			if !slices.Contains(joined, v) {
				joined = append(joined, v)
			}
		}
		if len(joined) > MaxWriterVersionPins {
			o.errs = append(o.errs, fmt.Errorf("cipheron: profile %q's writer is pinned to %d master key versions; at most %d",
				profile, len(joined), MaxWriterVersionPins))
			return
		}
		o.writerPins[profile] = joined
	}
}

// WithPinsDir reads the profiles' pins from dir, an absolute path — the "<profile>.fingerprint" and
// "<profile>.contextDigest" files WithEnvironment reads from EnvPinsDir, under the same rules (the checked reader, a
// directory writable by nobody but root and this user, a Kubernetes volume read through its "..data" link) — and
// RE-READS it while the client runs (livepins.go, owner decision D-P): a key-context pin the kubelet updates (a widen,
// a narrow) is in force without a restart, an update that is not whole or holds a pin the first read refuses is not
// applied, a profile whose file disappears keeps its pins, and a profile's fingerprint never changes. For a client that
// does not use WithEnvironment — a network client, whose pins are a ConfigMap the application mounts. With
// WithEnvironment and EnvPinsDir set, it must name the same directory (else the client is refused: two answers).
// It implies nothing about required pins: add WithRequiredPins. Given again with another directory, the client is
// refused.
func WithPinsDir(dir string) Option {
	return func(o *options) {
		if o.pinsDirOption != "" && filepath.Clean(o.pinsDirOption) != filepath.Clean(dir) {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithPinsDir(%q) and WithPinsDir(%q) are two answers to one "+
				"question; pass one", o.pinsDirOption, dir))
			return
		}
		if dir == "" {
			o.errs = append(o.errs, errors.New("cipheron: WithPinsDir: no directory"))
			return
		}
		o.pinsDirOption = dir
	}
}

// WithRequiredPins makes a pin required for every profile the client uses: a profile with no fingerprint — neither
// WithProfileFingerprint nor, with WithEnvironment, a "<profile>.fingerprint" file in the pins directory — is not
// trusted on first use; its first call fails with ErrPinRequired before anything is asked of cipheron. Use it where
// the pins are delivered with the application (the sidecar chart mounts one per profile), so that a pin missing from
// a deployment is an error and not a silent fall back to trust on first use.
//
// The refusal is each profile's first call's, before any request: a pin from any source — WithProfileFingerprint, or
// a pins file read by WithEnvironment — serves the profile. One case is refused earlier, when the client is made:
// with WithEnvironment, a pins directory (EnvPinsDir) that is set and read and holds no "<profile>.fingerprint", and
// no WithProfileFingerprint either — then no profile could ever be used, and DialGRPC/DialHTTP fail with
// ErrPinRequired (and ErrServerIdentity), the answer every call would give. An empty directory beside a pin given by
// an option is accepted. A directory that cannot be read is refused whatever the pins.
func WithRequiredPins() Option {
	return func(o *options) { o.requirePins = true }
}

// WithTenantFingerprint pins tenant's key in profile to fp, the fingerprint CreateTenantKey answered for it
// (transport.TenantFingerprint: "sha256:" and 64 lowercase hex digits). A Tenant handle given a blob of another
// key — another key of the tenant, or a blob swapped where the application stores it — fails every call with
// ErrTenantKey before anything is sent, and so does RewrapTenantKey given one. Without a pin the blob the
// application hands over is the tenant's key. Repeat it per tenant. (A wrapped profile only: a derived profile's
// tenants have no key of their own.)
//
// TENANT PINS ARE FIXED FOR THE CLIENT'S LIFE (unlike the pins directory of WithEnvironment, which is re-read): there is no way to add, change or drop one on a client that exists. A
// tenant whose key the service rotates (CreateTenantKey again: a NEW key, with a new fingerprint) is therefore
// refused by a client that pins the old fingerprint — its new blob is "not the pinned key" — until a client is made
// with the new pin. A service that rotates tenant keys either pins nothing per tenant (and protects the blobs
// where it stores them), or makes its clients anew when a tenant's pin changes. RewrapTenantKey keeps the key and
// its fingerprint, and needs nothing. The target blob of Tenant.ReEncrypt is not held to the pin (it is usually the
// tenant's new key).
func WithTenantFingerprint(profile, tenant, fp string) Option {
	return func(o *options) {
		ref := tenantRef{profile, tenant}
		switch {
		case profile == "" || !transport.ValidTenant(tenant):
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithTenantFingerprint(%q, %q): a profile and a tenant id", profile, tenant))
		case !transport.ValidFingerprint(fp):
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithTenantFingerprint(%q, %q): %q is not a fingerprint "+
				"(%s and 64 lowercase hex digits, as CreateTenantKey answers it)", profile, tenant, fp, transport.FingerprintPrefix))
		case o.tenantPins[ref] != "" && o.tenantPins[ref] != fp:
			o.errs = append(o.errs, fmt.Errorf("cipheron: tenant %q of profile %q is pinned to two fingerprints", tenant, profile))
		default:
			if o.tenantPins == nil {
				o.tenantPins = map[tenantRef]string{}
			}
			o.tenantPins[ref] = fp
		}
	}
}

// WithMaxMessageBytes is the largest message the client sends or receives, n bytes (default
// DefaultMaxMessageBytes). A plaintext, a ciphertext or data whose request or answer would not fit is refused
// before anything is sent, with ErrTooLarge. cipheron has its own limit (its listener's maxRequestBytes, by default
// room for a request carrying one segment of transport.MaxSegmentSize, 64 MiB at most), which refuses with ErrTooLarge
// too.
func WithMaxMessageBytes(n int) Option {
	return func(o *options) {
		if n < minMaxMessageBytes || n > math.MaxInt32 {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithMaxMessageBytes(%d): between %d and %d", n,
				minMaxMessageBytes, math.MaxInt32))
			return
		}
		o.maxMessage = n
	}
}

// WithConnections is how many connections the client keeps to cipheron, from 1 to MaxConnections (default
// DefaultConnections over gRPC, DefaultHTTPConnections over HTTP). Over gRPC calls take them in turn, any number at
// once on each (up to cipheron's maxConcurrentStreams); each is opened, and authenticated, like the first, when a
// call first needs it. Over HTTP it is the most connections the transport opens, and so the most calls that run at
// once (HTTP/1.1: one request a connection); the others wait. MaxConnections is under cipheron's default cap of connections per caller (32,
// maxConnectionsPerCaller): a caller that runs several clients, or several processes under one identity, shares
// that cap among them.
func WithConnections(n int) Option {
	return func(o *options) {
		if n < 1 || n > MaxConnections {
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithConnections(%d): from 1 to %d", n, MaxConnections))
			return
		}
		o.connections = n
	}
}

// WithRoundRobin spreads a network client's calls over every address its host name resolves to (gap review D8):
// each of the WithConnections connections becomes gRPC's DNS resolver over the address's host and the round_robin
// policy over what it resolves — one connection to EACH resolved address, calls taken in turn across those that are
// ready. Behind a headless Kubernetes Service (the cipheron chart's service.headless) the host resolves to the pods
// themselves, so every replica serves this client, not the one an L4 balancer happened to pick per connection.
//
// What it costs and what it does not do:
//   - connections: WithConnections × the replicas, each its own TLS handshake; cipheron bounds a caller's
//     connections per replica (maxConnectionsPerCaller), which each replica sees as WithConnections, as without it;
//   - discovery is by reconnection: the address is resolved again when a connection closes or fails — every replica
//     sends GOAWAY at its maxConnectionAge (30 minutes, shorter when configured), so a replica added is in use within
//     that, and a replica removed is dropped as its connection closes. gRPC resolves at most every 30 seconds;
//   - nothing about trust changes: each connection is verified exactly as one connection is (the server's
//     certificate by its host name or WithServerSPIFFEID, the profile's pin, every answer's signature). A replica that
//     fails verification fails the calls given to it, as one replica would.
//
// gRPC only, network only: DialHTTP and a socket address refuse it. Off by default (one connection per address, as
// gRPC's pick_first picks it).
func WithRoundRobin() Option {
	return func(o *options) { o.roundRobin = true }
}

// WithKeysMaxAge is how old, at most, a profile's signing-key list may be when Verify (the Client's, and a derived
// profile's Tenant.Verify) decides on a signature with it: from MinKeysMaxAge (5 seconds) to MaxKeysMaxAge (24 hours),
// DefaultKeysMaxAge (5 minutes) unless given. A list older than that is fetched again before Verify answers, so a
// signing key cipheron revoked is refused here at most d after the revocation reached the cipheron that answers.
// When that fetch fails, Verify fails closed: (false, ErrKeysStale), wrapping the fetch's error — online
// verification then needs cipheron reachable at least once every d. A failed fetch is not retried for a few seconds
// (the Verifies meanwhile answer ErrKeysStale with that failure), so a cipheron that is down is not asked once per
// Verify. Sign judges the key its answer names on a list no older than d too (refreshed first, the same way): a
// signature under a key revoked since is refused (ErrSigningKeyRevoked), and a list that cannot be refreshed is
// ErrKeysStale — no signature is returned. KeyStatement hands out only a statement this Client verified less than d
// ago (else ErrKeysStale). Encrypt and the other calls do not look at the list's age. Ages are measured on the
// monotonic clock: a wall clock stepped back does not make an old list fresh. Given again with another value, the
// client is refused.
func WithKeysMaxAge(d time.Duration) Option {
	return func(o *options) {
		switch {
		case d < MinKeysMaxAge || d > MaxKeysMaxAge:
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithKeysMaxAge(%s): from %s to %s", d, MinKeysMaxAge, MaxKeysMaxAge))
		case o.keysMaxAge != 0 && o.keysMaxAge != d:
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithKeysMaxAge(%s) and WithKeysMaxAge(%s) are two answers to one "+
				"question; pass one", o.keysMaxAge, d))
		default:
			o.keysMaxAge = d
		}
	}
}

// endpoint is where a client connects: a unix socket (an absolute path) or a network address (host:port).
type endpoint struct {
	socket  string
	address string
}

// unixScheme is the prefix of a socket written as a URI.
const unixScheme = "unix://"

// IsSocket reports whether address names a unix socket (and not a network address), as DialGRPC reads it.
func IsSocket(address string) (bool, error) {
	e, err := parseEndpoint(address)
	return e.socket != "", err
}

// parseEndpoint reads where to connect:
//   - "unix:///run/cipheron/private/cipheron.sock" (the path after the scheme must be absolute), or anything with a
//     "/" in it, is a socket path;
//   - "host:port", the port a number from 1 to 65535 and the host not empty, is a network address;
//   - a bare name with no ":" is a socket path relative to the working directory.
//
// Anything else is refused rather than guessed.
func parseEndpoint(s string) (endpoint, error) {
	switch {
	case s == "":
		return endpoint{}, errors.New("cipheron: no address: write a socket path or host:port")
	case strings.HasPrefix(s, unixScheme):
		p := strings.TrimPrefix(s, unixScheme)
		if !filepath.IsAbs(p) {
			return endpoint{}, fmt.Errorf("cipheron: %q: a unix:// address names an absolute path (unix:///run/cipheron/private/cipheron.sock)", s)
		}
		return endpoint{socket: filepath.Clean(p)}, nil
	case strings.Contains(s, "/"):
		abs, err := filepath.Abs(s)
		if err != nil {
			return endpoint{}, err
		}
		return endpoint{socket: abs}, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if !strings.Contains(s, ":") {
			abs, err := filepath.Abs(s)
			if err != nil {
				return endpoint{}, err
			}
			return endpoint{socket: abs}, nil
		}
		return endpoint{}, fmt.Errorf("cipheron: %q is neither a socket path nor host:port: %w", s, err)
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 || host == "" {
		return endpoint{}, fmt.Errorf("cipheron: %q: a network address is host:port, with a host and a port from 1 to 65535", s)
	}
	return endpoint{address: s}, nil
}

// plan is a validated endpoint with its options.
type plan struct {
	endpoint

	serverUID   *uint32     // socket: nil only with WithAnyServer
	tls         *tls.Config // the client's own clone, server verification applied; network only
	requestKey  ed25519.PrivateKey
	pins        map[string]string
	contextPins map[string][]string
	writerPins  map[string][]string
	requirePins bool
	tenantPins  map[tenantRef]string
	maxMessage  int
	connections int
	roundRobin  bool
	keysMaxAge  time.Duration // 0: DefaultKeysMaxAge
	observer    func(profile, kind string)
	retry       *RetryPolicy // nil: none
	// The live re-read of the pins directory (livepins.go): pinsDir "" when there is none.
	pinsDir       string
	dirPins       dirPins
	inlinePins    map[string]string
	inlineContext map[string][]string
}

// resolve parses where — or, with WithEnvironment, takes it from the environment — and checks the options against
// it: a socket takes WithServerUID or WithAnyServer (one of them) and no TLS; a network address takes TLS and a request key — both required — and
// WithServerSPIFFEID, and neither WithServerUID nor WithAnyServer.
func resolve(where string, opts []Option) (*plan, error) {
	o := options{maxMessage: DefaultMaxMessageBytes} // connections 0: the transport's default (DialGRPC, DialHTTP)
	for _, f := range opts {
		if f != nil { // a nil Option is skipped
			f(&o)
		}
	}
	if o.env {
		var err error
		if where, err = o.fromEnvironment(where); err != nil {
			return nil, err
		}
	}
	e, err := parseEndpoint(where)
	if err != nil {
		return nil, err
	}
	if o.requestKey != nil && o.requestKeyFile != "" {
		o.errs = append(o.errs, errors.New("cipheron: a request key and a request key file are two answers to one question; pass one"))
	}
	if d := o.pinsDirOption; d != "" {
		switch {
		case o.pinsDir != "" && o.pinsDir != filepath.Clean(d):
			o.errs = append(o.errs, fmt.Errorf("cipheron: WithPinsDir(%q) and %s=%s are two answers to one question; "+
				"pass one", d, EnvPinsDir, o.pinsDir))
		case o.pinsDir == "":
			if err := o.readPins(d); err != nil {
				return nil, fmt.Errorf("cipheron: WithPinsDir: %w", err)
			}
		}
	}
	if len(o.errs) > 0 {
		return nil, errors.Join(o.errs...)
	}
	p := &plan{endpoint: e, serverUID: o.serverUID, pins: o.pins, contextPins: o.contextPins, writerPins: o.writerPins,
		requirePins: o.requirePins, tenantPins: o.tenantPins,
		maxMessage: o.maxMessage, connections: o.connections, roundRobin: o.roundRobin, keysMaxAge: o.keysMaxAge,
		observer: o.observer, retry: o.retry, pinsDir: o.pinsDir, dirPins: o.dirPins,
		inlinePins: o.inlinePins, inlineContext: o.inlineContext}
	if e.socket != "" {
		if o.roundRobin {
			return nil, fmt.Errorf("cipheron: %s is a unix socket: WithRoundRobin spreads calls over the addresses a "+
				"network host name resolves to, and a socket has one process", e.socket)
		}
		if o.tls != nil || o.tlsFiles != nil || o.serverSPIFFEID != "" {
			return nil, fmt.Errorf("cipheron: %s is a unix socket: TLS options apply to a network address only "+
				"(on the socket cipheron knows its callers by their uid and gid)", e.socket)
		}
		switch {
		case o.serverUID != nil && o.anyServer:
			return nil, errors.New("cipheron: WithServerUID and WithAnyServer contradict each other; pass one")
		case o.serverUID == nil && !o.anyServer:
			return nil, fmt.Errorf("cipheron: %s is a unix socket: say which uid cipheron runs as (WithServerUID; "+
				"10443 in cipheron's image), so that a process that takes the socket path while cipheron is down "+
				"receives nothing — or pass WithAnyServer to trust whatever listens there", e.socket)
		}
	} else {
		if o.serverUID != nil || o.anyServer {
			return nil, fmt.Errorf("cipheron: %s is a network address: WithServerUID and WithAnyServer apply to a "+
				"unix socket only (verify a network server by its certificate: WithServerSPIFFEID, or its hostname)", e.address)
		}
		if o.tls != nil && o.tlsFiles != nil {
			return nil, errors.New("cipheron: a TLS configuration and TLS files are two answers to one question; pass one")
		}
		if o.tls == nil && o.tlsFiles == nil {
			return nil, fmt.Errorf("cipheron: %s is a network address: a TLS configuration with a client certificate "+
				"is required (cipheron knows its network callers by their certificate's SPIFFE ID)", e.address)
		}
		if o.requestKey == nil && o.requestKeyFile == "" {
			return nil, fmt.Errorf("cipheron: %s is a network address: a request key is required "+
				"(WithRequestKeyFile): cipheron requires every network caller to sign its requests, so that whoever "+
				"terminates TLS on the way can neither forge nor replay them", e.address)
		}
		if o.tlsFiles != nil {
			if o.tls, err = TLSFromFiles(o.tlsFiles[0], o.tlsFiles[1], o.tlsFiles[2]); err != nil {
				return nil, err
			}
		}
		if p.tls, err = clientTLS(o.tls, o.serverSPIFFEID); err != nil {
			return nil, err
		}
	}
	// The client's own copy, which its Close wipes: the option's copy stays the option's (it may make another
	// client), and a key read from a file is this client's alone.
	p.requestKey = bytes.Clone(o.requestKey)
	if o.requestKeyFile != "" {
		if p.requestKey, err = readRequestKey(o.requestKeyFile); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// readRequestKey reads a request private key file (WithRequestKeyFile) and wipes its bytes.
func readRequestKey(path string) (ed25519.PrivateKey, error) {
	pemBytes, err := secpath.ReadFile(path, "cipheron request key", secpath.Private, maxRequestKeyFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroize.Bytes(pemBytes)
	key, err := transport.ParseRequestPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("cipheron request key %s: %w", path, err)
	}
	return key, nil
}

// clientTLS is the client's own clone of cfg, refused when it presents no client certificate or would verify
// the server against the system's roots or not at all, with the SPIFFE ID check installed when serverSPIFFEID
// is set, and with every verification of the server marked so that its refusal is ErrServerIdentity.
func clientTLS(cfg *tls.Config, serverSPIFFEID string) (*tls.Config, error) {
	c := cfg.Clone()
	if c.MinVersion == 0 {
		// Unset: TLS 1.3, not crypto/tls's 1.2. cipheron's listener serves 1.3, and only a TLS 1.3 alert is
		// authenticated (refusal.go). A MinVersion the caller wrote is the caller's (WithTLS).
		c.MinVersion = tls.VersionTLS13
	}
	if err := checkClientCertificate(c); err != nil {
		return nil, err
	}
	if c.RootCAs == nil && c.VerifyConnection == nil && c.VerifyPeerCertificate == nil {
		return nil, errors.New("cipheron: the TLS configuration has no RootCAs and no verification of its own " +
			"(VerifyConnection, VerifyPeerCertificate): the server would be verified against the system's roots, " +
			"which any public CA's customer chains to. Give it the CA bundle cipheron's certificate is issued by")
	}
	if c.VerifyConnection != nil {
		prev := c.VerifyConnection
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if err := prev(cs); err != nil {
				return &identityError{err}
			}
			return nil
		}
	}
	if c.VerifyPeerCertificate != nil {
		prev := c.VerifyPeerCertificate
		c.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			if err := prev(raw, chains); err != nil {
				return &identityError{err}
			}
			return nil
		}
	}
	if serverSPIFFEID == "" {
		if c.InsecureSkipVerify && c.VerifyConnection == nil && c.VerifyPeerCertificate == nil {
			return nil, errors.New("cipheron: the TLS configuration verifies no server (InsecureSkipVerify without " +
				"VerifyConnection or VerifyPeerCertificate): use WithServerSPIFFEID, or verify the hostname")
		}
		return c, nil
	}
	want, err := spiffeid.FromString(serverSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("cipheron: the server SPIFFE ID %q: %w", serverSPIFFEID, err)
	}
	if c.RootCAs == nil {
		return nil, errors.New("cipheron: WithServerSPIFFEID verifies the server's chain against the TLS " +
			"configuration's RootCAs, and it has none")
	}
	roots, prev, clock := c.RootCAs, c.VerifyConnection, c.Time
	// The hostname check is replaced, not dropped: VerifyConnection below verifies the chain against RootCAs
	// for serverAuth, as crypto/tls would, and then the SPIFFE ID instead of a name. crypto/tls calls it on
	// every handshake, resumed ones included.
	c.InsecureSkipVerify = true
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &identityError{errors.New("cipheron: the server presented no certificate")}
		}
		now := time.Now()
		if clock != nil {
			now = clock()
		}
		inter := x509.NewCertPool()
		for _, ic := range cs.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
		leaf := cs.PeerCertificates[0]
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return &identityError{fmt.Errorf("cipheron: the server's certificate: %w", err)}
		}
		got, err := x509svid.IDFromCert(leaf)
		if err != nil {
			return &identityError{fmt.Errorf("cipheron: the server's certificate carries no single SPIFFE ID: %w", err)}
		}
		if got.String() != want.String() {
			return &identityError{fmt.Errorf("cipheron: the server is %s, not the expected %s: refusing to talk to it", got, want)}
		}
		if prev != nil {
			return prev(cs) // already marked above
		}
		return nil
	}
	return c, nil
}

// checkClientCertificate refuses a configuration that presents no usable client certificate, and makes a
// GetClientCertificate that answers none fail the handshake here rather than present nothing.
func checkClientCertificate(c *tls.Config) error {
	if len(c.Certificates) == 0 && c.GetClientCertificate == nil {
		return errors.New("cipheron: the TLS configuration presents no client certificate; cipheron knows its " +
			"network callers by their certificate's SPIFFE ID")
	}
	if c.GetClientCertificate != nil {
		get := c.GetClientCertificate
		c.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := get(cri)
			if err != nil {
				return nil, err
			}
			if err := usableCertificate(cert); err != nil {
				return nil, err
			}
			return cert, nil
		}
		return nil
	}
	certs := make([]tls.Certificate, len(c.Certificates))
	copy(certs, c.Certificates)
	for i := range certs {
		if err := usableCertificate(&certs[i]); err != nil {
			return err
		}
	}
	c.Certificates = certs
	return nil
}

// usableCertificate refuses a client certificate with no chain, no private key, or a leaf that does not
// parse; it fills Leaf in when it was left empty.
func usableCertificate(cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return errors.New("cipheron: the TLS configuration's client certificate is empty (no certificate chain or " +
			"no private key); cipheron knows its network callers by their certificate's SPIFFE ID")
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("cipheron: the TLS configuration's client certificate does not parse: %w", err)
		}
		cert.Leaf = leaf
	}
	return nil
}
