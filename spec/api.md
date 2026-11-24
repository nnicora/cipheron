# cipheron API and wire protocol

cipheron does an application's cryptography for it: the application asks it to encrypt, decrypt, re-encrypt or sign
data in a **profile** (a named set of keys, such as `credentials`), and never holds a key itself. This page is the exact
contract between a client and cipheron: the gRPC service, the JSON API, every message and field, the errors, and the
protocol byte by byte — enough to write a client in another language, and to check what every signature and every
encryption covers.

Sources: `proto/v1/cipheron.proto` (the API), `wire/transport` (every transcript, digest,
fingerprint and header, and the stored layouts — the ciphertext formats, the tenant key blob, the segmented object —
with the one suite that derives each item's key and seals it: `catalog.go`, `ciphertext.go`, `tenant.go`, `segment.go`,
and what this release writes and reads of each, `transport.Release()`), `wire/format` (the framework: kinds,
schemes, suites, policies, and every label, `labels.go`), all in this repository; and, in cipheron's server, its
checks and refusals around the layouts, its master keys, data keys and keyset file, and the order of its checks and
answers. The OpenAPI description generated from the proto is
`proto/v1/cipheron.swagger.json`. Should this page and the code ever disagree, the code
and the [conformance vectors](#conformance-kit) decide, and the page is the one to fix.

- [Who this page is for, and how to read it](#who-this-page-is-for-and-how-to-read-it)
- [Words this page uses](#words-this-page-uses)
- [Transports](#transports)
- [The RPCs](#the-rpcs)
- [Messages](#messages)
- [Errors](#errors)
- [The transcript version](#the-transcript-version)
- [Notation](#notation)
- [HPKE](#hpke)
- [Digests](#digests)
- [Request transcript](#request-transcript)
- [Response transcript](#response-transcript)
- [Identity and fingerprint](#identity-and-fingerprint)
- [Signing keys](#signing-keys)
- [Key-context digest](#key-context-digest)
- [Key check values](#key-check-values)
- [Derived-profile signatures](#derived-profile-signatures)
- [Ciphertext formats](#ciphertext-formats)
- [Associated data](#associated-data)
- [Key statement](#key-statement)
- [Cross-profile ReEncrypt](#cross-profile-reencrypt)
- [Batches](#batches)
- [Segmented objects](#segmented-objects)
- [JSON fields](#json-fields)
- [Tenant key blob](#tenant-key-blob)
- [Data key derivations](#data-key-derivations)
- [Keyset file](#keyset-file)
- [Doing it by hand, in another language](#doing-it-by-hand-in-another-language)
- [Conformance kit](#conformance-kit)

## Who this page is for, and how to read it

This is a reference: you look things up in it rather than read it from the top. It serves three readers.

- **A developer writing a client in a language other than Go.** The Go library, `github.com/nnicora/cipheron`, does everything on
  this page for you ([client-library.md](../docs/client-library.md)); without it, you need all of it. Read
  [Transports](#transports) to [Errors](#errors) for what travels, [The transcript version](#the-transcript-version)
  to [Derived-profile signatures](#derived-profile-signatures) for what to compute and check, then follow
  [Doing it by hand](#doing-it-by-hand-in-another-language) step by step and hold your code to the
  [conformance kit](#conformance-kit).
- **A security reviewer** checking what binds what: the [transcripts](#request-transcript), the [HPKE](#hpke) info
  strings and the [ciphertext formats](#ciphertext-formats) give the exact bytes each signature and each key covers.
- **An application developer or operator decoding a refusal**: [Errors](#errors) gives every gRPC code, HTTP status,
  message and machine-readable reason, and [the order of checks](#the-order-of-checks) says which one a request meets
  first. For what to do about each, see cipheron's troubleshooting guide, section *gRPC codes and ErrorInfo reasons*.

The page has four parts:

| part | sections | what it answers |
| --- | --- | --- |
| the API | Transports, The RPCs, Messages, Errors, The transcript version | where to connect, what to send, what comes back, what each refusal means |
| the protocol | Notation to Derived-profile signatures | how each request and answer is sealed, signed and checked, byte by byte |
| the stored formats | Ciphertext formats to Keyset file | the bytes your application (ciphertexts, tenant key blobs) or the operator (keysets) keeps |
| the implementer's checklist | Doing it by hand, Conformance kit | the steps of a client in order, and the test vectors and test server to prove it |

Byte layouts are written in the [notation](#notation) below. A term is explained where it first appears, the next
section lists the ones the whole page relies on, and cipheron's glossary defines every term of its
documentation set.

## Words this page uses

| word | what it means here |
| --- | --- |
| profile | a named set of keys in cipheron's configuration (`credentials`, `ledger`); every request names one, and nothing of one profile opens another's data |
| tenancy | how a profile treats the customers ("tenants") of the application: **shared** (one set of keys for everyone), **perTenant wrapped** (a key per tenant, which the application stores as a [tenant key blob](#tenant-key-blob)), or **perTenant derived** (every tenant's keys computed from the profile's and the tenant's name, nothing stored) — cipheron's tenancy guide |
| caller, caller entry | who connects (on the socket the process's uid and gid, on the network its certificate's SPIFFE ID), and the configuration entry that lists which operations it may use. The configuration names no tenant: which caller acts for which tenant is the application's decision |
| operation, grant | what a caller entry may do: `encrypt`, `decrypt`, `sign`, `reencrypt`, `provision` (make and rewrap tenant keys), `export` and `import` (move a ciphertext between profiles), `retenant` (a move between profiles that changes the tenant) |
| nonce | 16 random bytes, new for every request: it makes each request and its answer unique, so a recorded answer never passes for another request's, and a recorded request is served at most once by each cipheron process alive at its timestamp (cipheron's security guide, section *The replay cache*) |
| HPKE, seal | Hybrid Public Key Encryption (RFC 9180): encrypting to someone's public key so only the holder of the private key can open it. A client **seals** a plaintext to the profile's key; cipheron seals a decrypted plaintext back to a key the client made for that request |
| Ed25519 | the signature algorithm (RFC 8032) of every signature on this page: requests, answers, the signing-key list, and Sign's output |
| request key | a caller's own Ed25519 key pair; it signs every request but PublicKey, so a party that can use the caller's connection still cannot forge or redirect a request, and a replay is bounded: at most once by each cipheron process alive at the request's timestamp, within `maxSkew`; a process started after it refuses it (`CIPHERON_STARTING`) (cipheron's security guide, sections *Request keys* and *The replay cache*) |
| response key | the profile's Ed25519 key that signs every answer, so a client knows the answer came from cipheron and was made for its own request |
| transcript, label, digest | the exact bytes a signature covers: a fixed **label** that names what is signed, then fields each preceded by its length; a **digest** is a SHA-256 over a request's or an answer's payload fields, which the transcript then carries |
| transcript version | the number bound inside everything signed or sealed: written as the version the release writes for the transcripts, checked under every version it reads — today both are `1`; not negotiated, carried by no message ([The transcript version](#the-transcript-version)) |
| identity, fingerprint, pin | a profile's **identity** is its keys that never change, with its tenancy; its **fingerprint** is a SHA-256 over the profile's name and its identity; a client **pins** the fingerprint (keeps the expected value) and refuses any server whose keys hash to another |
| signing keys | the keys Sign signs with (shared and derived profiles): they rotate, so each has an id and a state — active, verifyOnly, revoked |
| master version, data key | a **master version** is a key held by a KMS (a key management system, such as a KMIP server) that cipheron fetches at start; a **data key** is derived from a master version for one purpose, and each ciphertext's own AES key is derived from a data key ([Data key derivations](#data-key-derivations)) |
| key-context digest | a SHA-256 over everything that decides which data a cipheron of the profile can read and which keys it publishes; replicas compare it, and it can be pinned |
| associated data | context (a row's key, a column name) a caller binds into a ciphertext without storing it in it: the ciphertext then decrypts only with the same context |
| AEAD, tag | AES-256-GCM, the cipher of every ciphertext: it encrypts and authenticates, and its 16-byte **tag** fails if any byte of the ciphertext or of its additional data changed |
| ErrorInfo reason | a fixed machine-readable word (`CIPHERON_BUSY`, …) attached to a refusal; a client decides on it, never on the human-readable message |

## Transports

cipheron listens in one or both of two places, and offers the same service in two encodings on each.

- The **socket** is a Unix profile socket: a file that the application and cipheron share inside one Pod, when cipheron
  runs as a **sidecar** (a second container beside the application). The kernel tells cipheron which user (uid) and
  group (gid) the connecting process runs as, so the caller needs no certificate.
- The **network** port serves cipheron run as a service of its own, for applications in other Pods. It speaks mutual
  TLS: the client presents a certificate too, and the certificate's **SPIFFE ID** (a URI naming a workload,
  `spiffe://<trust domain>/...`) is the caller.
- **gRPC** (protobuf over HTTP/2) is what the Go library uses; the **JSON API** (JSON over HTTP/1.1) is the same
  service for a language or a tool without a gRPC library, `curl` included.

**Why the caller is the connection, never something in the request:** what the kernel reports or the TLS handshake
proved cannot be written by the caller, so a request cannot claim to be someone else
(cipheron's security guide, section *Who may call, and for what*).

| | socket | network |
| --- | --- | --- |
| connect to | the unix socket (`socket.path`) | `network.address`, TLS 1.3 (or 1.2 if configured), a client certificate required |
| gRPC | a connection whose first bytes are the HTTP/2 client preface | ALPN `h2` |
| JSON API | any other connection: HTTP/1.1 | ALPN `http/1.1` |
| the caller is | the kernel's uid and gid of the connecting process | the one SPIFFE ID of the verified client certificate |

gRPC is served by a native `grpc.Server`, service `cipheron.v1.CipherService` (methods
`/cipheron.v1.CipherService/<Method>`). Requests and answers are uncompressed (`grpc-encoding: identity`): a
request sent in any other encoding (`gzip`, or one gRPC does not have) is refused `UNIMPLEMENTED` before it is read
— nothing a caller sends is decompressed — and recorded like every refusal after admission. The JSON API is
grpc-gateway over the same service, HTTP/1.1 only: on the network a JSON request sent over HTTP/2 reaches the gRPC
server and is not served (`curl --http1.1`).

**Unknown request fields are refused on both transports**, the same way: `INVALID_ARGUMENT`, no ErrorInfo reason.
Over gRPC the request (and every message in it, `auth` included) is walked before the service sees it: `unknown field
<n> in <message>: the request has a field the API does not have`. Over HTTP the gateway's decoder does not discard
unknown fields. Why strict: a field cipheron ignored could be one the caller relies on, and a refusal says so at once;
a client built from the same API never sends one. **Answers are read by the fields the client has**: the Go client
reads none of an answer's fields that its API does not have, and decides nothing on one.

### The declared request size

cipheron admits a request against its listener's **memory budget** (`memoryBudget`,
cipheron's configuration reference, section *Listener limits*) before it reads the request's message: the request reserves
`5 × its size + its size / 64 + 786432` bytes (what a request holds at its peak, measured), and gives them back when
it ends. gRPC reads a message's length and its body in one
step, with nothing in between, so the size has to arrive before the message: a request **declares** it.

- **gRPC**: the metadata (request header) `cipheron-request-bytes`, the number of bytes of the request message as
  sent — its protobuf encoding, `proto.Size` in Go. Exactly one value, decimal digits only — no sign, no space, no
  leading zero —, 1 or more, at most what a signed 64-bit integer holds (`^[1-9][0-9]{0,18}$`); an empty message
  declares `1`. The Go library sets it on every call itself, replacing any value the
  caller's context carries; a client of your own sets it per call (the key and the parser cipheron uses:
  `RequestBytesMetadataKey` and `ParseRequestBytes` in `wire/transport`).
- **HTTP**: the body's `Content-Length`. The request is reserved at the size of message that body decodes to (4/3 of
  it in base64, plus 4 KiB of JSON; `transport.HTTPMessageBytes`), at most `maxRequestBytes`. Every HTTP client that
  sends a body of known length declares it so.

**The undeclared lane.** A request that declares nothing — a gRPC client that does not set the metadata, an HTTP body
sent chunked (no `Content-Length`) — is served, reserved at and held to the listener's `undeclaredMaxRequestBytes`
(1 MiB unless configured, and never more than `maxRequestBytes`). A client of your own that sends no declaration
therefore keeps working, unchanged, for requests up to that size; to send larger ones it declares the size.

What each outcome is answered ([Errors](#errors) has the table):

| the request | the answer |
| --- | --- |
| a declaration that is not one decimal number of bytes, 1 or more (two values, `0`, `+5`, `007`, …) | `INVALID_ARGUMENT`, no details: `the request's size declaration (cipheron-request-bytes) is not one decimal number of bytes, 1 or more` — before the message is read |
| a declared size, or a `Content-Length` decoding to one, over `maxRequestBytes` | `RESOURCE_EXHAUSTED` (HTTP 413), no details: `received message larger than max: the request exceeds the listener's maxRequestBytes` — before the message or body is read |
| a size the memory budget cannot cover now | **busy**, as at `maxInFlight`: `RESOURCE_EXHAUSTED` (HTTP 429) with ErrorInfo `CIPHERON_BUSY` and `RetryInfo` — before the message or body is read; retry |
| a gRPC message larger than it declared | `INVALID_ARGUMENT`, no details: `the request message is larger than its declared size (cipheron-request-bytes)` — once the message has been read; its connection is then closed once that answer is written, and its caller's cooldown starts (below) |
| any request of a caller in its cooldown | **busy**: `RESOURCE_EXHAUSTED` (HTTP 429) with ErrorInfo `CIPHERON_BUSY` and a `RetryInfo` of the time left (HTTP `Retry-After`: its seconds, rounded up), message `cipheron refuses this caller's requests for a while: one of its request messages was larger than its declared size (cipheron-request-bytes); retry later` — before anything else is checked |
| a request with no declaration larger than `undeclaredMaxRequestBytes` | `RESOURCE_EXHAUSTED` (HTTP 413), no details: `received message larger than max: a request that declares no size (cipheron-request-bytes over gRPC, Content-Length over HTTP) is at most the listener's undeclaredMaxRequestBytes` — over gRPC once the message has been read, over HTTP as the body is read |
| a declared size larger than the message | served: the request reserved more than it needed, until it ends |

**What the declaration cannot do.** gRPC reads a message whole once its stream is admitted, so a request that sends
more than it declared is refused only after its message was read: what it holds meanwhile beyond its reservation is
bounded by `maxRequestBytes` (gRPC's own limit on a message) and by the caller's `maxInFlightPerCaller`. Such a
refusal is recorded in the audit trail with the connection's identity, and it has consequences beyond the request: its
connection is closed once the refusal is written, and the caller's **cooldown** starts — for one minute its new
requests on that listener, over gRPC and HTTP and from every connection, are answered busy with a `RetryInfo` of the
time left, before anything is reserved for them. Its requests already in flight finish; the other listener still
serves it. The Go library declares every request exactly, so only a client that computes its declaration wrongly meets
the cooldown; its busy answer is retryable, and a client that waits out its `RetryInfo` is served again. Over HTTP a
body cannot run past its `Content-Length`, and a chunked one is cut at the undeclared lane's bound as it is read: the
cooldown is never started there.

JSON API conventions:

- `POST` only: any other method is HTTP `405` with `Allow: POST` and a JSON `google.rpc.Status` (`UNIMPLEMENTED`);
  every answer carries `Cache-Control: no-store` — an answer is made for one request and its nonce, so no cache in
  the path may keep it or hand it to anyone else;
- field names in lowerCamelCase (`sealedPlaintext`, `requestNonce`); bytes in standard base64; every field of an
  answer is written, empty ones included;
- **enums are written as numbers** (`"tenancy": 1`, `"state": 3`), the same numbers as over gRPC (the tables below
  give each); no request carries an enum;
- a field the API does not have is an error (`INVALID_ARGUMENT`, 400);
- **a request is exactly one JSON object** (the request message) and has exactly one profile, as over gRPC. The body
  is decoded whole: anything after the object other than JSON whitespace — a second object, an object with an unknown
  field, trailing bytes — is refused `INVALID_ARGUMENT` (400). The profile is the path's `{profile}`; a body may omit it
  or repeat the same value, and a different one is refused 400 (`the request body's profile differs from the profile in
  the request path`). No operation takes query parameters: a query string is refused 400 (`the request has a query
  string: the API takes no query parameters`). An empty or whitespace-only body is an empty request; an oversize one
  is still 413 (below);
- exactly two HTTP headers become gRPC metadata — `Grpc-Metadata-X-Request-Id` (the audit event's `request_id`, as
  `x-request-id` is on gRPC) and `Grpc-Metadata-Traceparent` (the request span's link, as `traceparent` is on gRPC) —
  and no other (not `X-Request-Id` or `Traceparent` without the prefix, not `Grpc-Metadata-Tracestate`, not
  `Authorization`); nothing of the service becomes a response header; the authorization reads the connection only;
- the request message is bounded by the listener's `maxRequestBytes` on both protocols: a gRPC message as received; an
  HTTP request as decoded, its JSON body being allowed up to 4/3 of it plus 4 KiB (the base64 of its bytes fields and
  the JSON around them). Beyond either: HTTP `413`, `RESOURCE_EXHAUSTED`, no details. The body's `Content-Length` is
  its [declared size](#the-declared-request-size); a chunked body (no `Content-Length`) is held to the listener's
  `undeclaredMaxRequestBytes` instead;
- an error is a JSON `google.rpc.Status` (`code`, `message`, `details`), with the HTTP status of its gRPC code.

A connection from a caller that **no** profile lists is closed before a byte of a request is read: such a caller gets
no answer at all. On the socket the connection is closed as it is accepted (gRPC waits for a connection until its
deadline; HTTP sees the connection closed). On the network the TLS handshake refuses it with a `bad_certificate`
alert; the Go library and `cipheron client` turn that alert into `PERMISSION_DENIED` (`ErrPermissionDenied`) at once,
over gRPC and HTTP, when it is authenticated — TLS 1.3, read after the server proved its certificate — and treat it
as a connection failure otherwise (TLS 1.2). **Why so early:** a process no profile lists learns nothing at all, not
even which profiles exist or which operations they offer, and cannot make cipheron spend work on its requests.

## The RPCs

Each RPC (remote procedure call) works on one profile, named in the JSON route's `{profile}` and in the request's
`profile` field. The table gives, for each, the **operation** the caller's entry must be granted in the configuration
(cipheron's configuration reference, section *`callers`*), and its **transcript label**: the word that names the RPC inside
everything signed for it, so a signature made for one RPC never passes for another's. The operation and the label
usually match; where they do not (RewrapTenantKey, the batches, a cross-profile ReEncrypt), the grant decides who may
call and the label decides what is signed.

| RPC | JSON route (`POST`) | operation the caller entry needs | transcript label | request carries |
| --- | --- | --- | --- | --- |
| PublicKey | `/v1/cipher/{profile}/public-key` | none: any listed caller | — | `profile`, `request_nonce` |
| Encrypt | `/v1/cipher/{profile}/encrypt` | `encrypt` | `encrypt` | `enc`, `sealed_plaintext`, `request_nonce`, `auth`, `tenant`, `tenant_key`, `associated_data` |
| Decrypt | `/v1/cipher/{profile}/decrypt` | `decrypt` | `decrypt` | `recipient_public_key`, `ciphertext`, `request_nonce`, `auth`, `tenant`, `tenant_key`, `associated_data` |
| Sign | `/v1/cipher/{profile}/sign` | `sign` | `sign` | `enc`, `sealed_data`, `request_nonce`, `auth`, `tenant`, `tenant_key` |
| ReEncrypt | `/v1/cipher/{profile}/reencrypt` | `reencrypt` within the profile; cross-profile: `export` on `profile` and `import` on `to_profile`, and `retenant` on `profile` when the move changes the tenant; a re-binding (a `to_associated_data` other than `associated_data`) also `decrypt` on `profile` and `encrypt` where the new ciphertext is made ([associated data](#associated-data)) | `reencrypt` | `ciphertext`, `tenant`, `tenant_key`, `to_tenant_key`, `request_nonce`, `auth`, `associated_data`, `to_associated_data`, `to_profile`, `to_tenant`, `to_auth` |
| CreateTenantKey | `/v1/cipher/{profile}/tenant-key` | `provision` | `provision` | `tenant`, `request_nonce`, `auth` |
| RewrapTenantKey | `/v1/cipher/{profile}/rewrap-tenant-key` | `provision` | `rewrap-tenant-key` | `tenant`, `tenant_key`, `request_nonce`, `auth` |
| EncryptBatch | `/v1/cipher/{profile}/encrypt-batch` | `encrypt` | `encrypt-batch` | `items` (`enc`, `sealed_plaintext`, `associated_data`), `tenant`, `tenant_key`, `request_nonce`, `auth` |
| DecryptBatch | `/v1/cipher/{profile}/decrypt-batch` | `decrypt` | `decrypt-batch` | `recipient_public_key`, `items` (`ciphertext`, `associated_data`), `tenant`, `tenant_key`, `request_nonce`, `auth` |
| ReEncryptBatch | `/v1/cipher/{profile}/reencrypt-batch` | `reencrypt` (an item that re-binds: also `decrypt` and `encrypt`) | `reencrypt-batch` | `items` (`ciphertext`, `associated_data`, `to_associated_data`), `tenant`, `tenant_key`, `to_tenant_key`, `request_nonce`, `auth` |
| RewrapTenantKeyBatch | `/v1/cipher/{profile}/rewrap-tenant-key-batch` | `provision` | `rewrap-tenant-key-batch` | `items` (`tenant`, `tenant_key`), `request_nonce`, `auth` |

What each does:

- **PublicKey** returns the profile's identity (HPKE key, response key, tenancy), its signing keys and its key-context
  digest, signed by the response key over the request's nonce, so a recorded older answer does not pass for a fresh
  one ([signing keys](#signing-keys)). It also carries the [key statement](#key-statement).
- **Encrypt** opens the plaintext sealed to the profile's HPKE key and returns it encrypted: format 4 (shared, derived)
  under the **writer** (the master version new data is made under), or format 3 (wrapped) under the tenant key — 5 and 6
  with [associated data](#associated-data).
- **Decrypt** decrypts a ciphertext of the profile — format 4 or 5 (shared, derived), 3 or 6 (wrapped) — and returns
  the plaintext sealed to the caller's one-time public key.
- **Sign** opens the data sealed to the profile's HPKE key and signs it, Ed25519 (RFC 8032, pure): shared, with the
  active signing key over the data; derived, with the active signing key over the
  [tenant-bound message](#derived-profile-signatures); wrapped, with the tenant key over the data. The answer names the
  key (`key_id`).
- **ReEncrypt** decrypts a stored ciphertext (any format the profile reads) and encrypts the same plaintext again: format
  4 under the writer (shared, derived), or format 3 under `to_tenant_key` (wrapped) — 5 and 6 with `to_associated_data`,
  which a request with `associated_data` must carry ([associated data](#associated-data)). The plaintext never leaves
  cipheron. With `to_profile` it moves the ciphertext into ANOTHER profile of the same cipheron ([cross-profile
  ReEncrypt](#cross-profile-reencrypt)).
- **EncryptBatch, DecryptBatch, ReEncryptBatch, RewrapTenantKeyBatch** are the single operations over a list of
  items, with one auth and one response signature for the batch and a result (or an item error) per item
  ([batches](#batches)).
- **CreateTenantKey** (wrapped profiles) makes a new tenant key and returns it as a [blob](#tenant-key-blob) wrapped
  under the writer's tenant-wrapping key.
- **RewrapTenantKey** (wrapped profiles) opens a blob and returns the same tenant key (same key id, signing key, storage
  key, creation time, fingerprint) in a new blob, with a new salt, under the writer's tenant-wrapping key.

There is no Verify RPC: signatures verify with any Ed25519 implementation, so anyone holding the published public key
— a partner, an auditor, a service without access to cipheron — checks them without asking cipheron
([Signing keys](#signing-keys), [Key statement](#key-statement)). No RPC activates, retires or rotates a key: keys
change only through the configuration and the keyset file, which an operator changes and reviews, so a caller allowed
to encrypt can never change what it encrypts under (cipheron's keys and rotation guide).

## Messages

The messages are defined in `proto/v1/cipheron.proto`; the tables below say what each field holds and why it
is there. Three fields recur:

- `string profile` is in every request: the profile as configured.
- `bytes request_nonce` is in every request: 16 random bytes, new for every request. The answer is signed over it, so
  an answer recorded earlier never passes for the answer to this request, and each cipheron process accepts a signed
  request's nonce only once; a process started after the request was signed refuses it (`CIPHERON_STARTING`), and
  cipheron's security guide, section *The replay cache* gives the bound across replicas. PublicKey too refuses any other length,
  none included (`INVALID_ARGUMENT`): an answer over the empty nonce would pass for every later request without one, for
  the identity's life.
- `RequestAuth auth`, in every request but PublicKey: the request key's signature
  ([Request transcript](#request-transcript)); required when the caller entry has request keys.

No message carries a version: both sides bind the [transcript version](#the-transcript-version) into what they sign
and seal, and the API's own version is its protobuf package, `cipheron.v1`.

On the wire, protobuf names a field by its **field number**, not its name: a client generated from the proto file
needs nothing more, while a hand-written encoder needs the numbers below. The numbers are those of the proto file; a
number that is not used is not a field (cipheron refuses a request that carries one).

The fields beyond the core of each message (proto field numbers):

| message | field | number | content |
| --- | --- | --- | --- |
| `PublicKeyResponse` | `hpke_suite` | 10 | `HpkeSuite { kem_id, kdf_id, aead_id }` of `hpke_public_key`: `0x0010`, `0x0001`, `0x0002`. Always written; a client refuses an answer without it |
| | `response_key_algorithm` | 11 | `SignatureAlgorithm` of `response_public_key`: `SIGNATURE_ALGORITHM_ED25519` (1). Always written |
| | `additional_identity_keys` | 12 | repeated `IdentityKey { role, hpke_suite, signature_algorithm, public_key }`: keys added to the identity after the profile was made (none in a profile cipheron makes); covered by [fingerprint derivation 2](#identity-and-fingerprint) |
| | `key_statement`, `key_statement_signature` | 13, 14 | the [key statement](#key-statement) and the response key's Ed25519 signature over it |
| `SigningKey` | `algorithm` | 4 | `SIGNATURE_ALGORITHM_ED25519` (1); 0 is never sent ([signing keys](#signing-keys)) |
| `EncryptRequest`, `DecryptRequest` | `associated_data` | 9 | caller [associated data](#associated-data), 0 to 65 536 bytes |
| `ReEncryptRequest` | `associated_data`, `to_associated_data` | 9, 10 | the stored ciphertext's and the new one's. proto3 `bytes` have no presence, so empty is none. A non-empty `associated_data` with an empty `to_associated_data` is refused: send the same bytes to keep the binding ([associated data](#associated-data)) |
| | `to_profile`, `to_tenant`, `to_auth` | 11, 12, 13 | the [cross-profile](#cross-profile-reencrypt) target and its entry's signature |
| `ReEncryptResponse` | `to_response_signature` | 3 | cross-profile: the target profile's response signature |

Every field of the single operations, by message (a number in parentheses is a length in bytes; the batch messages,
whose items carry the same fields, are described in [Batches](#batches) and numbered in the proto file):

| message | field | type | content |
| --- | --- | --- | --- |
| `RequestAuth` | `timestamp_ms` | int64 | Unix milliseconds when the client made the request |
| | `signature` | bytes | Ed25519 (64) by a request key over the [request transcript](#request-transcript) |
| `PublicKeyResponse` | `hpke_public_key` | bytes | the HPKE public key: an uncompressed P-256 point (65) |
| | `response_public_key` | bytes | the Ed25519 response key (32) |
| | `tenancy` | `Tenancy` | `TENANCY_SHARED` (1), `TENANCY_PER_TENANT_WRAPPED` (2), `TENANCY_PER_TENANT_DERIVED` (3) |
| | `signing_keys` | repeated `SigningKey` | every signing key ever added, revoked ones included, ascending `key_id`, exactly one ACTIVE; none in a wrapped profile; at most 256 |
| | `keys_signature` | bytes | Ed25519 by the response key over the [signing-keys transcript](#signing-keys), which includes the request's nonce |
| | `context_digest` | string | the [key-context digest](#key-context-digest) |
| `SigningKey` | `key_id` | bytes | [`SigningKeyID`](#signing-keys)(`public_key`) (16) |
| | `state` | `SigningKeyState` | `SIGNING_KEY_STATE_ACTIVE` (1): signs; `SIGNING_KEY_STATE_VERIFY_ONLY` (2): its signatures verify, it no longer signs; `SIGNING_KEY_STATE_REVOKED` (3): listed, never signs, every signature under it refused. 0 (`UNSPECIFIED`) is never sent; a client refuses an answer holding any other number |
| | `public_key` | bytes | Ed25519 public key (32) |
| `EncryptRequest` | `enc`, `sealed_plaintext` | bytes | the HPKE encapsulated key (65) and the sealed plaintext |
| | `tenant` | string | perTenant profiles: required; shared: must be empty |
| | `tenant_key` | bytes | wrapped profiles: the tenant's blob, required; shared and derived: must be empty |
| `EncryptResponse` | `ciphertext` | bytes | format 4 (shared, derived) or 3 (wrapped) |
| | `response_signature` | bytes | over the [response transcript](#response-transcript) |
| `DecryptRequest` | `recipient_public_key` | bytes | a one-time P-256 public key, uncompressed (65) |
| | `ciphertext` | bytes | a ciphertext of the profile |
| | `tenant`, `tenant_key` | | as Encrypt's |
| `DecryptResponse` | `enc`, `sealed_plaintext` | bytes | the plaintext sealed to `recipient_public_key` |
| | `response_signature` | bytes | |
| `SignRequest` | `enc`, `sealed_data` | bytes | the data, sealed |
| | `tenant`, `tenant_key` | | as Encrypt's |
| `SignResponse` | `signature` | bytes | Ed25519 (64) |
| | `key_id` | bytes | the key that signed (16): a `SigningKey.key_id` (shared, derived) or the tenant key id (wrapped) |
| | `response_signature` | bytes | |
| `ReEncryptRequest` | `ciphertext` | bytes | a stored ciphertext of the profile |
| | `tenant` | string | as Encrypt's |
| | `tenant_key` | bytes | wrapped: the blob the ciphertext was made under (required); otherwise empty |
| | `to_tenant_key` | bytes | wrapped: the blob to encrypt under, the same tenant's (required); otherwise empty |
| `ReEncryptResponse` | `ciphertext`, `response_signature` | bytes | |
| `CreateTenantKeyRequest` | `tenant` | string | the tenant |
| `CreateTenantKeyResponse` | `tenant_key` | bytes | the [tenant key blob](#tenant-key-blob) |
| | `signing_public_key` | bytes | the tenant key's Ed25519 public key (32) |
| | `fingerprint` | string | the [tenant fingerprint](#tenant-key-blob) |
| | `response_signature` | bytes | |
| `RewrapTenantKeyRequest` | `tenant`, `tenant_key` | | the tenant and its blob |
| `RewrapTenantKeyResponse` | `tenant_key`, `signing_public_key`, `fingerprint`, `response_signature` | | as CreateTenantKey's; the same key |

## Errors

Every refusal is a gRPC status (on the JSON API: a `google.rpc.Status` body with the matching HTTP status). A client
decides on the code and on the `google.rpc.ErrorInfo` detail (`domain: "cipheron.v1"`) where there is one — never on
the message. **Why:** the code and the reason are what a client is meant to act on; the message is written for a
person and may be reworded (`wire/transport`, `Reason*`). A `google.rpc.RetryInfo` detail, where there is
one, says how long to wait before trying again.

**A refusal is not signed.** Only answers carry a response signature; a refusal — its code, its reason, its
`RetryInfo` — is not signed by the profile's response key, and is only as trustworthy as the connection that carried it
(the server's certificate on the network, the server's uid on the socket). A party in the path that can answer for
cipheron can answer `CIPHERON_KEY_VERSION_UNAVAILABLE` or `the ciphertext could not be decrypted` for rows of its
choosing. So never delete, quarantine or provision anything again on a refusal alone: ask again through another
replica or connection, or confirm with a signed operation (a Decrypt that succeeds, a PublicKey answer that lists the
version). The kit's `errorClass` kind holds a client to the class and retry rule of every refusal
([Conformance kit](#conformance-kit)).

**Why every authorization failure is the same `permission denied`:** a refused caller learns nothing about why — not
whether the profile exists, whether it is listed, or which check failed — so probing cipheron tells it nothing. The
operator reads the real reason in cipheron's log (cipheron's troubleshooting guide, section *Refusal reasons in the log*).
Likewise, a ciphertext that fails its tag is one failure, `the ciphertext could not be decrypted`, whether it was
modified, belongs to another profile or tenant, or came with the wrong associated data: the answer never says which.

| code (HTTP) | message | when |
| --- | --- | --- |
| `PERMISSION_DENIED` (403) | `permission denied` | no caller on the connection, an unknown profile, a caller the profile does not list, an entry without the operation, `auth` missing, out of `maxSkew`, a signature that does not verify, a signature by a request key past its `notAfter`, a replayed nonce, a re-encryption to other associated data by an entry not granted `decrypt` and `encrypt` — all the same answer; the log says which |
| `INVALID_ARGUMENT` (400) | `the associated data does not match the ciphertext: …` + ErrorInfo `CIPHERON_ASSOCIATED_DATA` | a format-5 or format-6 ciphertext sent without its associated data, a format-3 or format-4 one sent with some, or associated data over 65 536 bytes ([associated data](#associated-data)). Associated data that is given but wrong is `the ciphertext could not be decrypted`, as any modification |
| | `associated_data without to_associated_data: …` + ErrorInfo `CIPHERON_ASSOCIATED_DATA` | a ReEncrypt (within its profile or across profiles) or a ReEncryptBatch item with a non-empty `associated_data` and an empty `to_associated_data`, refused before anything is decrypted ([associated data](#associated-data)) |
| | `the batch holds more than 4096 items, which no batch may hold: split it` (no ErrorInfo) | a batch of more than 4096 items (`transport.MaxBatchItems`), counted in its wire form and refused before it is decoded: the same answer to every caller, on both protocols, naming no configured limit |
| | `the batch holds <n> items and <b> payload bytes; this cipheron accepts at most …` + ErrorInfo `CIPHERON_BATCH_LIMIT`, metadata `maxItems`, `maxBytes` | a batch over `batch.maxItems` or `batch.maxBytes` (checked after admission, before any key is used) |
| | `a batch holds at least one item` | an empty batch |
| | `the request's size declaration (cipheron-request-bytes) is not one decimal number of bytes, 1 or more` (gRPC; no ErrorInfo) | a gRPC request whose [declared size](#the-declared-request-size) does not parse, or carries more than one value; refused before its message is read (recorded) |
| | `the request message is larger than its declared size (cipheron-request-bytes)` (gRPC; no ErrorInfo) | a gRPC message larger than the size it declared, refused once read (recorded) |
| | `to_tenant and to_auth are cross-profile fields: …` | a ReEncrypt within its profile carrying `to_tenant` or `to_auth` |
| | `the target profile is shared: …`, `the target profile is perTenant: …` | a cross-profile ReEncrypt whose target fields do not fit the target's tenancy |
| | `the profile is shared: a request names no tenant and carries no tenant_key` | a tenant or a blob in a shared profile |
| | `the profile is perTenant: a request names its tenant and carries its tenant_key` | a wrapped profile's request without its tenant or blob |
| | `the profile is perTenant derived: a request names its tenant and carries no tenant_key` | a derived profile's request without a tenant, or with a blob |
| | `to_tenant_key is the blob of the tenant key to re-encrypt under: required in a perTenant wrapped profile` | ReEncrypt without `to_tenant_key` in a wrapped profile |
| | `the profile is not perTenant wrapped: it has no tenant key blobs to create or rewrap` | CreateTenantKey or RewrapTenantKey in a shared or derived profile. The configuration grants `provision` only in a wrapped profile, so a listed caller is refused `PERMISSION_DENIED` before this; it is the handlers' own check |
| | `unknown field <n> in <message>: the request has a field the API does not have` (gRPC; no ErrorInfo) | a request carrying a field the API does not have, `auth` included |
| | `the request is not a valid protobuf message of its RPC's request type` (gRPC; no ErrorInfo) | a gRPC request whose bytes do not decode as its RPC's request message |
| | `the request body's profile differs from the profile in the request path` (HTTP; no ErrorInfo) | an HTTP body naming another profile than the path's `{profile}` |
| | `the request has a query string: the API takes no query parameters` (HTTP; no ErrorInfo) | an HTTP request with a query string |
| | `tenant is not a tenant id: 1 to 2048 bytes of printable ASCII, 0x21 to 0x7E` | |
| | `request_nonce must be 16 random bytes, new for every request` | for an entry with request keys, only once the signature verified; PublicKey: a nonce that is not 16 bytes, none included |
| | `the sealed payload could not be opened` | `enc`/sealed payload does not open (another key, another info string, modified) |
| | `recipient_public_key is not a P-256 public key (an uncompressed point)` | Decrypt |
| | `the ciphertext is not a cipheron ciphertext` | wrong magic, a format byte that is not 3, 4, 5 or 6, or a wrong length; a format the profile's tenancy does not use (3 or 6 in a shared or derived profile, 4 or 5 in a wrapped one) |
| | `the ciphertext could not be decrypted` | the tag fails: modified, another profile, another tenant (derived) |
| | `the ciphertext belongs to another tenant key` | wrapped: the ciphertext's key id is not the blob's |
| | `tenant_key is not a key of this tenant in this profile` | wrapped: a blob that is not one (a blob of a layout version cipheron does not read among them — today any but 1), another tenant's or profile's, or does not open |
| | `the key version of this ciphertext is not available` + ErrorInfo `CIPHERON_KEY_VERSION_UNAVAILABLE` | the ciphertext's master version is not listed, or was withdrawn by its KMS (the KMIP state poll: cipheron's operations guide, section *The KMIP state poll*). Not corruption: listed again, it reads again |
| | `the key version of this tenant key is not available` + ErrorInfo `CIPHERON_KEY_VERSION_UNAVAILABLE` | the blob's wrapping version is not listed, or was withdrawn by its KMS |
| | (gateway) | an unknown JSON field, a body that does not parse |
| `RESOURCE_EXHAUSTED` (429) | `cipheron is at its limit of requests in flight; retry later` + ErrorInfo `CIPHERON_BUSY` + `RetryInfo` (1 s) | **busy**: `maxInFlight` or `maxInFlightPerCaller` reached, or the listener's `memoryBudget` cannot cover the request's reservation (both refused before the request's message or body is read; on HTTP with `Retry-After: 1`); the caller entry's replay cache full (only for a request whose signature verified); a gRPC connection's unread answers stayed at their budget until the stream's deadline |
| | `cipheron has no locked memory for this request's key now; retry later` + ErrorInfo `CIPHERON_BUSY` + `RetryInfo` | busy: no locked memory for a tenant key or a derived key |
| | `cipheron refuses this caller's requests for a while: one of its request messages was larger than its declared size (cipheron-request-bytes); retry later` + ErrorInfo `CIPHERON_BUSY` + `RetryInfo` (the time left) | busy: the caller is in its one-minute cooldown on the listener after a gRPC message larger than it declared ([the declared request size](#the-declared-request-size)); on HTTP 429 with `Retry-After` the seconds left |
| `RESOURCE_EXHAUSTED` (413 on HTTP) | gRPC's own (`grpc: received message larger than max ...`), **no details** | **too large**: a gRPC request message over `maxRequestBytes`. Not busy: no reason, no `RetryInfo`. the Go library tells it by the missing details plus gRPC's wording; any other detail-less `RESOURCE_EXHAUSTED` is `ErrUnavailable` there |
| | `received message larger than max: the request exceeds the listener's maxRequestBytes`, **no details** | too large: a gRPC request that declares a size over `maxRequestBytes`, refused before its message is read; an HTTP body over 4/3 of it plus 4 KiB (refused before it is read when its `Content-Length` says so), or one that decodes to more than it. the Go library: `ErrTooLarge` |
| | `received message larger than max: a request that declares no size (cipheron-request-bytes over gRPC, Content-Length over HTTP) is at most the listener's undeclaredMaxRequestBytes`, **no details** | too large for the [undeclared lane](#the-declared-request-size): a request with no declared size over `undeclaredMaxRequestBytes`. Declare the size to send it. the Go library: `ErrTooLarge` |
| `UNIMPLEMENTED` (405) | `Method Not Allowed` | an HTTP method other than `POST` (`Allow: POST`); gRPC's own `UNIMPLEMENTED` for a method the server does not know |
| | `cipheron reads uncompressed requests only: send the request with grpc-encoding identity (it is ciphertext or a digest, which does not compress)`, no details; for an encoding gRPC does not have, gRPC's own `grpc: Decompressor is not installed for grpc-encoding "<e>"` | a gRPC request sent in an encoding other than `identity`, refused before it is read (recorded) |
| `UNAVAILABLE` (503) | `cipheron is not serving: its keys are wiped` | after shutdown wiped the keys |
| | `cipheron could not hold this request's key now; retry later` + ErrorInfo `CIPHERON_BUSY` + `RetryInfo` | a cached key wiped under the request at every attempt while cipheron is still serving |
| `UNAVAILABLE` (503) | `cipheron cannot record this request in its audit trail now; retry later` + ErrorInfo `CIPHERON_AUDIT_UNAVAILABLE` + `RetryInfo` (1 s) | with `audit.onFailure: refuse`: no place in the audit buffer or a sink failing or stalled (refused before any key is used), or the request's event not recorded by every sink within 5 s (the operation ran and its answer is withheld) (cipheron's configuration reference, section *`audit`*); the Go library: `ErrUnavailable`, retryable |
| `UNAVAILABLE` (503) | `no master key version writes now: this cipheron's clock is before the activateAt of every active version` + ErrorInfo `CIPHERON_NO_WRITER` | a write (an Encrypt or a ReEncrypt whose new ciphertext is a shared or derived profile's, CreateTenantKey, RewrapTenantKey; a wrapped profile's Encrypt and ReEncrypt use the tenant's own key and never ask for the writer) when no master version is in force at this cipheron's clock (stepped back after the start), or when the version that writes was withdrawn by its KMS (the KMIP state poll: cipheron's operations guide, section *The KMIP state poll*; the same answer, and the log says which); reads still work; another replica may serve it |
| `UNAVAILABLE` (503) | `the profile is sealed on this replica: its master key versions did not unseal at the start and are being unsealed again; retry later, or on another replica` + ErrorInfo `CIPHERON_PROFILE_SEALED` + `RetryInfo` (5 s) | only with `unseal.partial` (cipheron's configuration reference, section *`unseal`*): a request to a profile whose master versions did not unseal at this replica's start, from a caller the profile lists (anyone else gets `PERMISSION_DENIED`, as for an unknown profile); the Go library: `ErrProfileSealed`, a kind of `ErrUnavailable`, retryable (cipheron's `multi-cloud-masters` example) |
| `UNAVAILABLE` (503) | `this cipheron process started after the request was signed: sign it again and send it again` + ErrorInfo `CIPHERON_STARTING` + `RetryInfo` (how far the timestamp is before the start, rounded up to a millisecond) | for an entry with request keys, once the signature verified: a timestamp before the instant this cipheron process started (its start barrier: it cannot know whether a process alive before it served the request); nothing is done and the nonce is not recorded, so signing the request again (a new timestamp and nonce) and sending it again is safe for every operation, CreateTenantKey and RewrapTenantKey included; the Go client does so once by itself (when the RetryInfo is at most 1 second and fits the call's deadline); the Go library: `ErrUnavailable` |
| `DEADLINE_EXCEEDED`, `CANCELED` | gRPC's own | a gRPC answer whose stream ended (its deadline, or the client went away) before it was sent |
| `INTERNAL` (500) | `internal error` | anything else, a handler's panic included (on both transports, logged without the request); logged as `cipheron: operation failed` |

The Go client never follows an HTTP redirect (cipheron never answers one: a 3xx at its address is a proxy's, and is
`FAILED_PRECONDITION` there) and reads an HTTP 404 on an operation's route as `UNIMPLEMENTED`.

<a id="the-order-of-checks"></a>

**The order of checks** (the server's admission), none touching a key before the last passed.
**Why an order matters:** each answer tells the caller something, so the checks run in the order that tells the
least — a caller that is not listed learns only "denied", and a party holding a caller's connection but not its
request key learns nothing about which operations the entry is granted or how its requests are shaped.

0. before anything else: a caller in its [cooldown](#the-declared-request-size) → busy; before the request's message is
   read: its [declared size](#the-declared-request-size) → `INVALID_ARGUMENT`
   (malformed), `RESOURCE_EXHAUSTED` (over `maxRequestBytes`), busy (the memory budget); once it is read, a gRPC
   message larger than it declared → `INVALID_ARGUMENT`, or, with no declaration, over `undeclaredMaxRequestBytes` →
   `RESOURCE_EXHAUSTED`; before the request is decoded: a batch of more than 4096 items → `INVALID_ARGUMENT` (the same
   answer to every caller); a batch is then digested only for a caller its profile lists — any other is refused as in step 1, with
   nothing digested;
1. the connection's caller, the profile, the caller's entry in it → `PERMISSION_DENIED` (with `unseal.partial`, a
   profile sealed on this replica asked by a caller it lists → `UNAVAILABLE`, `CIPHERON_PROFILE_SEALED`);
2. for an entry **with** request keys, the request's signature first, before the operation: `auth` present, timestamp
   within `maxSkew`, the signature (either of the entry's keys, over the [request transcript](#request-transcript)) →
   `PERMISSION_DENIED`; then the nonce's length → `INVALID_ARGUMENT`; then the timestamp against the process's start
   → `UNAVAILABLE`, `CIPHERON_STARTING` (nothing is done and the nonce is not recorded); then the replay cache → `PERMISSION_DENIED`
   (seen) or busy (full); then the operation (by the transcript label's grant: RewrapTenantKey is `provision`) →
   `PERMISSION_DENIED`; and only then the tenancy: the request's tenancy shape → `INVALID_ARGUMENT`; the tenant id →
   `INVALID_ARGUMENT`. So a request the entry's key did not sign is refused the same way, after the same work, whatever
   its operation, and a malformed `tenant` or `tenant_key` is `INVALID_ARGUMENT` only for a request the key signed;
3. for an entry **without** request keys: the operation → `PERMISSION_DENIED`, the tenancy as above, then the nonce's
   length;
4. a cross-profile ReEncrypt then admits its **target** on the same connection identity: the target profile lists the
   caller (an unknown or unlisted target is `PERMISSION_DENIED`, the same answer as any); for a target entry with
   request keys, its keys signed `to_auth` (over the target's request transcript: same label, nonce and digest; its own
   skew and replay cache) → `PERMISSION_DENIED`; its entry is granted `import` (the source entry was granted `export`
   instead of `reencrypt`) → `PERMISSION_DENIED`; a move that changes the tenant needs `retenant` in the SOURCE entry →
   `PERMISSION_DENIED`; the target tenant fits the target's tenancy → `INVALID_ARGUMENT`; for a target entry without
   request keys, `to_auth`'s nonce check comes last;
5. a batch is then held to `batch.maxItems` and `batch.maxBytes` → `INVALID_ARGUMENT` (`CIPHERON_BATCH_LIMIT`), before
   any key is used; RewrapTenantKeyBatch's items are judged one by one (tenancy, tenant id), a refusal being that
   item's error;
6. a re-encryption's associated data, before anything is decrypted: over 65 536 bytes, or a non-empty
   `associated_data` with an empty `to_associated_data` → `INVALID_ARGUMENT` (`CIPHERON_ASSOCIATED_DATA`); a
   re-binding (other `to_associated_data`) by an entry not granted `decrypt` on the source and `encrypt` where the new
   ciphertext is made → `PERMISSION_DENIED`; for a ReEncryptBatch, each item's, a refusal being that item's error;
7. the operation itself: open the payload, check and open the blob (only now), decrypt/encrypt/sign, sign the answer.

Which tenant a caller acts for is not one of these checks: cipheron's configuration names no tenant. A request is
bound to its tenant cryptographically — the tenant is in the request digest, in every derived key's label, in every
ciphertext's additional data, in every blob's wrap and in the message a derived profile signs for a tenant — so nothing
made for one tenant opens or verifies as another's.

## The transcript version

Everything cipheron and its clients sign or seal binds a **transcript version** as a 4-byte field at a fixed place:
right after the label in the [request](#request-transcript), [response](#response-transcript) and
[signing-keys](#signing-keys) transcripts, and right after the context string in the [HPKE](#hpke) info of a request
payload and of a Decrypt answer's plaintext. The transcripts are one versioned kind (`wire/transport`,
`catalog.go` and `transcripts.go`): a signer or a sealer builds every transcript under the version the release's policy
**writes** (`transport.WrittenTranscriptVersion(p)`), and a verifier or an opener rebuilds it under each version the
policy **reads**, the written one first, until one verifies or opens. Today the release writes and reads one version, `1`
(`transport.TranscriptVersion`). It is **not negotiated** and travels in **no message**.

**Why the version is bound at all.** A later layout of any of these transcripts would be a later number, so a
signature or a seal made under one layout can never verify or open as another's (domain separation). There is nothing
to downgrade to: an answer signed under a number the client does not read does not verify (the client refuses it as
not the profile's, `ErrServerIdentity` in the Go library), a request signed under a number cipheron does not read is
`PERMISSION_DENIED`, and a payload sealed under another info does not open (`INVALID_ARGUMENT`, `the sealed payload
could not be opened`).

The other numbered layouts carry their own version in their own bytes, each a kind whose versions the release's policy
declares, the one it writes and the ones it reads (`wire/format`): the [key statement](#key-statement), the
[keyset file](#keyset-file), the [tenant key blob](#tenant-key-blob), the [segmented object](#segmented-objects), the [JSON field](#json-fields)
prefix and the ciphertext [format byte](#ciphertext-formats); each writes `1` (the ciphertexts: formats 3 to 6) and,
today, reads only what it writes. A reader picks the layout from the stored or received bytes, never from
configuration. **The API itself** is versioned by its protobuf package, `cipheron.v1` (the gRPC service `cipheron.v1.CipherService`, the JSON
routes `/v1/...`): a new API version would be a new package. How a version of a stored or signed layout is added and
retired: [compatibility.md](compatibility.md).

## Notation

The byte layouts from here on are built from a few fixed pieces:

- `lp(x)`: `x`'s length as 4 bytes big-endian, then `x`. Every transcript below is a concatenation of `lp` fields, so
  no two field lists encode the same bytes. **Why:** without the lengths, the fields `ab`, `c` and the fields `a`,
  `bc` would be the same bytes, and a signature over one would pass for the other.
- `u32(n)`, `u64(n)`: big-endian.
- `||`: concatenation. Strings are their UTF-8 bytes (in practice ASCII: profile names, tenant ids, version ids and
  labels cannot hold anything else).
- `SHA-256`, `HKDF-SHA256-Expand(prk, info, L)` (RFC 5869 §2.3), `HKDF-SHA256(ikm, salt, info, L)` (extract then
  expand), `Ed25519` (RFC 8032, pure), AES-256-GCM with a 96-bit nonce and a 128-bit tag. HKDF turns one secret key into
  as many independent keys as there are distinct `info` strings: that is how cipheron gets a separate key for every
  purpose, derived tenant and ciphertext from the few keys it holds, and stores none of the derived ones.
- Labels all begin `cipheron/v1|`, the protocol's **label namespace** (built in one file, `wire/format/labels.go`): `v1` is the namespace's
  version, not a release's; a later layout of everything under a namespace would be a later version of it, whose
  labels differ within the namespace prefix, before any label text (`cipheron/v2|…` against `cipheron/v1|…`). cipheron's own seal blobs use a namespace of their own,
  `cipheron/seal/v1|`. A tenant key blob's wrap info is the one HKDF info string that begins with a length prefix
  instead.

## HPKE

**What for.** A plaintext to encrypt and data to sign never travel in the clear, not even inside TLS: the client
seals them to the profile's HPKE public key, which only cipheron can open, and cipheron seals a decrypted plaintext to a
one-time key the client made for that one request. So a TLS-terminating proxy, a service-mesh sidecar or another
process that can reach the socket sees only sealed bytes (cipheron's security guide, section *What an intermediary still sees*).
**Why not rely on TLS alone:** TLS protects one hop, and whoever terminates it — a proxy, a mesh — reads everything
inside it; and the socket has no TLS at all. **Why HPKE:** a published standard, with its own test vectors, that
many languages' cryptography libraries implement, so a client in another language needs no cryptography of
cipheron's own.

RFC 9180, single-shot base mode, no AAD, suite **KEM `0x0010` DHKEM(P-256, HKDF-SHA256), KDF `0x0001` HKDF-SHA256,
AEAD `0x0002` AES-256-GCM**. `enc` and public keys are uncompressed P-256 points (65 bytes). The info string binds
every seal to its context:

| sealed | by | to | info |
| --- | --- | --- | --- |
| Encrypt's plaintext, Sign's data | the client | the profile's `hpke_public_key` | `cipheron/v1\|request\|<profile>\|<op>` — `<op>` `encrypt` or `sign`; in a perTenant profile (wrapped or derived) `cipheron/v1\|request\|<profile>\|<op>\|<tenant>` — then `lp(u32(1))`, the [transcript version](#the-transcript-version), and `lp(requester key)` (below) |
| Decrypt's plaintext | cipheron | the request's `recipient_public_key` | `cipheron/v1\|response\|<profile>\|decrypt` — perTenant: `cipheron/v1\|response\|<profile>\|decrypt\|<tenant>` — then `lp(u32(1))`, the transcript version |

A payload sealed for encrypt cannot be signed, opened in another profile or for another tenant, or presented as a
response. ReEncrypt, CreateTenantKey and RewrapTenantKey seal nothing: no plaintext or key travels in them. **Why the
info string names the operation, the profile and the tenant:** a sealed payload copied out of one request cannot be
reused in another kind of request, profile or tenant — data sealed to be encrypted cannot be sent to Sign to have it
signed, nor one tenant's data encrypted under another tenant's key.

**The requester.** A request's info string ends with `lp(requester key)`: the SHA-256 of the Ed25519 request public
key that signs the request (32 bytes), or a zero-length field for a client without a request key — `lp` a 4-byte
big-endian length and the bytes. The two infos are

```
request:  "cipheron/v1|request|<profile>|<op>[|<tenant>]" || lp(u32(1)) || lp(SHA-256(request public key) or "")
response: "cipheron/v1|response|<profile>|decrypt[|<tenant>]" || lp(u32(1))
```

Neither a profile, an operation nor a tenant id holds a `0x00` byte, so the context string ends where the version's
length begins: one info names one (profile, operation, tenant[, requester]).

cipheron opens the payload with the key of the caller entry that **verified** the request's signature (an entry
without request keys: the empty field). A payload one caller sealed does not open in a request another caller signed,
even one granted the same operations in the same profile: it is refused `INVALID_ARGUMENT` (`the sealed payload could
not be opened`) and nothing is encrypted or signed. **Why:** without it, a second caller that saw another caller's
sealed payload could submit it as its own and decrypt the result with its own grant. A consequence: a client that
holds a request key binds every payload to it, so its Encrypt and Sign work only through an entry that lists that key
— an entry without request keys does not know it (Decrypt and the calls that seal nothing are not affected).

## Digests

**What for.** A signature covers a fixed-size SHA-256 digest of the request's (or the answer's) payload fields rather
than the fields themselves, so the [request](#request-transcript) and [response](#response-transcript) transcripts
have one layout for every RPC; the transcript's label says which RPC's fields the digest is of.

```
Digest(f1, ..., fn) = SHA-256( lp("cipheron/v1|digest") || lp(f1) || ... || lp(fn) )
```

| label | request digest fields | response digest fields |
| --- | --- | --- |
| `encrypt` | `enc`, `sealed_plaintext`, `tenant`, `tenant_key` | `ciphertext` |
| `decrypt` | `recipient_public_key`, `ciphertext`, `tenant`, `tenant_key` | `recipient_public_key`, `enc`, `sealed_plaintext` (of the answer) |
| `sign` | `enc`, `sealed_data`, `tenant`, `tenant_key` | `signature`, `key_id` |
| `reencrypt` | `ciphertext`, `tenant`, `tenant_key`, `to_tenant_key` | `ciphertext` |
| `provision` (CreateTenantKey) | `tenant`, empty | `tenant_key`, `signing_public_key`, `fingerprint` |
| `rewrap-tenant-key` | `tenant`, `tenant_key` | `tenant_key`, `signing_public_key`, `fingerprint` |

`tenant` and `tenant_key` are digested even when empty (a zero-length field): a request of one tenancy is never
another's. Digests of one form are told apart by the label they are signed under.

**Fields digested only when present.** A digest of `n + 1`
fields is never one of `n` (the fields are length-prefixed), so a request without these fields is digested exactly as
in the table, and none with them is taken for one without:

| label | appended when | appended fields |
| --- | --- | --- |
| `encrypt`, `decrypt` | `associated_data` is not empty | `associated_data` |
| `reencrypt` | any of `associated_data`, `to_associated_data`, `to_profile`, `to_tenant` is not empty | all four, in that order (empty ones as zero-length fields) |

The batch labels' digests are [their own](#batches).

## Request transcript

**What for.** When a caller entry has request keys, the client signs every request but PublicKey with its request
key. The signature shows that the holder of the key made this request (not merely someone holding the caller's
connection), made it now (the timestamp), and made it once (the nonce, which cipheron remembers in a **replay cache**
for twice the allowed skew plus one second; each process keeps its own, and a process started after the request was signed refuses
it). So an intermediary that holds the caller's network identity can neither forge nor redirect a request, and a
replay is bounded as cipheron's security guide, section *The replay cache* says: at most once by each replica alive at the
request's timestamp, within `maxSkew` (cipheron's security guide, section *Request keys*).

What a caller's request key signs (`auth.signature`):

```
lp("cipheron/v1|signed_request") || lp(u32(1)) || lp(profile) || lp(label) || lp(u64(timestamp_ms))
  || lp(request_nonce) || lp(request digest)
```

`1` is the [transcript version](#the-transcript-version) (a 4-byte field behind its 4-byte length). `label` is the
transcript label of the table above (`rewrap-tenant-key` for RewrapTenantKey). cipheron accepts a request when
`timestamp_ms` is within `requestAuth.maxSkew` of its request clock, the signature verifies under one of the entry's
request keys (one whose `notAfter` has not passed), the nonce is 16 bytes, the entry has not used the nonce within
`2 × maxSkew + 1 s`, and the request was not signed before this process started (`CIPHERON_STARTING`).
Request keys: Ed25519, the private key PEM PKCS #8 (`PRIVATE KEY`), the public key PEM PKIX (`PUBLIC KEY`).
**Why a timestamp and a nonce both:** the nonce alone would make cipheron remember every nonce forever; the timestamp
bounds how long one must be remembered, and the window is `2 × maxSkew` because a timestamp may be off by `maxSkew`
either way (a nonce is kept one second longer, so the two windows never touch:
cipheron's security guide, section *The replay cache*). The default `requestAuth.maxSkew` (30 s) allows ordinary clock drift between hosts
(cipheron's configuration reference, section *`requestAuth`*).

## Response transcript

**What for.** Every answer but PublicKey's is signed by the profile's response key, so a client that pinned the
profile's [identity](#identity-and-fingerprint) accepts an answer only from that profile's cipheron — not from an
impostor on the socket path or behind an accepted certificate —, only for the request it sent itself, and only from a
cipheron on a [key context](#key-context-digest) it accepts.

What the profile's response key signs (`response_signature`, every answer but PublicKey's):

```
lp("cipheron/v1|signed_response") || lp(u32(1)) || lp(profile) || lp(context digest) || lp(label) || lp(request_nonce)
  || lp(requester) || lp(request digest) || lp(response digest)

context digest = the key-context digest of the cipheron that answered, as its PublicKey answer gives it
                 ("sha256:" and 64 lowercase hex digits, the string's bytes). The answer does not carry it: the
                 client verifies under the digests it accepts — the ones it pins, else the ones the profile's
                 verified PublicKey answers gave
requester = SHA-256(auth.signature)  — or EMPTY (a zero-length field, not 32 zero bytes) when the request carried no
            auth or an empty signature
```

cipheron computes the requester over the `auth.signature` it received; the client over the one it sent. The context
digest binds the answer to the key context of the replica that made it: an answer of a replica on a context the
client does not accept — a stale or drifted shared file, a rollout its pins do not name — does not verify, whichever
path carried it. The request
digest binds the answer to the request's payload (an answer to another caller's request under the victim's nonce does
not verify); the requester binds it to who signed it (an insider repeating the victim's fields under its own key gets
an answer that does not verify for the victim). The [transcript version](#the-transcript-version) binds it to this
layout: no answer signed under it verifies as another layout's.

## Identity and fingerprint

**What for.** The fingerprint is a short value — `sha256:` and 64 hex digits — that names a profile's identity. A
client **pins** it: it gets the value out of band (printed by `cipheron keygen`, or mounted by the charts), compares
it with the fingerprint of the keys the server answers, and refuses a server whose keys hash to anything else. That is
what makes every signature on this page worth checking: they verify under keys the pin vouches for. **Why the
identity never rotates:** a pin would break at every rotation. The keys that do rotate — signing keys, master
versions — are vouched for by the identity's response key instead
(cipheron's keys and rotation guide, section *The keys of a profile*).

A profile's identity is its tenancy and the keys that never rotate: the HPKE key and the response key, with the HPKE
key's suite (`hpke_suite`), the response key's algorithm (`response_key_algorithm`) and any key added to the identity
after the profile was made (`additional_identity_keys`, none in a profile cipheron makes: the extension point for a
post-quantum or hybrid key, added to an existing profile instead of a new profile).

The fingerprint has two derivations; which one is decided by the identity. **Derivation 1** — a *classical* identity:
suite `0x0010/0x0001/0x0002`, an Ed25519 response key, no added key (every profile cipheron makes):

```
Fingerprint = "sha256:" || lowerhex( SHA-256( lp("cipheron/v1|fingerprint") || lp(profile) || lp(tenancy)
              || lp(hpke_public_key) || lp(response_public_key) ) )
```

Its derivation fixes the suite and the algorithm, so the value names them. **Derivation 2** — any other identity:

```
Fingerprint = "sha256:" || lowerhex( SHA-256( lp("cipheron/v1|fingerprint2") || lp(profile) || lp(tenancy)
              || lp(suite: u16(kem) u16(kdf) u16(aead)) || lp(hpke_public_key)
              || lp(u32(response algorithm)) || lp(response_public_key)
              || lp(u32(n)) || n × ( lp(u32(role)) || lp(algorithm id) || lp(public key) ) ) )
```

the added keys in canonical order (bytewise ascending of their encodings); `role` 1 HPKE, 2 response; `algorithm id`
the suite (6 bytes) of an HPKE key, `u32(algorithm)` otherwise. The labels differ, so no derivation-2 value is a
derivation-1 value. **For pins:** adding a key to a profile's identity changes its fingerprint (derivation 2): its data
and ciphertexts do not change, and the pin is updated (both fingerprints pinned while it changes); the added key is
covered by the pin itself, never only by a signature of the classical response key.

`tenancy` is its string: `shared`, `perTenantWrapped`, `perTenantDerived` (a configuration writes the two perTenant modes `tenancy: perTenant` with `tenantKeys: wrapped` or `derived`). `cipheron keygen ensure` prints the
fingerprint; a client pins it. Validity rules a client applies to an answer before pinning or comparing: a known
tenancy, a valid P-256 point for the classical HPKE suite (1 to 4096 bytes of key for another suite), a 32-byte
Ed25519 response key, well-formed added keys. A client accepts an identity of a suite or with added keys it does not
implement (it pins it and verifies its lists) and refuses to USE it: sealing a payload to an HPKE suite it does not
implement is `ErrBadResponse` in the Go library. Its response key must be Ed25519 for anything to verify; an answer
whose response key is of another algorithm cannot be authenticated, and is `ErrServerIdentity`.

## Signing keys

**What for.** A shared or derived profile signs with its **signing keys** (a wrapped profile's tenants each have their
own). Unlike the identity they rotate: one key is **active** and signs; older ones stay listed as **verifyOnly** so
their signatures keep verifying; a compromised one is **revoked**, listed so that every signature under it is
refused. Each key has a 16-byte id, which a Sign answer names, so a verifier knows which public key to use. The list
comes in the PublicKey answer, signed by the response key over the request's nonce, so a client always gets the
current list and not one recorded before a revocation
(cipheron's keys and rotation guide, section *Signing-key rotation*).

```
SigningKeyID(pub) = first 16 bytes of SHA-256( lp("cipheron/v1|signing-key-id") || lp(pub) )           Ed25519
SigningKeyIDOf(a, pub) = first 16 bytes of SHA-256( lp("cipheron/v1|signing-key-id2") || lp(u32(a)) || lp(pub) )
                                                                                         another algorithm a

signing-keys transcript
  = lp("cipheron/v1|signed_keys") || lp(u32(1)) || lp(profile) || lp(tenancy) || lp(context_digest)
    || lp(request_nonce of the PublicKeyRequest)
    || lp(u32(k)) || for each key in ascending key_id (bytewise): lp(key_id) || lp(u32(state number)) || lp(public_key)
```

`1` is the [transcript version](#the-transcript-version). The state is its **number** — 1 active, 2 verifyOnly, 3
revoked; a key in any other state refuses the whole list. A key's **algorithm** (`SigningKey.algorithm`, Ed25519) is
bound by its id (`SigningKeyIDOf`), so the transcript — and the key-context digest — cover it without a field of its
own: the extension point for a signing key of another algorithm. A client checks the id against the algorithm
answered, refuses a list with algorithm 0, and keeps a key of an algorithm it does not implement listed and unusable
(the Go library: `Verify` under it is `ErrBadResponse`).

A wrapped profile's list is empty (`k` = 0); the transcript still binds the version, the profile, the tenancy, the
digest and the nonce. `keys_signature` is the response key's Ed25519 signature over it.

A client sends a fresh nonce with every PublicKey request and accepts the answer when:

- the tenancy is one of the three, `hpke_suite` and `response_key_algorithm` are present, and every signing key names
  an algorithm and a state of the three — anything else refuses the whole answer;
- the identity is valid and (first fetch) matches its pin, or (later) equals the one it has;
- `context_digest` is `sha256:` and 64 lower-case hex digits;
- the list is valid — none in a wrapped profile; otherwise 1 to 256 keys, each under its own id (an Ed25519 key 32
  bytes), no id twice, **exactly one** active;
- `keys_signature` verifies under the response key over the transcript with the client's own nonce;
- and the [key statement](#key-statement) verifies against the same identity and says the same digest and keys.

cipheron's own check of what it publishes (and of what a keyset holds) is the same, and also refuses a key of an
algorithm cipheron does not make.

`internal/client` adopts a later list only when it still names every key (same id, same public key) the list it
holds did: a list that forgets a key is not adopted. **A revocation is monotonic in a client:** once it has seen a key
`revoked` in an authenticated list, the key stays revoked for that client's life, whatever a later list says.
`Verify` under a revoked key is `(false, ErrSigningKeyRevoked)`, never `true`; a Sign answer naming a revoked key is
refused. **Maximum key age:** `Verify` fetches the list again when it is older than `WithKeysMaxAge` (default 5
minutes; 5 seconds to 24 hours) and fails closed with `ErrKeysStale` when it cannot — so a revocation takes effect for
a verifier within the rollout time plus that age, and online verification needs cipheron reachable at least once per
that age. Sign judges the key its answer names on a list no older than that age too, refreshed the same way. The age
is a trade-off: a shorter one brings a revocation to verifiers sooner, at the cost of more PublicKey calls and of
needing cipheron reachable more often. The raw-key `cipheron.Verify(pub, data, sig)` knows no state.

## Key-context digest

**What for.** Several cipherons may serve one profile — replicas of a service, or members of a group that share a
profile across clusters or regions — and they must read the same ciphertexts and publish the same keys. The
**key-context digest** is a short value over everything that decides that. Every cipheron publishes it in its
PublicKey answer; a member may pin it (`expectContext`) and then refuses to start on a configuration, keyset or master
key that differs; and a client may pin it too (cipheron's configuration reference, section *`expectContext`*). **Why a digest
rather than comparing configurations:** members are configured per deployment (seals, callers, limits differ), and a
digest covers only what must be equal, in a form any two members, and any client, can compare.

```
ContextDigest = "sha256:" || lowerhex( SHA-256(
    lp("cipheron/v1|context") || lp(profile) || lp(tenancy)
 || lp(u32(n)) || n × ( lp(version id) || lp(KCV) )        — the listed master versions, ascending id (bytewise)
 || lp(keyset fingerprint)
 || lp(u32(k)) || k × ( lp(signing key id) || lp(state) )  — the published signing keys, ascending id;
                                                              state the STRING "published" (an active or a
                                                              verifyOnly key) or "revoked" ) )
```

A signing-key revocation changes the digest (a key's state string changes from "published" to "revoked"); an
activation does not (`signing.active`, `signing.activeGeneration` and `signing.activateAt` move no
digest and no pin).

`KCV` is a master version's [key check value](#key-check-values). Not covered: the versions' states and `activateAt`
(which version writes never changes what can be read), how a version is sealed, any tenant (cipheron's configuration
names none: a tenant is bound per request, inside each ciphertext, blob, derivation and signature), and anything per
service. Two cipherons with one digest read each other's ciphertexts, publish the same signing keys and verify each
other's signatures; during a signing-key activation they may still sign with different published keys, which every
client accepts (D-Q).

## Key check values

```
KCV(master version key, profile, version id) = first 16 bytes of
    HMAC-SHA256( HKDF-SHA256-Expand(master version key, "cipheron/v1|<profile>|kcv", 32), version id )
```

**What for.** A key check value (KCV) lets two cipherons — or a cipheron and the value its keyset recorded — confirm
that they unsealed a master version to the same key, without either revealing the key. **Why it matters:** a version
present under one id on two members but holding two different keys would make each member's ciphertexts unreadable
on the other, and would look like corruption; the recorded KCV catches it at start, and the key-context digest
between members.

Not secret: it tells whether two cipherons unsealed one version to one key and nothing else (a one-way function of
the key, 16 bytes). A keyset records the KCV of master versions (`masterVersions`); cipheron
refuses to start when a listed version unseals to a key whose KCV is not the recorded one, and the key-context digest
covers every listed version's KCV.

## Derived-profile signatures

A derived profile's tenants share the profile's signing keys, so Sign signs a message that names the tenant. **Why:** a
signature over the data alone, under a key every tenant shares, would verify as any tenant's; with the profile and the
tenant inside the signed bytes, it is one tenant's in one profile. (A wrapped profile needs no such message: each tenant
signs with its own key.)

```
TenantSignedMessage = lp("cipheron/v1|tenant-signature") || lp(profile) || lp(tenant) || lp(data)
```

The signature is pure Ed25519 over these bytes, under the signing key `key_id` names. A signature for tenant A never
verifies as tenant B's, nor as another profile's. Worked: commands signed for one device, each verified on its device
offline (cipheron's `iot-device-fleet` example).

## Ciphertext formats

**What for.** A ciphertext is what your application stores in place of the plaintext. Its header names what is needed to
decrypt it again — the master version (format 4), or the tenant key (format 3) — so data written before a rotation stays
readable for as long as its key is listed, and a sweep can find the rows still under an old key without decrypting
anything. **Why a fresh 32-byte salt in every ciphertext:** each ciphertext's AES key is derived from the data key and
its own salt, so no two ciphertexts share an AES-GCM key. A data key may serve for a long time, and NIST SP 800-38D
(§8.3) bounds one AES-GCM key with random 96-bit nonces to 2^32 encryptions — a bound a busy profile could pass and a
stateless process could not count.

Every ciphertext begins `"CPH1"` and a format byte and ends with the GCM nonce (12), the ciphertext and the tag (16)
(`nonce || ct || tag`, the nonce drawn inside the module). The salt is 32 random bytes. A client needs only the header
(`cipheron.KeyID`, `transport.ParseKeyID`); only cipheron, which holds the keys, opens the rest (the layouts are declared once, as data, in `wire/transport/catalog.go`, and sealed by the one suite,
`format.HKDFSHA256AESGCM` in `wire/format/suite.go`). The
four formats are the two tenancies' layouts, each without and with caller associated data, and all four are written
and read ([compatibility.md](compatibility.md#the-ciphertext-formats) gives each header byte by byte). **One
algorithm:** every ciphertext is AES-256-GCM under its own HKDF-SHA256-derived key, and no setting chooses another.
The algorithm is not a header field of its own: each format byte names one fixed pairing of a layout and its
algorithms (formats 3 to 6: an HKDF-SHA256 per-ciphertext key and AES-256-GCM), and the byte is authenticated — the
header is part of the AEAD's additional data — so the stored bytes alone tell, offline (`KeyID.Format`), which
algorithm a row needs, and a changed byte fails the tag. Another approved algorithm would come as format bytes of its
own, never as a setting that changes what an existing byte means, and would derive its keys under a label namespace of
its own: the suite derives only under its own namespace and the catalog refuses a second suite owning the same one, so no key is
ever used under two algorithms.

<!-- format:ciphertext-layouts -->
| format | layout | written by | overhead |
| --- | --- | --- | --- |
| 3 | `"CPH1" \| 0x03 \| tenant key id (16) \| salt (32) \| nonce \| ct \| tag` | a perTenant wrapped profile | 81 |
| 4 | `"CPH1" \| 0x04 \| len (1) \| master version id (len) \| salt (32) \| nonce \| ct \| tag` | a shared or perTenant derived profile | 67 to 98 (version id 1 to 32 bytes) |
| 5 | format 4's layout with format byte `0x05` | a shared or derived profile, with [associated data](#associated-data) | as 4 |
| 6 | format 3's layout with format byte `0x06` | a perTenant wrapped profile, with associated data | 81 |
<!-- /format -->

The header is everything before the nonce. Per-ciphertext key and additional data (cipheron's side):

<!-- format:ciphertext-keys -->
| format | AES-256 key | AAD |
| --- | --- | --- |
| 3 | `HKDF-SHA256-Expand(storage key, "cipheron/v1\|<profile>\|<tenant>\|message" \|\| salt, 32)` | header (53) `\|\|` lp(profile) `\|\|` lp(tenant) |
| 4 | `HKDF-SHA256-Expand(data key, "cipheron/v1\|<profile>\|message4\|" \|\| lp(version id) \|\| lp(tenant) \|\| salt, 32)` | header `\|\|` lp(profile) `\|\|` lp(tenant) (tenant empty in a shared profile) |
| 5 | as format 4 | header `\|\|` lp(profile) `\|\|` lp(tenant) `\|\|` lp(associated data) |
| 6 | as format 3 | header `\|\|` lp(profile) `\|\|` lp(tenant) `\|\|` lp(associated data) |
<!-- /format -->

The format-4 data key is the storage data key of the version in a shared profile, the tenant's storage key of the version
in a derived one ([derivations](#data-key-derivations)). A changed version or salt, another profile or another tenant
fails the tag. Format 3's key id is checked against the blob's before anything is opened.

`KeyID` (what `cipheron client key-id` prints): `tenant-key:<hex id>` (formats 3 and 6: the blob it needs), `<version>`
(formats 4 and 5); its `AssociatedData` is true for formats 5 and 6. Reading the header proves nothing: it is
authenticated when cipheron opens the ciphertext. A ciphertext with the right magic and a format byte that is not 3, 4,
5 or 6 is `transport.ErrCiphertextFormat` (it wraps `ErrCiphertext`), which the Go library reports as `ErrInvalidInput`;
an Encrypt or ReEncrypt answer in such a format is refused (`ErrBadResponse`), so nothing is stored that the client
could not send back.

## Associated data

A request may carry caller **associated data** (`associated_data`; 1 to 65 536 bytes, empty: none): context, not a
secret — a row's primary key, a record type, a column name. It is bound into the ciphertext's AEAD and **never
stored** in it: the application gives it again at every Decrypt. **What for:** it ties a ciphertext to where it
belongs. Without it, anyone who can write to the database could copy one row's ciphertext into another row (another
customer's, another column), and the application would decrypt it there as if it were that row's value.

- With associated data Encrypt answers **format 5** (shared, derived) or **6** (wrapped): format 4's or 3's layout
  under its own format byte, which records that the ciphertext needs associated data. The AEAD's additional data is
  the format's own followed by `lp(associated data)`; the key derivation is unchanged. Without it, Encrypt answers
  format 4 or 3.
- Decrypt (and ReEncrypt's `associated_data`) of format 5 or 6 **without** associated data, or of format 3 or 4
  **with** some, is refused before any key is used: `INVALID_ARGUMENT`, `CIPHERON_ASSOCIATED_DATA`. A client checks
  the format byte first and refuses it itself (`ErrAssociatedData`). With **other** associated data the tag fails:
  `the ciphertext could not be decrypted` — never other data. A ciphertext copied from one row to another, whose key
  is its associated data, does not decrypt there.
- ReEncrypt takes the stored ciphertext's associated data (`associated_data`) and the new ciphertext's
  (`to_associated_data`; empty: the new one is made without). **A re-encryption never drops it:** a non-empty
  `associated_data` with an empty `to_associated_data` is refused before anything is decrypted, `INVALID_ARGUMENT`,
  `CIPHERON_ASSOCIATED_DATA`, `associated_data without to_associated_data: …` — within a profile, across profiles, and
  per ReEncryptBatch item. The fields are proto3 `bytes`, which have no presence, so the rule is on emptiness: send
  the same bytes as `to_associated_data` to keep the binding; none on either side is served. **Why:** a sweep that
  forgot the new ciphertext's would make a ciphertext bound to nothing, which decrypts only without associated data:
  the binding would be gone without a word. A client library whose helpers add a binding of their own (a JSON field's
  record and pointer, a segment's object and position) always sends a non-empty `associated_data`, so cipheron cannot
  see a missing caller part there: the library checks it before sending
  ([client-library.md](../docs/client-library.md#a-re-encryption-never-drops-the-associated-data)).
- **A re-encryption keeps the binding unless the caller may re-bind:** other bytes as `to_associated_data`, or
  `to_associated_data` where the stored ciphertext has none, is a **re-binding**, served only for an entry granted
  `decrypt` on the source profile and `encrypt` where the new ciphertext is made (the same entry and profile within a
  profile) — what the caller could do by hand, decrypt then encrypt. Otherwise it is `PERMISSION_DENIED`, decided after
  admission and before anything is decrypted; `reencrypt`, `export` and `import` alone never re-bind. **Why:** a
  re-binding moves a value to another row, record, object position or tenant, which a migration sweep never needs.
  The audit event of a re-encryption records whether it changed the associated data (`associated_data_changed`),
  never the bytes.
- In the request digest `associated_data` is a field only when present ([digests](#digests)); it is never logged and
  never in a metric.

Worked: a value bound to its table, row and column
(cipheron's `database-columns-associated-data` example).

## Key statement

`PublicKeyResponse.key_statement` is the profile's **key statement**: what cipheron states about its keys — the
identity, tenancy, key-context digest and signing keys with their states and algorithms — at the time it issued it,
**without a nonce**, so it can be published and checked offline by anyone holding the profile's pinned fingerprint.
**What for:** a party that verifies the profile's signatures but cannot, or should not, call cipheron — a partner, an
auditor, a service in another network — gets the signing keys from a document cipheron itself signed, rather than
from whoever passed them on. `key_statement_signature` is the response key's Ed25519 signature over its bytes:

```
lp("cipheron/v1|key_statement") || lp(u32(1)) || lp(profile) || lp(tenancy) || lp(u64(issued_at ms)) || lp(context_digest)
  || lp(suite: 6 bytes) || lp(hpke_public_key) || lp(u32(response algorithm)) || lp(response_public_key)
  || lp(u32(n)) || n × ( lp(u32(role)) || lp(algorithm id) || lp(public key) )            added keys, canonical order
  || lp(u32(k)) || k × ( lp(key_id) || lp(u32(state number)) || lp(u32(algorithm)) || lp(public_key) )
                                                                                          ascending key_id
```

Verifying it (`transport.VerifyKeyStatement`): parse every field and nothing after, in canonical form (the bytes are
exactly the encoding of what was read); the profile inside is a profile name (`transport.ValidProfile`) and the one
expected; the identity inside has the **pinned** fingerprint; the response key inside is Ed25519 and the signature is
its. A client checks the statement of every PublicKey answer this way and requires it to be the fresh answer's (the
same identity, digest and keys). **It proves no freshness:** a recorded statement verifies forever, so a verifier
bounds its age by `issued_at` (cipheron's clock) and keeps any revocation it once saw. The Go client's `KeyStatement`
hands out only a statement whose signing keys, states included, are the list it holds — so never one listing as usable
a key it holds revoked (a replica lagging a revocation answers one) — and only while it is younger than
`WithKeysMaxAge`; otherwise it is `ErrSigningKeyRevoked` or `ErrKeysStale`. Its `Verify` checks a shared profile's
signature and `VerifyTenant` a derived profile's: a statement of the other tenancy is `ErrTenancy`, with nothing
verified. The Go client exports it (`KeyStatement.Export`: JSON
`{"format": "cipheron-key-statement/1", "profile", "fingerprint", "statement", "signature"}`, base64), imports it
offline (`ImportKeyStatement(exported, profile, pinnedFingerprint, maxAge)` — the pin is the verifier's, never the
document's), and views it as a JWKS (a JSON Web Key Set, RFC 7517; OKP Ed25519 keys, RFC 8037; `kid` the hex key id,
`alg` `EdDSA`) of the ACTIVE and VERIFY_ONLY keys only — a JWKS cannot say "revoked", so revoked keys (and keys of an
algorithm the client does not implement) are left out. Worked: a counterparty's verifier
(cipheron's `contract-signing-service` example).

## Cross-profile ReEncrypt

ReEncrypt with `to_profile` (not empty, not the request's own profile) decrypts the ciphertext in the request's profile
and encrypts the plaintext in `to_profile`, **in one call, inside one cipheron**: the plaintext never leaves it. It is
how a ciphertext moves when its profile must be replaced (an identity compromise, a tenancy change, a residency move, a
new algorithm generation).

- **Grants.** Moving a ciphertext out of a profile is its own grant, **`export`**, on the source
  profile; taking one in is **`import`**, on the target profile. `reencrypt` re-encrypts within its profile only: an
  entry granted `reencrypt` on both profiles — or `reencrypt` on the source and `decrypt` on the target, which would
  let a caller that may only re-encrypt the source's data read it in the target — is refused (`PERMISSION_DENIED`). A
  migration job holds `export` and `import`, never `decrypt`. **Why separate grants:** a grant to re-encrypt in place
  must not quietly become a way to carry data into a profile where someone else may decrypt it, so each profile's
  configuration must allow its own side.
- **A change of tenant is a third grant, `retenant`, on the source profile.** A move changes the tenant when both
  profiles are perTenant and the target tenant is not the source's, or when one profile is shared and the other perTenant
  (either way). Such a move needs `retenant` in the source entry, besides `export` there and `import` on the target;
  without it, `PERMISSION_DENIED`. A move between two shared profiles, or one that keeps its tenant between two perTenant
  profiles (derived ones too), needs no `retenant`. **Why:** `export` and `import` move a record, and keep its tenant.
  Their holder cannot read the record, but without this rule it could re-bind tenant A's record to tenant B's key in
  the other profile, where B's readers open it. Whether a tenant's data may become another tenant's is the source
  profile's owner's decision. cipheron decides it with the other grants: after the source's admission, right after the
  target's `import` (and so after `to_auth` for a target entry with request keys), and before the target's tenancy
  and anything opened or unwrapped. Its refusal is logged and audited as a missing
  `export` or `import` is, under the grant's name.
- The source side is admitted as any ReEncrypt of its profile (its tenant and its ONE blob, `tenant_key`), its entry
  granted `export`.
- The target side is then admitted on the same connection identity: `to_profile` lists the caller; when that entry
  has request keys, `to_auth` is first a signature by one of them over the request transcript **of `to_profile`** (the
  same label `reencrypt` — `export`, `import` and `retenant` are grants, never transcript labels — and the same
  timestamp rules, nonce and request digest), held to that entry's skew and replay cache; then its entry is granted
  `import`. The target tenant is `to_tenant` (empty: the request's tenant, for a perTenant target); a wrapped target takes
  `to_tenant_key`. A target that is unknown, does not list the caller, or does not grant it `import` is
  `PERMISSION_DENIED`, as any authorization failure (and so is a source that does not grant `export`, or a change of
  tenant whose source does not grant `retenant`).
- Within a profile (`to_profile` empty or the profile itself) `to_tenant` and `to_auth` are refused: a ciphertext never
  moves to another tenant of its profile.
- The answer carries `response_signature` by the source profile's response key and `to_response_signature` by the
  target's, each over the response transcript under its own profile (the same nonce, requester, request digest and
  response digest). A client verifies both, against both profiles' identities.
- The request digest is `reencrypt`'s with the extension group ([digests](#digests)): `to_profile` and `to_tenant` are
  in it, so the request cannot be redirected.

Worked: two profiles merged by a migrator (cipheron's `cross-profile-migration` example: shared to
shared, no `retenant`), a file shared into another tenant's key in a second profile
(cipheron's `secure-file-sharing-between-tenants` example: `retenant`), and accounts
moved between a wrapped and a shared profile
(cipheron's `premium-tenants-dedicated-profiles` example: `retenant` on both sides).

## Batches

EncryptBatch, DecryptBatch, ReEncryptBatch and RewrapTenantKeyBatch are the single operations over a list of items:
**one** nonce, auth and response signature for the batch, a result per item. **What for:** many small items — the
rows of a page, a re-encryption sweep, the segments of a large object — in one round trip with one signature each
way, instead of one request per item; and since each item has its own result, one bad ciphertext does not fail the
others.

- **Authorized as the single operation** (`encrypt`, `decrypt`, `reencrypt`, `provision`), under transcript labels of
  their own (`encrypt-batch`, `decrypt-batch`, `reencrypt-batch`, `rewrap-tenant-key-batch`).
- **One scope for the data batches:** `tenant` and `tenant_key` (and ReEncryptBatch's `to_tenant_key`,
  DecryptBatch's `recipient_public_key`) are the batch's, for every item. RewrapTenantKeyBatch's items each name their
  tenant and blob (a rewrap sweep crosses tenants): each item's tenant is checked as RewrapTenantKey's request is, a
  refusal being that item's error.
- **Per-item results:** each result is the single answer's fields, or an `ItemError { code, reason, message }` — the
  status the single operation would have answered (a ciphertext that does not decrypt, a key version not listed,
  associated data, another tenant key, an item's tenant that is not a tenant id). A failure of the whole request
  (authorization, the limits, busy, keys wiped, no writer, an internal error) is the RPC's answer; no result is
  returned then.
- **Limits** (`batch.maxItems`, default 128; `batch.maxBytes`, default 16 918 211 bytes): checked after admission and before any
  key is used; `CIPHERON_BATCH_LIMIT` names them, so a client can split the batch and send it again. Before any of
  that, a batch's items are counted in its wire form, before it is decoded: more than 4096
  (`transport.MaxBatchItems`, which no `batch.maxItems` may exceed) is refused with one answer for every caller,
  `INVALID_ARGUMENT` without ErrorInfo ([Errors](#errors)); and its items are digested only for a caller the profile
  lists, so a caller it does not list is refused with nothing digested, at any count.
  `batch.maxBytes` counts the sum of the lengths of its payload fields (`transport.BatchBytes`): the request's tenant
  key blobs and DecryptBatch's recipient key, and per item EncryptBatch `enc` + `sealed_plaintext` +
  `associated_data` (a plaintext of n bytes is n + 81 once sealed), DecryptBatch `ciphertext` + `associated_data`,
  ReEncryptBatch `ciphertext` + `associated_data` + `to_associated_data`, RewrapTenantKeyBatch `tenant` +
  `tenant_key`; the field names, nonces and auth are not counted (the listener's
  `maxRequestBytes` bounds the whole message). **Why 16 918 211 bytes by default:** it equals the default
  `maxRequestBytes` — 16 MiB and the 140 995 bytes a request carrying one segment of 16 MiB (the largest segment
  size) adds to it — so a batch the default listener admits also fits the batch limit, and a segmented object of any
  segment size is served by default (cipheron's configuration reference, section *`batch`*).
- **Digests:**

```
request digest  = BatchDigest( item digest 0, item digest 1, … )
                  item digest: the single operation's request digest of the item's fields with the batch's scope —
                  EncryptDigestAAD(enc, sealed_plaintext, tenant, tenant_key, associated_data),
                  DecryptDigestAAD(recipient_public_key, ciphertext, tenant, tenant_key, associated_data),
                  ReEncryptDigestExt(ciphertext, tenant, tenant_key, to_tenant_key, {associated_data, to_associated_data}),
                  RewrapTenantKeyDigest(item tenant, item tenant_key)
response digest = BatchDigest( result digest 0, … )
                  result digest: Digest(0x00, the single answer's response fields) — or, for an item error,
                  Digest(0x01, u32(code), reason, message)
BatchDigest(d0, …, dn-1) = Digest( u32(n), d0, …, dn-1 )
```

Every item of an EncryptBatch is sealed as an Encrypt's payload (info `…|encrypt`, the requester); every plaintext of a
DecryptBatch answer is sealed to the one `recipient_public_key` under Decrypt's response info. Worked, with the limits
and the per-item errors: cipheron's `batch-high-throughput` example.

## Segmented objects

An object larger than one request is a **segmented object**, a client format over ordinary ciphertexts (cipheron sees
only batches of ciphertexts with associated data). **Why segments:** a request is bounded by the listener's
`maxRequestBytes` (16 918 211 bytes by default: one segment of the largest size, 16 MiB, fits), so a file of any size
is cut into segments, each encrypted as one batch item;
the associated data below makes the segments one object again, in one order:

<!-- format:segmented-object -->
```
"CPS1" | 0x01 | object id (16) | segment size (4) | count (4)
```
<!-- /format -->

The object id is 16 random bytes; the segment size and the count are big-endian 32-bit numbers. Then come `count`
segments, each `u32(length) || ciphertext`:

```
segment i's associated data = lp("cipheron/v1|segment") || lp(object id) || lp(u32(i)) || lp(final: 0x01 for the last
                              segment, 0x00 otherwise) || lp(the caller's associated data)
```

A reader decrypts segment `i` of a container with the associated data of position `i` of that container
(`final` = `i == count - 1`) and checks the sizes the header names (every segment but the last holds exactly the
segment size). So a segment moved (another index), a container truncated (its new last segment was not made final),
extended or spliced with a segment of another object (another object id) or of another position does not decrypt
(`ErrSegmented`). Segment sizes are 1 KiB to 16 MiB (64 KiB by default), at most 2^20 segments; the caller's
associated data of an object is at most 65 476 bytes (65 536 less the 60 the segment fields add).

A **stream** reader or writer (the Go library's `EncryptStream`/`DecryptStream`) uses the same bytes: a writer that
knows the object's size up front writes the header first and then each segment as its batch is encrypted; a reader
reads the header, then segment after segment (a segment's length is at most the segment size plus 1 KiB, anything
longer is refused before it is allocated), and refuses bytes after the last segment. Worked, with each of these
tamperings refused: cipheron's `large-objects-streaming` example.

## JSON fields

A **JSON field** is a client convention over ordinary ciphertexts with associated data: a field of a JSON document,
named by its JSON Pointer (RFC 6901, a path such as `/customer/iban`), encrypted alone. **What for:** only the
sensitive fields of a document are encrypted, and the rest stays readable where it is stored; the associated data
keeps each encrypted field at its place in its record. The convention is published so that a reader in another
language reads the same documents.

```
plaintext       = the field's value as compact JSON (any JSON type)
associated data = lp("cipheron/v1|json-field") || lp(record id) || lp(JSON Pointer) || lp(the caller's associated data)
value written   = the JSON string "cipheron:v1:" || base64(ciphertext)   (standard alphabet, padded)
```

The record id is the record's own identity as the application stores it (1 to 1024 bytes of UTF-8). A field decrypts
only at the pointer and in the record it was made for. A reader refuses a value at an encrypted field's place that is
not such a string (a field put back in clear), and never passes it through. `cipheron:v1:` is the prefix of the
version written; a reader takes a value as an encrypted field when it opens with exactly the prefix of a version the
release reads for the JSON field — today only `cipheron:v1:` (`cipheron:v01:` is not version 1's) — and refuses it otherwise
(the Go library's `IsJSONField`). The whole associated data is at most 64 KiB. Worked: cipheron's `json-field-encryption` example (a document's fields, and their sweep).

## Tenant key blob

**What for.** In a perTenant wrapped profile every tenant has keys of its own — a storage key and an Ed25519 signing
key — and cipheron keeps no state. So it hands the tenant's keys to the application **wrapped** (encrypted) under the
profile's tenant-wrapping key, as a **blob** the application stores with the tenant's record and sends with every
request for that tenant. Only cipheron can open it. **Why this way:** the tenant's keys live and die with the
tenant's record — deleting every copy of the blob, older rewrapped ones included, makes everything encrypted under
it unreadable for good (cipheron's tenancy guide, section *Erasure*) — and cipheron needs no database of its own. **Why not a
derived profile instead:** a derived tenant's keys can always be computed again from the profile's master versions, so
one tenant's data cannot be erased on its own (cipheron's tenancy guide, section *Choosing*).

The blob, layout version 1 (what CreateTenantKey and RewrapTenantKey make; today the one layout written and read):

<!-- format:tenant-key-blob -->
```
"CPT1" | 0x01 | key id (16) | lp(profile) | lp(tenant) | signing public key (32)
       | len (1) | wrapping master version id (len) | created (8)
       | salt (32)
       | nonce | ct | tag: AES-256-GCM of the 96-byte plaintext, exactly 124 bytes
```
<!-- /format -->

`created` is a big-endian 64-bit count of Unix seconds, after 1970. The sealed plaintext is the tenant's storage key
(32) and its Ed25519 private key (64); the nonce (12) is drawn inside the module and the tag is 16 bytes.

Profile a profile name (lower-case letters and digits in hyphen-separated words, starting with a letter, 1 to 63 bytes:
`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, `transport.ValidProfile`), tenant a tenant id, version id 1 to 32 bytes of
`[A-Za-z0-9._-]`; exactly 124 bytes follow the header. A blob is `226 + len(profile) + len(tenant) + len(version id)`
bytes, at most 2369 (`transport.MaxTenantKeyLen`).
The version byte is `1`; a blob of a version cipheron does not read (today any but 1), or with a creation time of 0 or
before 1970, is refused (`transport.ErrTenantKey`). The version names one fixed pairing of the layout and its
algorithms — version 1: an AES-256-GCM wrap, under a key of the blob's own, of the storage key and an Ed25519 signing
key — so the stored bytes alone tell, offline (`ReadTenantKey`'s `Version`), which algorithms a blob needs. The header
(everything before the nonce, the version and the salt included) is the additional data: a blob whose version, key
id, profile, tenant, public key, wrapping version, creation time or salt was changed does not open. `created` is the tenant key's creation time, which a rewrap keeps, so a service can
apply its own interval to tenant keys.

Wrapping key:

```
HKDF-SHA256-Expand(tenant-wrapping data key of the wrapping version, WrapInfo, 32)
WrapInfo = lp("cipheron/v1|tenant-blob-wrap") || lp(profile) || lp(tenant) || lp(version id) || salt (32)
```

`WrapInfo` is `format.TenantBlobWrapInfo`. The salt is 32 random bytes from `crypto/rand`, new for every blob (a
rewrap draws a new one), so every blob is wrapped under an AES key of its own, used once. `WrapInfo` begins with a length prefix (first byte `0x00`) where every
other HKDF info string cipheron uses begins with `cipheron/`, so it is none of them under any key. Opening a blob
recomputes the signing public key from the private key and compares it with the header's. Fingerprint (what a client
pins with `WithTenantFingerprint`; a rewrap keeps it):

```
TenantFingerprint = "sha256:" || lowerhex( SHA-256( lp("cipheron/v1|tenant-fingerprint") || lp(profile) || lp(tenant)
                    || lp(key id) || lp(signing public key) ) )
```

The header is readable by anyone and **not authenticated** until cipheron opens the blob.

## Data key derivations

Inside cipheron; no client needs them, but they define what "rotation" means. A master version's key never encrypts data
itself: cipheron derives from it a **data key** per purpose, and from that each ciphertext's (or blob's) own key. **Why
this way:** a new master version needs only one new key in the KMS, and gives new data keys with no key to distribute;
every older data key can be derived again for as long as its master version is listed, so old data stays readable with
nothing stored.

```
data key (version, purpose) = HKDF-SHA256-Expand(master key of version, "cipheron/v1|<profile>|<purpose>", 32)
    purpose: storage (shared: format-4 keys), tenant-root (derived), tenant-wrap (wrapped: the blobs' wrapping keys)

derived tenant storage key = HKDF-SHA256-Expand(tenant-root data key of version,
                             "cipheron/v1|<profile>|tenant-storage|" || lp(tenant), 32)
```

The master version id is not in the label: each version is a key of its own (two versions unsealing to one key are
refused). Every data key is derived again on demand; nothing is stored.

## Keyset file

**What it is.** A profile's **keyset** is the file that holds its identity keys and signing keys, encrypted —
**wrapped** — under a master key version from the KMS; cipheron opens it at start. The operator's tooling (`cipheron
keygen ensure`) writes it, and it may be kept in a repository or a Kubernetes Secret: the public parts are readable,
the private parts open only with the master key. This layout matters to someone who audits or reimplements that
tooling, not to a client (cipheron's keys and rotation guide, section *The keys of a profile*).

JSON, at most 128 KiB, one object and nothing after it, unknown fields refused, and exactly the bytes `keygen` writes:
a member written twice, other spacing or member order, or a raw U+2028, U+2029 or U+0085 inside
a string is refused at every read. The file is written in a **keyset version**: each
version is its own JSON, its own wrap additional data and the key types it holds, and a release reads one or more
versions and writes one. Version **1** is the version written and, today, the only one read; it names no key type
(its keys are an HPKE DHKEM(P-256) key, an Ed25519 response key and Ed25519 signing keys). A file of a version
cipheron does not read is refused (`keyset version <n>; this cipheron reads version 1`), and so is one with no
`version` member (`not a keyset file: it has no version member`). How a version is added:
cipheron's guide to adding a keyset version.

```json
{
  "version": 1,
  "kind": "shared",
  "profile": "credentials",
  "created": "2026-11-09T10:00:00Z",
  "hpkePublicKey": "<base64, 65 bytes>",
  "responsePublicKey": "<base64, 32 bytes>",
  "signingKeys": [ { "keyId": "<base64, 16 bytes>", "state": "revoked", "publicKey": "<base64, 32 bytes>" },
                   { "keyId": "<base64, 16 bytes>", "state": "active", "publicKey": "<base64, 32 bytes>" } ],
  "wrappingVersion": "v2",
  "masterVersions": [ { "id": "v1", "kcv": "<base64, 16 bytes>" }, { "id": "v2", "kcv": "<base64, 16 bytes>" } ],
  "fingerprint": "sha256:<hex>",
  "wrapped": "<base64>"
}
```

- `kind`: `shared`, `perTenantWrapped`, `perTenantDerived`. `signingKeys`: shared and derived only, 1 to 256,
  exactly one `active`, the others `verifyOnly` or `revoked`. A **revoked** key stays listed with its public key (so a
  refusal can name it); its private key is not in the wrap. `created` is not authenticated. `fingerprint` is the
  [fingerprint](#identity-and-fingerprint) of the profile's identity, and must match it.
- `masterVersions` records, sorted by id, the [key check value](#key-check-values) of master versions as `keygen`
  saw them: the wrapping version's always, and every version the configuration listed when `keygen profile`, `rewrap`
  or `record-versions` wrote the file. A recorded value is never changed.
- `wrapped` = `nonce || AES-256-GCM(plaintext) || tag` under
  `HKDF-SHA256-Expand(master version key, "cipheron/v1|<profile>|keyset-wrap", 32)`, with additional data
  `lp("cipheron/v1|keyset-header") lp(u32(1)) lp(kind) lp(profile) lp(hpkePublicKey) lp(responsePublicKey)
  lp(u32(k))` then per signing key, in the file's order, `lp(keyId) lp(state) lp(publicKey)`, then
  `lp(wrappingVersion) lp(u32(m))` then per recorded version, ascending id, `lp(id) lp(kcv)`. The plaintext:
  `lp(HPKE scalar, 32) lp(response private key, 64)`, then `lp(signing private key, 64)` of each signing key that is
  not revoked, in the file's order — 68 bytes shorter per revoked key. **Why the public fields are additional data:**
  the file's version, public keys, states and recorded check values are readable, and binding them to the wrap makes
  any edit of them — a key swapped, a state changed (a `revoked` edited back to `verifyOnly` among them) — a file that
  does not open.

## Doing it by hand, in another language

The steps of a client, in order. Every check named here matters: a check left out is a gap that an impostor, or a
party in the path, can use — the [conformance kit](#conformance-kit) holds the computations to the vectors, and its
test server can answer the way an impostor would, to prove the checks.

1. **PublicKey** (`profile`, a fresh 16-byte `request_nonce`): check the tenancy is one of the three, `hpke_suite` and
   `response_key_algorithm` are present and the ones you implement (else do not use the profile), and every signing
   key's state is 1, 2 or 3; validate the identity; compute its fingerprint and compare it with the one `keygen ensure`
   printed (or **trust on first use**: keep the first identity you see and refuse any later one — weaker than a pin
   given out of band, because the very first answer could already be an impostor's); validate the signing-key list and
   verify `keys_signature` under `response_public_key` over the signing-keys transcript with your nonce; check the
   [key statement](#key-statement) against your pin and the answer, and bound its age: refuse one whose `issued_at`
   is older than your own maximum age (the statement carries no nonce, so a recorded one verifies forever). Keep the
   identity, the list and the context digest. Fetch the list again when it is older than your own maximum age before
   you rely on a key's state.
2. **Encrypt**: HPKE-seal the plaintext to `hpke_public_key` with info `cipheron/v1|request|<profile>|encrypt`
   (`|<tenant>` in a perTenant profile) followed by `lp(u32(1))` and `lp(SHA-256(your request public key))` (a
   zero-length field without a request key: [HPKE](#hpke)); draw a 16-byte nonce; compute the request digest
   `Digest(enc, sealed, tenant, tenant_key)`; with a request key, sign the request transcript (the version `1`, label
   `encrypt`, now in ms). Verify `response_signature` over the response transcript (the context digest one you
   accept: pinned, else one the profile's verified PublicKey answers gave; requester = SHA-256 of the signature you
   sent, empty if none; response digest `Digest(ciphertext)`). Check the ciphertext: format 4 (shared,
   derived) or 3 under the blob's key id (wrapped), of length plaintext + overhead; any other format is refused. Store
   it.
3. **Decrypt**: generate a P-256 key pair for this request; send its public key (65 bytes), the ciphertext, a nonce
   and the auth (request digest `Digest(recipient, ciphertext, tenant, tenant_key)`); verify the response signature
   (response digest `Digest(recipient, enc, sealed_plaintext)`); HPKE-open with the private key and info
   `cipheron/v1|response|<profile>|decrypt` (`|<tenant>`) followed by `lp(u32(1))`; drop the key pair.
4. **Sign**: as Encrypt with label/op `sign`; verify the response signature (response digest
   `Digest(signature, key_id)`); then verify the signature yourself: shared, over the data under the listed key
   `key_id` names (fetch the list again if the id is new: a signing rotation); derived, over `TenantSignedMessage`;
   wrapped, over the data under the blob's signing public key, `key_id` being the blob's key id. Store the signature
   **and** its key id.
5. **Verify** offline: Ed25519 under the listed key the stored key id names (derived: over `TenantSignedMessage`) —
   only if that key's state is 1 (active) or 2 (verifyOnly). A key in state 3 (revoked) verifies nothing.
6. **ReEncrypt** (label `reencrypt`, request digest `Digest(ciphertext, tenant, tenant_key, to_tenant_key)`, response
   digest `Digest(ciphertext)`): check it as Encrypt's (for the plaintext length the old ciphertext implies); the new
   ciphertext replaces the old. With `associated_data`, send the same bytes as `to_associated_data`: cipheron refuses
   one without the other, and other bytes are a re-binding, refused unless the entry is granted `decrypt` and
   `encrypt` ([associated data](#associated-data)).
7. **CreateTenantKey** (label `provision`, request digest `Digest(tenant, "")`) and **RewrapTenantKey** (label
   `rewrap-tenant-key`, request digest `Digest(tenant, blob)`): verify the response signature (response digest
   `Digest(tenant_key, signing_public_key, fingerprint)`), parse the blob (a layout version your client reads — today
   1 —, your profile and tenant, the answered public key, the answered fingerprint) — after a rewrap also the same key id, public key, fingerprint and
   creation time as the blob you sent — and store it.
8. Map errors by code and ErrorInfo reason ([Errors](#errors)): `CIPHERON_KEY_VERSION_UNAVAILABLE` is not
   corruption; `CIPHERON_BUSY` and a `RetryInfo` mean retry later; `CIPHERON_NO_WRITER`,
   `CIPHERON_AUDIT_UNAVAILABLE` and `CIPHERON_PROFILE_SEALED` mean retry later or on another replica;
   `CIPHERON_STARTING` means sign the request again and send it again (after its `RetryInfo`);
   `RESOURCE_EXHAUSTED` without details is too large, not busy. Never send CreateTenantKey or RewrapTenantKey again on
   your own, but after `CIPHERON_STARTING`: a second execution makes a second key or blob, and that refusal says
   nothing ran. A reason counts only in the domain `cipheron.v1` and with the code cipheron answers it with; a
   `RetryInfo` alone makes nothing retryable. A refusal is not signed ([Errors](#errors)): never delete, quarantine
   or re-provision on one alone — re-ask through another replica or connection, or confirm with a signed operation.
9. **The rest**: with [associated data](#associated-data), append it to the Encrypt/Decrypt digest, expect format 5
   or 6, and check the format byte before sending a Decrypt; a [batch](#batches) is the single operation's digests
   under `BatchDigest`, its answer one result or item error per item in order; a
   [cross-profile ReEncrypt](#cross-profile-reencrypt) needs `to_auth` and verifies `to_response_signature` under the
   target profile's response key.

<a id="conformance-kit"></a>

## Conformance kit

What a client in another language is held to before it talks to a cipheron: the protocol's vectors, packaged, a JSON
Schema for them, a runner, and a test server. Source: `conformance` (the vectors and the runner),
`cipherontest` (the test server), `cipheron conformance` (cipheron's CLI reference, section *`cipheron conformance`*).
**What for:** a transcript off by one byte fails every signature check with the same unhelpful answer; the vectors
tell you which layout is wrong, on your own machine, before any cipheron is involved. Worked: a client written from
this page alone, held to the vectors through an adapter, to the test server's impostors, and to a real cipheron
(cipheron's `third-party-client-conformance` example).

**The vectors** (`cipheron conformance vectors`; `spec/vectors/cipheron-conformance-v1.json`) are
self-contained: 259 cases, each naming its `kind`, its `input` and the `output` a conforming implementation computes,
every byte string in lower-case hex; the schema (`cipheron conformance schema`; `vectors.schema.json`, draft 2020-12,
schema id `cipheron-conformance/v1`) names each kind's input and output exactly. The file names the
[transcript version](#the-transcript-version) once, as a constant of the whole suite: `"transcriptVersion": 1`
(the schema's `const`; `conformance.Parse` refuses a file with another value than the transcript version the package
writes, `transport.WrittenTranscriptVersion(transport.Release())`, or none). No case carries a version of its own.

**Where they come from.** The cases are derived from the repository's **frozen set**,
`spec/frozen/` — `manifest.json` and the keysets of three profiles, `ledger` (shared),
`people` (perTenant derived) and `docs` (perTenant wrapped), made under published test master keys (ILLUSTRATIVE: they
open nothing real) — and a test (`TestTheVectorsAreTheFrozenFilesDerivation`) requires the embedded file to be byte for
byte its derivation from that set. The set holds what cipheron writes for fixed inputs: keysets of the version written
(1), ciphertexts of formats 3, 4, 5 and 6, a `CPS1` object, a JSON document with encrypted fields, tenant key blobs
created and rewrapped, signatures, fingerprints, key-context digests, key statements, and the signed and sealed
transcripts — with tenants of the tenant rule's edges (1 to 2048 bytes of 0x21 to 0x7E): a derived and a wrapped tenant
holding `|`, `"`, `\`, `/` and `%`, a 2048-byte tenant in both, and a blob at the bound (2369 bytes: the longest profile
name, tenant id and wrapping version id). The `reEncryptAssociatedData`, `tenantId` and `errorClass` cases are rules,
not layouts: the generator writes them from the rules, and they hold no bytes of the set. The refusals of
`ciphertextKeyID` and `tenantKey` are derived from the set's bytes and the release's schemes (`transport.Release().Schemes()`): every format the code
reads gets its truncated and malformed headers, and the format bytes and blob versions no layout has. The set is
written by cipheron's server (its keyring, under the published test masters; `manifest.json` names the command), only
when asked, and the kit is written from it with:

```sh
go test ./conformance -run TestTheVectorsAreTheFrozenFilesDerivation -update-conformance
```

Readers in this repository (`wire/transport`, `conformance`, the Go library) and in cipheron's server hold today's code
to the set; neither the set nor the kit is ever
regenerated to make a reader pass, and `make check-golden-fixtures` holds the set to what the repository commits.
**Why frozen:** vectors regenerated from the code would follow a bug in the code; frozen ones catch it.

| kind | cases | input | output | the layout it checks |
| --- | --- | --- | --- | --- |
| `digest` | 30 | `fields` (hex list) | `digest` | [Digests](#digests): a request's and an answer's payload digest, associated data, ReEncrypt's extension group and a batch with its items' digests included |
| `requestTranscript` | 15 | `profile`, `operation`, `timestampMs`, `nonce`, `digest` | `transcript` | [Request transcript](#request-transcript) |
| `requestSignature` | 20 | `publicKey`, `transcript`, `signature` | `valid` | Ed25519 over the request transcript (a server's check; a flipped signature, a flipped transcript, S not below L — RFC 8032 section 5.1.7 requires S < L — and a signature of 63 or 65 bytes are `false`) |
| `requestSealInfo` | 7 | `profile`, `operation`, `tenant` (empty: a shared profile), `requestPublicKey` (empty: none) | `info` | [HPKE](#hpke): the info a request payload is sealed under, bound to the version and the requester; tenants of the rule's edges included |
| `responseSealInfo` | 4 | `profile`, `operation`, `tenant` | `info` | [HPKE](#hpke): the info a Decrypt answer's plaintext is sealed under, bound to the version |
| `responseTranscript` | 11 | `profile`, `contextDigest`, `operation`, `requestNonce`, `requestSignature`, `requestDigest`, `responseDigest` | `transcript` | [Response transcript](#response-transcript) |
| `responseSignature` | 21 | `publicKey`, `transcript`, `signature` | `valid` | the client's check of every answer and of a PublicKey answer's `keys_signature` (a flipped signature, a flipped answer, another profile's key, S not below L, 63 and 65 bytes, and a keys signature checked under another nonce — a replayed answer — are `false`) |
| `signingKeysTranscript` | 3 | `profile`, `tenancy`, `contextDigest`, `nonce`, `keys` (`keyId`, `state` — `active`, `verifyOnly` or `revoked`, by name —, `publicKey`; written in ascending key id order) | `transcript` | [Signing keys](#signing-keys): the transcript writes each state's number, so the case checks the name-to-number mapping too |
| `fingerprint` | 4 | `profile`, `tenancy`, `hpkeSuite` (`kem`, `kdf`, `aead`), `hpkePublicKey`, `responseAlgorithm`, `responsePublicKey`, `additional` (left out: none; each `role`, `suite`, `algorithm`, `publicKey`) | `fingerprint` | [Identity and fingerprint](#identity-and-fingerprint): what a client pins — derivation 1, and derivation 2 for an identity under another suite with an added key |
| `keyStatement` | 6 | `statement`, `signature`, `profile`, `fingerprint` | `valid` | [Key statement](#key-statement), verified against a pin (another pin, another profile and a flipped signature are `false`) |
| `ciphertextKeyID` | 52 | `ciphertext` | `keyId`, or `refused` | [Ciphertext formats](#ciphertext-formats): `<version>` (formats 4 and 5, a segmented object's segments included), `tenant-key:<hex>` (formats 3 and 6); refused: a format no layout has (2, 7, 9, 255), another magic, the magic alone, no byte, a header cut short, a ciphertext shorter than an empty plaintext's, a version id of length 0, of 33 bytes, or holding `/` or a space |
| `signingKeyID` | 6 | `algorithm`, `publicKey` | `keyId` | a signing key's id: Ed25519's, and another algorithm's (its id names the algorithm) |
| `segmentAssociatedData` | 4 | `objectId`, `index`, `final`, `associatedData` | `associatedData` | [Segmented objects](#segmented-objects): what a segment is encrypted with |
| `jsonFieldAssociatedData` | 5 | `recordId`, `pointer`, `associatedData` | `associatedData` | encrypted JSON fields: `lp("cipheron/v1|json-field") lp(record id) lp(pointer) lp(associated data)` |
| `reEncryptAssociatedData` | 5 | `associatedData`, `toAssociatedData` (empty: none) | `valid` | [Associated data](#associated-data): a re-encryption's `associated_data` with an empty `to_associated_data` is `false` (cipheron refuses it, a client does not send it); so are other bytes and the target's alone (a re-binding, which a client does not send); the same bytes and none on either side are `true` |
| `tenantKey` | 17 | `blob`, `profile`, `tenant` (the call's) | `keyId`, `signingPublicKey`, `wrappingVersion`, `created` (Unix seconds), `fingerprint`; or `refused` | [Tenant key blob](#tenant-key-blob): its header, checked against the call's profile and tenant (steps 4 and 7); refused: another tenant or profile, a version no layout has (0, 2), another magic, a trailing byte, a byte over 2369, a byte short, a tenant that is not an id, a profile that is not a name, a creation time of 0 |
| `tenantFingerprint` | 6 | `profile`, `tenant`, `keyId`, `signingPublicKey` | `fingerprint` | what a client pins a tenant key by: `"sha256:"` and the hex SHA-256 of `lp("cipheron/v1|tenant-fingerprint") lp(profile) lp(tenant) lp(key id) lp(signing public key)` |
| `tenantSignedMessage` | 4 | `profile`, `tenant`, `data` | `message` | what a derived profile's key signs for a tenant: `lp("cipheron/v1|tenant-signature") lp(profile) lp(tenant) lp(data)` |
| `tenantId` | 18 | `tenant` | `valid` | the tenant rule: 1 to 2048 bytes of 0x21 to 0x7E; every tenant of the set, the range's ends and 2048 bytes are `true`; no byte, 2049 bytes, a space, a trailing space, 0x7F, 0x00, a tab and a byte above 0x7E are `false` |
| `errorClass` | 21 | `code` (the canonical name, `"UNAVAILABLE"`), `errorInfo` (`domain`, `reason`; left out: none), `retryDelayMs` (left out: none) | `class`, `retry` (`never`, `transient`, `resign`), `minWaitMs` | [Errors](#errors): `CIPHERON_BUSY` on `RESOURCE_EXHAUSTED` and `CIPHERON_NO_WRITER`, `CIPHERON_PROFILE_SEALED`, `CIPHERON_AUDIT_UNAVAILABLE` and no ErrorInfo on `UNAVAILABLE` are `transient`; `CIPHERON_STARTING` on `UNAVAILABLE` is `resign` (sign again, send once more, whatever the operation); a reason in another ErrorInfo domain, on another code, or a `RetryInfo` alone is `never`; the wait is the `RetryInfo`'s when the rule retries |

An input field a kind does not have is refused by the reference's strict decoder, and so is a state name that is not
one of the three. **A refusal is an output:** a case of `ciphertextKeyID` or `tenantKey` (`conformance.RefusableKinds`)
whose input your implementation must refuse has the output `{"refused": true}`, and your adapter answers exactly that;
an `error` answer is never taken for a refusal, and fails as every error does. The schema accepts `refused` for those
two kinds only, and a tenant in a seal info is `^[!-~]{1,2048}$` or empty (a shared profile).

**The runner.** `cipheron conformance run --adapter <program> [-- <arg>...]` starts your adapter — a small program
around your implementation — and sends it one case per line on its standard input; it answers each, in order, with
one line on its standard output:

```text
in:  {"id":"c1","kind":"requestTranscript","input":{"profile":"ledger","operation":"encrypt","timestampMs":1767225600000,"nonce":"1010…","digest":"b112…"}}
out: {"id":"c1","output":{"transcript":"0000001a6369…"}}
out: {"id":"c4","output":{"refused":true}}          (bytes your implementation refuses: the case's answer)
out: {"id":"c2","error":"what went wrong"}          (a failed case)
out: {"id":"c3","unsupported":true}                 (a kind your implementation does not compute)
```

Outputs are compared as JSON values (key order and spacing aside). **"Unsupported" counts only for a whole kind, and
never for a verification kind:** a kind every case of which is answered unsupported is counted, not failed (a client
that only verifies answers need not compute request transcripts); a case answered unsupported is a failure when other
cases of its kind were answered, or when its kind is `responseSignature`, `signingKeysTranscript`, `fingerprint` or
`keyStatement` (`conformance.MandatoryKinds`) — the checks against an impostor, which every passing run has done in
full. The report counts passed, failed and unsupported cases per kind and lists every failure with what was expected;
the exit status is 1 when a case failed. In Go the same
runner is `conformance.Run(ctx, impl, suite)` over an `Implementation`, with `conformance.Exec(...)` for a program and
`conformance.Reference()` — `wire/transport`, which passes every case.

**What the kit does not cover.** HPKE itself (use your platform's RFC 9180 implementation and its own test vectors),
Ed25519 (RFC 8032's), AES-GCM, and the server's key derivations (only cipheron holds keys) — so it does not check that
a format-5/6 ciphertext, a segment or a JSON field DECRYPTS (the frozen set's readers do, against cipheron); a
JSON-field document's encoding (the value replaced by `cipheron:v1:` and the ciphertext's standard base64, the
field's plaintext its compact JSON) and a CPS1 object's container layout (the header, each segment behind its length)
are documented ([Segmented objects](#segmented-objects), [JSON fields](#json-fields)) but have no kind of their own:
a reader holds itself to the frozen set's object and documents (`manifest.json`); the order of a client's checks
([Doing it by hand](#doing-it-by-hand-in-another-language)) is behaviour, which the test server checks. The refusals
the kit holds are of stored bytes a client parses before it sends anything; a refusal cipheron answers is not signed,
and the kit says what it means (`errorClass`), not whether to believe it.

**The test server, `cipherontest`.** A CipherService for tests — of an application, or of a client in another
language over its socket or its mutual-TLS port: it holds a profile's keys, checks request auth, signs its answers as
the protocol says, refuses what cipheron refuses with cipheron's messages — unknown fields, associated data over
64 KiB, a re-encryption's `associated_data` without `to_associated_data`, a batch over `batch.maxItems` /
`batch.maxBytes`
(`SetBatchMaxItems`, `SetBatchMaxBytes`, counted as cipheron counts them), and on its JSON API a method other than
POST, a query string, another profile in the body, anything after the request, a body beyond the bound — enforces
cipheron's grants when a test restricts them (`Grant`: a cross-profile ReEncrypt needs `export` on its source and
`import` on its target, and `retenant` on its source when it changes the tenant, and a re-binding `decrypt` and
`encrypt`, as cipheron decides it), and can
be switched into the ways an impostor or a broken server answers (`SetMode`: junk ciphertexts, foreign response
signatures, a substituted key statement, a ciphertext made without the associated data the call sent
(`AssociatedDataDropped`), a signing key in a state the protocol does not have in a validly signed list
(`UnknownSigningKeyState`), a PublicKey answer replayed from another request nonce (`ReplayedKeys`), a tenant key answered with a signing public
key its blob does not name (`AnsweredOtherSigningKey`), …) or the ways cipheron, or a proxy in front of it, answers when it cannot
serve (`Fail`: busy, no writer, internal, unimplemented, a profile sealed, a proxy's detail-less overload). **What
for:** a client's error handling and its checks against impostors can be proved in a unit test, without a cipheron
or a KMS. It is not cipheron: its ciphertexts and tenant key blobs are sealed as cipheron seals them (the layouts and
their cryptography are `wire/transport`'s, which cipheron uses too), under keys the test server makes for
each test and no cipheron holds, so nothing it encrypted may be kept. Worked: a service's unit tests against it
(cipheron's `testing-apps-with-cipherontest` example).
