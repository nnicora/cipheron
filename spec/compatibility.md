# Formats and versions

cipheron has **one** version of each format it stores and of the protocol it speaks. This page names each of them,
says where its version is written, what each byte of a ciphertext's header means, and what cipheron and its Go client
library do with a value they do not have. It then states the **compatibility policy**: how a later release adds an
algorithm or a layout, and what happens to the data already stored. The byte layouts themselves are in
[api.md](api.md).

**Who this page is for.** An operator or an auditor who must say what a stored object is; a developer who writes a
client in another language; a reviewer who checks that nothing of an unknown form is ever read; whoever plans a
release that changes a format. The terms are those of [api.md](api.md#words-this-page-uses) and of
cipheron's glossary.

- [Every format and its version](#every-format-and-its-version)
- [The ciphertext formats](#the-ciphertext-formats)
- [The algorithm is named by the stored bytes](#the-algorithm-is-named-by-the-stored-bytes)
- [The transcript version](#the-transcript-version)
- [What is refused](#what-is-refused)
- [The conformance file](#the-conformance-file)
- [The compatibility policy](#the-compatibility-policy)
- [One release](#one-release)

## Every format and its version

| part | what it is | version | where the version is written | layout |
| --- | --- | --- | --- | --- |
| keyset file | a profile's identity and signing keys, wrapped under a master version | `1` | the file's `"version"` member; also bound into the wrap's additional data | [api.md](api.md#keyset-file) |
| tenant key blob | a wrapped tenant's keys, as the application stores them | `1` | the byte after `CPT1`; the header is the wrap's additional data | [api.md](api.md#tenant-key-blob) |
| ciphertext | what Encrypt returns | formats `3`, `4`, `5`, `6` | the byte after `CPH1` | [below](#the-ciphertext-formats), [api.md](api.md#ciphertext-formats) |
| segmented object | a client format: an object of any size as a list of ciphertexts | `1` | the byte after `CPS1` | [api.md](api.md#segmented-objects) |
| encrypted JSON field | a client convention: one field of a JSON document, encrypted | the prefix `cipheron:v1:` (version 1) | the start of the field's string value | [api.md](api.md#json-fields) |
| key statement | a profile's keys and their states, signed and publishable | `1` | the statement's head: the field after its label | [api.md](api.md#key-statement) |
| key statement export | a key statement as a JSON document to publish | the token `cipheron-key-statement/1` (version 1) | the document's `"format"` member, exactly this token | [client-library.md](../docs/client-library.md#publishing-the-signing-keys-the-key-statement) |
| fingerprint | the hash a client pins a profile's identity by | derivation `1` or `2` | the identity decides which | [api.md](api.md#identity-and-fingerprint) |
| transcripts and seal infos | everything signed or sealed between a client and cipheron | `1` | in no message: a 4-byte field at a fixed place in the bytes signed or sealed | [below](#the-transcript-version) |
| the API | the gRPC service and its JSON API | `cipheron.v1` | the proto package, the gRPC paths `/cipheron.v1.CipherService/<Method>`, the routes `/v1/cipher/{profile}/...`, the ErrorInfo domain | [api.md](api.md#the-rpcs) |
| conformance file | the protocol's test vectors | `cipheron-conformance-v1.json` | its `schema` (`cipheron-conformance/v1`) and `transcriptVersion` (`1`) | [below](#the-conformance-file) |

Each of the versioned items is declared once in the code, as data, with one framework, `wire/format`:
a *kind* and its *schemes* (one per version, each with its own codec), and a *policy* — what a release writes and reads
of every kind. Each kind names its scheme by one marker, the framework's: the magic and the byte after it (a
ciphertext, a tenant key blob, a segmented object), the statement's head (a key statement), the `"format"` member (a
key statement export), the prefix (an encrypted JSON field), the `"version"` member (a keyset file); a transcript
carries none and is rebuilt under each version read. There is one catalog and one policy per program boundary: the
protocol's, `transport.Release()` (`wire/transport/catalog.go`: every kind above but the keyset file),
and cipheron's server's, which is the protocol's with the keyset file added. Today every kind reads exactly the version it writes, but the ciphertext, which writes and reads its four
formats. The fingerprint, the API and the conformance file are not kinds: the fingerprint's derivation is chosen by
the identity and is only ever recomputed and compared, so it has no lifecycle. How the framework is organised, and how
a scheme, a suite or a version is added:
cipheron's architecture document, section *19. For cipheron's own developers: the format framework*.

**The API's version.** The protobuf package `cipheron.v1` is the API's version: it names the gRPC paths, the routes'
`/v1/` and the ErrorInfo domain. A later API version would be a proto package of its own, served beside this one; the
fields of `cipheron.v1` itself change in place, since cipheron and its client library are built together from it
([One release](#one-release)).

**The two fingerprint derivations.** Derivation `1` is that of a *classical* identity — the HPKE suite
`0x0010/0x0001/0x0002`, an Ed25519 response key, no added key — which is every identity cipheron makes. Derivation `2`
is that of any other identity: an HPKE suite or a response algorithm cipheron does not make, or keys added to the
identity. It is the protocol's extension point for another algorithm (a post-quantum or hybrid key, for instance): the
derivation names the suite, the algorithms and every key, and its label differs from derivation 1's, so no value of
one is a value of the other. A pin matches an identity only under the derivation written for it, so a classical
identity has only its derivation-1 fingerprint. A signing key of another algorithm than Ed25519 likewise has its id
derived under a label of its own, `cipheron/v1|signing-key-id2`, which names the algorithm
([api.md](api.md#signing-keys)).

**Why the version is written inside the data.** A ciphertext or a blob travels without its context — in a database
column, a backup, an export to another service — and whoever reads it must know what it is from its bytes alone. So
every stored format begins with fixed *magic* bytes (`CPH1`, `CPT1`, `CPS1`: "this is cipheron's") and a version or
format byte, and a reader refuses a value it does not have instead of guessing ([What is refused](#what-is-refused)).

## The ciphertext formats

The format byte is not a version: the four formats are the two tenancies' layouts, each made without and with caller
[associated data](api.md#associated-data). cipheron writes and reads all four.

| format | tenancy | associated data | `cipheron.KeyID` names |
| --- | --- | --- | --- |
| `3` | perTenant wrapped | none | `tenant-key:<hex id>`: the blob it needs |
| `4` | shared, perTenant derived | none | `<master version>` |
| `5` | shared, perTenant derived | required: format 4's layout under its own byte | `<master version>` |
| `6` | perTenant wrapped | required: format 3's layout under its own byte | `tenant-key:<hex id>` |

Formats 4 and 5, byte by byte:

<!-- format:ciphertext-bytes-4-5 -->
| bytes | element | content |
| --- | --- | --- |
| 0 to 3 | magic | `CPH1` |
| 4 | format | `0x04`, or `0x05` for a ciphertext made with associated data |
| 5 | length of the master version id: n | 1 to 32 |
| 6 to 5 + n | master version id | `[A-Za-z0-9._-]` |
| the next 32 | salt | the salt the ciphertext's own key is derived under |
| the rest | nonce, ciphertext and tag | the AES-256-GCM nonce (12), the ciphertext and its 16-byte tag |
<!-- /format -->

Formats 3 and 6, byte by byte:

<!-- format:ciphertext-bytes-3-6 -->
| bytes | element | content |
| --- | --- | --- |
| 0 to 3 | magic | `CPH1` |
| 4 | format | `0x03`, or `0x06` for a ciphertext made with associated data |
| 5 to 20 | tenant key id | the id of the blob it was made under |
| 21 to 52 | salt | the salt the ciphertext's own key is derived under |
| the rest | nonce, ciphertext and tag | the AES-256-GCM nonce (12), the ciphertext and its 16-byte tag |
<!-- /format -->

The header — everything before the nonce — is part of the AEAD's additional data, so a changed byte anywhere in it
fails the tag. A shared or derived profile reads formats 4 and 5 only, a wrapped profile formats 3 and 6 only. Reading a
header (`cipheron.KeyID`, `cipheron client key-id`) proves nothing: it is authenticated only when cipheron opens the
ciphertext. Each format's key derivation and additional data: [api.md](api.md#ciphertext-formats).

## The algorithm is named by the stored bytes

No stored item carries an algorithm field, and none needs one: each format byte (a ciphertext) and each layout version
(a tenant key blob) names **one** fixed pairing of a layout and its algorithms.

| marker | layout | algorithms |
| --- | --- | --- |
| ciphertext formats `3`, `4`, `5`, `6` (`CPH1` and the byte after it) | the formats above | the ciphertext's own key derived with HKDF-SHA256 (Expand) from the key it is made under, over a label and its 32-byte random salt; the data encrypted with AES-256-GCM under that key |
| tenant key blob version `1` (`CPT1` and the byte after it) | `"CPT1"` \| `1` \| key id \| profile \| tenant \| public key \| wrapping version \| created \| salt \| nonce \| wrapped keys \| tag | the blob's own wrap key derived with HKDF-SHA256 (Expand) from the tenant-wrapping key, over a label and its salt; AES-256-GCM wraps the tenant's storage key and its Ed25519 signing key |

The marker is authenticated: it is in the header, and the header is the AEAD's additional data, so an item whose
marker was changed does not open. An application can therefore tell from its stored bytes alone, offline, which
algorithm a row or a blob needs — `cipheron.KeyID(ct).Format` for a ciphertext, `cipheron.ReadTenantKey(blob).Version`
for a blob — and an attacker who changes the marker gets a refusal, not a weaker algorithm.

Each layout's algorithms are its *suite* (`format.Suite`, `wire/format/suite.go`), and each suite
derives its keys only under labels of its own namespace (`cipheron/v1|` for the one suite of this release); the
catalog refuses two suites owning one namespace. A later algorithm therefore derives its keys under a label of its own,
and no key is ever used under two algorithms. The algorithm is not configurable: no setting, per profile or otherwise,
chooses it, and decryption picks how to read an item from its bytes, never from configuration
(cipheron's FAQ, section *Can I choose another encryption algorithm?*).

## The transcript version

Everything a client and cipheron sign or seal binds the transcript version, `1` (`transport.TranscriptVersion`): the
one version this release writes and reads. It is **not negotiated** and travels in **no message**: the writer builds
every transcript with the version the release's policy writes, and the verifier rebuilds what it checks under each
version the policy reads, the written one first. It is written as a 4-byte big-endian field behind its 4-byte length
(`00 00 00 04 00 00 00 01`):

- right after the label in the [request](api.md#request-transcript), [response](api.md#response-transcript) and
  [signing-keys](api.md#signing-keys) transcripts;
- right after the context string in the HPKE info a request payload is sealed under (`RequestSealInfo`) and in the one
  a Decrypt answer's plaintext is sealed under (`ResponseInfoTenant`) ([HPKE](api.md#hpke)).

**Why bind the version.** A later layout of any of these would be a later number, so nothing signed or sealed under
these layouts can ever verify or open as that layout's (domain separation). A signature made under a version the
verifier does not read does not verify, and a payload sealed under such an info does not open
([What is refused](#what-is-refused)).

The other numbered layouts have their own version, written in their own bytes: the key statement (`1`), the keyset
file (`1`), the tenant key blob (`1`), the segmented object (`1`).

## What is refused

An unknown format, version, state, tenancy, suite or algorithm is **refused**, never read as something else. A version
is unknown when the release's policy does not read it for its kind; in this release every kind reads exactly version 1
(the ciphertext its formats 3 to 6; the fingerprint, which is no kind, its derivations 1 and 2). Where it is met decides the answer: cipheron refuses what a caller sends; the Go
library refuses a signed answer it does not have with `ErrBadResponse`, an answer it cannot authenticate with
`ErrServerIdentity`, and bytes a caller hands it with `ErrInvalidInput` or one of its kinds
([client-library.md](../docs/client-library.md#errors)). A key list and a batch answer are authenticated before anything in
them is read, so a value changed on the way is `ErrServerIdentity`, never `ErrBadResponse`.

| what | cipheron | the Go library |
| --- | --- | --- |
| a keyset of a version cipheron's release does not read for the keyset file (other than 1) | `serve` and every `keygen` command refuse it: `keyset version <n>; this cipheron reads version 1`; one with no `version` member: `not a keyset file: it has no version member`. A field the version does not have is refused too (the file is read strictly). A keyset of an older version a release still reads moves to the written version with `cipheron keygen upgrade` (or any `keygen` command that rewrites it) | — |
| a tenant key blob of a version the release does not read for the tenant key blob (other than 1) | `INVALID_ARGUMENT`, `tenant_key is not a key of this tenant in this profile` | a blob the application hands in (`Tenant`, `ReadTenantKey`): `ErrTenantKey`, also `ErrInvalidInput`; a blob in a CreateTenantKey or RewrapTenantKey answer: `ErrBadResponse` |
| a ciphertext whose format byte is not one the release reads for the ciphertext (3, 4, 5, 6) | `INVALID_ARGUMENT`, `the ciphertext is not a cipheron ciphertext` (so is a format the profile's tenancy does not use) | a ciphertext the application hands in (`KeyID`, Decrypt, ReEncrypt): `ErrInvalidInput`, refused before it is sent (cipheron's magic with a format byte the release does not read: the message ends `a format this protocol does not have (format <n>)`); an Encrypt or ReEncrypt answer: `ErrBadResponse` |
| a segmented object of a version other than 1 | — (cipheron sees only its segments) | `ErrSegmented`, also `ErrInvalidInput` |
| a key statement of a version the release does not read for the key statement (other than 1) | — | `ImportKeyStatement`: `ErrKeyStatement`, also `ErrInvalidInput`; the statement of a PublicKey answer: `ErrServerIdentity` |
| a signature or a seal info under a transcript version the release does not read | a request signature: `PERMISSION_DENIED`; a request payload sealed under another info: `INVALID_ARGUMENT`, `the sealed payload could not be opened` | a response or keys signature: `ErrServerIdentity`; a Decrypt answer's plaintext sealed under another info: `ErrBadResponse` |
| a signing-key state other than active (1), verifyOnly (2), revoked (3) | — (it publishes only these) | in a PublicKey answer whose key list's signature covers it: `ErrBadResponse`; one the signature does not cover (changed on the way): `ErrServerIdentity`; either way the whole answer is refused and nothing kept. In a list handed to `VerifyWithKeys` or `VerifyTenantWithKeys`: `ErrInvalidInput` |
| a tenancy other than the three | — | `ErrServerIdentity` (the fingerprint and the key list's signature hold the tenancy's name, so such an answer cannot be authenticated), nothing kept |
| an HPKE suite or a response key algorithm the library does not implement | — | the identity can be pinned; a response key it cannot verify under is `ErrServerIdentity` (nothing it signs can be checked), and every call that would seal a payload to a suite it does not implement is `ErrBadResponse` |
| a signing key of an algorithm the library does not implement | — | listed and used for nothing: `Verify` under it is `ErrBadResponse`, `VerifyWithKeys` `ErrInvalidInput` |
| a request field the API does not have | `INVALID_ARGUMENT`: over gRPC `unknown field <n> in <message>: ...`, over HTTP 400 | — |
| a gRPC request in an encoding other than identity (compressed) | `UNIMPLEMENTED`, `cipheron reads uncompressed requests only: …` (an encoding gRPC does not have: gRPC's own `grpc: Decompressor is not installed …`), before the message is read; audited | — (it sends uncompressed requests only) |
| a batch of more than 4096 items | `INVALID_ARGUMENT`, `the batch holds more than 4096 items, which no batch may hold: split it`, before it is decoded | refused before it is sent |
| a configuration key cipheron does not have | refused at load: the decoding is strict (cipheron's configuration reference, section *How the file is read*) | — |

**Why refuse.** A reader that guessed at a layout it does not have could read the wrong key, the wrong tenant or the
wrong state out of it. A refusal is loud at the moment the object is met, and nothing is stored or used that could not
be read back.

## The conformance file

`spec/vectors/cipheron-conformance-v1.json` (`cipheron conformance vectors`) holds the protocol's
vectors: 259 cases of 20 kinds, each a `kind`, an `input` and the `output` a conforming implementation computes — for
the cases an implementation must refuse (bytes that are no layout, a tenant key blob of another tenant or profile, one
byte over a bound; only the kinds `ciphertextKeyID` and `tenantKey` have them), the output `{"refused": true}`. Its
`schema` is `cipheron-conformance/v1` and its `transcriptVersion` is `1`, a constant of the whole file: the reader
(`conformance.Parse`) refuses a file of any version but the one this release writes
(`transport.WrittenTranscriptVersion(transport.Release())`), or with none, and refuses a field it does not have. The cases of the layouts
and transcripts are derived from the frozen set `spec/frozen/` and held to it byte for
byte; the layouts' refusal cases come from those bytes and from the release's schemes (every format the release reads
gets its truncated and malformed headers, and the bytes no scheme has are the ones the release's policy refuses); the cases of three
rules — `reEncryptAssociatedData`, `tenantId` and `errorClass` — are written from the rules and hold no bytes of the
set. What each kind checks, and the runner: [api.md](api.md#conformance-kit); a client held to them:
cipheron's `third-party-client-conformance` example.

## The compatibility policy

Nothing is in production yet, and this release reads exactly one version of each kind (the ciphertext formats 3 to
6, the fingerprint's derivations 1 and 2). The policy below is how every **later** release changes an algorithm or a
stored layout. In the code each step is a change of the release's policy, and the order is one function over two
policies, `format.Check(previous, next)`, run against the record of the previous release
(the protocol's, `wire/transport/testdata/release.txt`; cipheron's server keeps its own, with the keyset file): it
allows a version to join what a kind reads at any time, refuses a
writer that switches to a version the previous release did not read, and refuses removing a version the previous
release wrote
(cipheron's architecture document, section *19. For cipheron's own developers: the format framework*:
"How to add a scheme or a suite" and "How to add a version, and the lifecycle as policy transitions").
Every kind has a version 2 that exists only in the tests and is a layout of its own — its own codec, and for the
tenant key blob another suite: `wire/transport/v2layouts_test.go`, and cipheron's server's tests for the ciphertext
and the keyset file (cipheron's guide to adding a keyset version). Each is written in its own layout and read beside
version 1, and a policy that does not read it refuses it: what a release that adds a version relies on.

**1. Every stored item names its layout.** A ciphertext by its format byte (`transport.FormatTenantKey` 3,
`FormatVersioned` 4, `FormatVersionedAAD` 5, `FormatTenantKeyAAD` 6, in `wire/transport/ciphertext.go`;
read by `cipheron.KeyID(ct).Format`), a tenant key blob by its layout version (`transport.TenantKeyHeader.Version`,
in `wire/transport/tenant.go`; read by `cipheron.ReadTenantKey(blob).Version`), a keyset file by its
`"version"` (one codec per version in cipheron's server: cipheron's guide to adding a keyset version). Decryption picks its reader from the stored bytes, never
from configuration, and the marker names the algorithm too ([above](#the-algorithm-is-named-by-the-stored-bytes)).

**2. A release adds; it does not replace.** A release that brings another algorithm or layout **adds** it — other
format bytes, another blob or keyset version — and keeps every reader of a format customers may hold. Writing the
added format is a later release's step: a release writes a version only when the previous release already read it
(`format.Check`), and it is rolled out only after every replica **and** every application's client library runs a
release that reads it. The client library refuses a format it does not read, in what it is asked to send
(`parseCiphertext` in `internal/client/client.go`) and in answers (`checkCiphertext`), so a writer that
switched first would break the applications that lag. Readers first, the writer last: the same order as a master version's rollout
(cipheron's keys and rotation guide).

**3. Data moves with the tools that exist for a rotation.** Ciphertexts move with `ReEncrypt` and `ReEncryptBatch`
(the plaintext never leaves cipheron), found by their format with `cipheron.KeyID`; tenant key blobs move with
`RewrapTenantKey` and `RewrapTenantKeyBatch`; keysets with `cipheron keygen upgrade` (same keys, wrapping version and
fingerprint; every `keygen` command that rewrites a keyset writes it in the written version too). A re-encryption keeps
each row's associated data.

**4. A reader is removed last.** A reader leaves only in a later release, announced in that release's notes, once the
sweeps report no item left in the old format — the same pattern as a master version that becomes `decryptOnly` and is
then removed from the list. Until then a row in the old format reads as it always did.

**5. A broken algorithm.** If an algorithm's confidentiality is broken, re-encryption protects only the copies an
attacker does not hold. Migrate fast, then destroy the pre-migration backups, dumps and replicas: every copy still in
the old format stays exposed.

**Why this order.** A party that meets a format it does not read refuses it, loudly ([What is refused](#what-is-refused)).
Adding the reader everywhere before anything writes means no running replica and no application is ever handed an
item it cannot read; removing a reader only after the sweeps means no stored item becomes unreadable. The
authenticated marker means an item is never read under the wrong algorithm, and the per-suite label namespace means
no key ever serves two algorithms.

## One release

The chart, the binary and the Go client library are **one release**, built from one commit.

- **The chart and the binary.** The chart renders cipheron's configuration, and the binary refuses a key it does not
  have, so a chart is used only with the binary of its own release. The image is pulled by digest; a published chart
  carries the digest of its release's image. cipheron logs a warning at start, and exports
  `cipheron_chart_binary_skew` 1 (alert `CipheronChartBinarySkew`), when the chart declares another version than the
  binary's (cipheron's Helm guide, section *Versions and distribution*).
- **The binary and the client library.** cipheron and the Go library are built from one API
  (`proto/v1/cipheron.proto`) and speak its one version: there is nothing to negotiate. Build the
  application against the Go library of the release its cipheron runs.
- **Which release runs.** `cipheron version` prints the binary's version, commit and FIPS 140-3 state
  (cipheron's CLI reference, section *`cipheron version`*); the metric `cipheron_build_info` carries the same.
