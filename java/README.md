# cipheron for Java

The Java client library of cipheron: it encrypts, decrypts, re-encrypts and signs through a cipheron, and checks every
answer before it returns it, as the Go library does. It speaks the same protocol ([spec/api.md](../spec/api.md)) over
the same API (`cipheron.v1`, gRPC or the JSON API over HTTP/1.1), and is held to the same conformance kit
([spec/vectors](../spec/vectors)).

**Who this page is for:** a Java team calling cipheron. The protocol and the security model are the repository's
([README](../README.md), [docs/client-library.md](../docs/client-library.md)); this page says how the Java library
expresses them.

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [What the library checks](#what-the-library-checks)
- [Options](#options)
- [Operations](#operations)
- [Errors](#errors)
- [Conformance and tests](#conformance-and-tests)
- [Building](#building)

## Requirements

- Java 21 or later.
- Coordinates `io.github.nnicora:cipheron`, package `io.github.nnicora.cipheron`, module `io.github.nnicora.cipheron`
  (it runs on the class path or the module path). The library is not published to a repository yet: build it from this
  directory (`./mvnw install`) and depend on `0.1.0-SNAPSHOT`.
- Runtime dependencies: grpc-java (Netty), protobuf-java and protobuf-java-util, Google's common protos, Gson. No
  cryptography library: every primitive is the JDK's (JCA), and HPKE (RFC 9180) is written on them and held to the
  RFC's own test vectors.

**FIPS 140-3.** The Go library runs under the Go Cryptographic Module. The Java library uses the JDK's default
providers (SunEC, SunJCE, SunJSSE), which are not FIPS-validated. The primitives (Ed25519, ECDH P-256, AES-256-GCM,
SHA-256, HMAC-SHA256, TLS 1.3) are approved ones, and the library asks the JCA for each by its algorithm name, never
naming a provider: the provider order the JDK is configured with (`java.security`) decides which one serves it. A
FIPS deployment configures a validated provider there, which is outside this library, and has not been tested with
it.

## Quick start

On the sidecar's unix socket:

```java
try (CipheronClient c = CipheronClient.builder("/run/cipheron/private/cipheron.sock")
        .serverUid(10443)                                              // the uid cipheron's image runs as
        .requestKeyFile(Path.of("/etc/app/cipheron/payments-api.key")) // the caller's Ed25519 request key
        .profileFingerprint("credentials", "sha256:<what keygen ensure printed>")
        .requiredPins()
        .build()) {
    byte[] ct = c.encrypt("credentials", "s3cret".getBytes(StandardCharsets.UTF_8));
    byte[] pt = c.decrypt("credentials", ct);
}
```

In a pod with the cipheron-sidecar chart, the environment it sets is enough:

```java
CipheronClient c = CipheronClient.builder("").environment().build();
```

Over the network (mutual TLS 1.3, the server checked by its SPIFFE id or host name):

```java
CipheronClient c = CipheronClient.builder("cipheron.payments.svc:8443")
        .tlsFiles(Path.of("client.pem"), Path.of("client.key"), Path.of("ca.pem"))
        .serverSpiffeId("spiffe://example.org/cipheron")
        .requestKeyFile(Path.of("payments-api.key"))
        .profileFingerprint("credentials", "sha256:…")
        .build();
```

A client is safe for concurrent use and connects on its first call; close it to release its connections.

## What the library checks

Before it returns anything, the library checks, as [spec/api.md](../spec/api.md) ("Doing it by hand, in another
language") lists:

- the profile's identity against its pin (or, unpinned, against the first identity it saw: trust on first use), and
  never adopts a changed one ([`ServerKeyChangedException`](#errors));
- the signed signing-key list under its own request's nonce, and the key statement that must agree with it; a key once
  seen revoked stays revoked;
- every answer's signature, under the key-context digests it accepts (the pinned ones, else those the profile's
  verified answers gave), bound to its request, its nonce and the request's signature;
- every ciphertext's format and length, every tenant key blob against the call's profile and tenant, every batch
  answer item by item;
- on the socket, that the process serving it runs as the expected uid (read with the JDK's `SO_PEERCRED` on the
  connection itself, before a byte is written); on the network, the server certificate against the configured CAs
  only, never the system's roots.

Requests are sealed to the profile's HPKE key (bound to the request key) and signed by the request key.

## Options

| builder method | what it does |
| --- | --- |
| `serverUid(uid)` / `anyServer()` | the socket's server check (one of the two is required on a socket) |
| `tlsFiles(cert, key, ca)` | the network's mutual TLS; the client pair is re-read on every handshake |
| `serverSpiffeId(id)` | checks the server by its SPIFFE id instead of its host name |
| `requestKeyFile(path)` / `requestKey(key)` | the Ed25519 request key (required on the network); the file must be private (`chmod 600`) |
| `profileFingerprint(profile, fp)` | pins a profile's identity |
| `contextDigestPin(profile, digests…)` | pins the key contexts a profile's answers may come from (at most 8) |
| `writerVersionPin(profile, versions…)` | pins the master versions new data may be made under (at most 8) |
| `tenantFingerprint(profile, tenant, fp)` | pins a wrapped tenant's key |
| `requiredPins()` | refuses a profile with no pin instead of trusting it on first use |
| `pinsDir(dir)`, `pinsReloadInterval(d)` | reads pins from `<profile>.fingerprint` / `<profile>.contextDigest` files, re-read every 10 s unless told otherwise |
| `environment()` | the sidecar's `CIPHERON_*` variables; production unless `CIPHERON_ENVIRONMENT=development` |
| `transport(Transport.HTTP)` | the JSON API over HTTP/1.1 instead of gRPC |
| `retry(policy)` | retries refusals that say "later"; never CreateTenantKey or the rewrap calls |
| `keysMaxAge(d)` | the oldest signing-key list a verification relies on (5 s to 24 h, default 5 min) |
| `maxMessageBytes(n)`, `connections(n)` | message bound (default 64 MiB + 64 KiB), pool size (1 to 16); over HTTP, the most calls (and connections, idle ones included) at once, the others waiting for one; an idle connection is closed after 90 s, before cipheron closes it |
| `observer(fn)` | told of `server_identity`, `server_key_changed`, `context_digest`, `keys_stale`, `retry` events |
| `defaultTimeout(d)` | a call's deadline unless it names one (`CallOption.timeout`), default 30 s |

## Operations

| | shared profile | perTenant profile (`client.tenant(profile, tenant, blob)`) |
| --- | --- | --- |
| single | `encrypt`, `decrypt`, `reEncrypt`, `sign`, `verify` | the same, on the `Tenant` |
| batch | `encryptBatch`, `decryptBatch`, `reEncryptBatch` | the same, on the `Tenant` |
| objects (`CPS1`) | `encryptObject`, `decryptObject`, `reEncryptObject`, and the `…Stream` forms | the object forms, on the `Tenant` |
| JSON fields | `encryptJsonFields`, `decryptJsonFields`, `reEncryptJsonFields` | encrypt and decrypt, on the `Tenant` |
| tenant keys | | `createTenantKey`, `rewrapTenantKey`, `rewrapTenantKeyBatch` (wrapped profiles) |
| across profiles | `reEncryptAcross(from, to, ciphertext)` | the same, with `Scope.tenant(…)` |
| keys | `keys`, `contextDigest`, `keyStatement` | |

A JSON-fields document comes back compact, written as the Go library writes it: object keys in sorted order, numbers as
they were written, the same escapes; the same document gives the same bytes from either library.

Associated data is a call option: `CallOption.associatedData(aad)`; a re-encryption of such a ciphertext names the
same bytes as `CallOption.targetAssociatedData(aad)`. The offline helpers are static on `Cipheron`: `keyId(ciphertext)`,
`verify`, `verifyTenant`, `verifyWithKeys`, `readTenantKey`; a party that holds only a pin imports a key statement with
`KeyStatement.importExported(json, profile, pin, maxAge)` and verifies signatures with it.

## Errors

Every failure is a `CipheronException` (unchecked); act on its class, never on its message:

| exception | meaning |
| --- | --- |
| `ServerIdentityException` (`ServerKeyChangedException`, `PinRequiredException`) | not the profile's cipheron: a pin that does not match, an answer that does not verify, a socket served by another uid, a server certificate that does not check |
| `PermissionDeniedException` | cipheron refused the caller; it names no cause, on purpose |
| `CertificateRefusedException` (a `PermissionDeniedException`) | on the network, cipheron refused this client's **certificate** in the TLS handshake (an identity no profile lists or outside its trust bundle's scope, a chain that does not verify), told by an authenticated TLS 1.3 alert: the calls on that connection fail at once instead of waiting for their deadlines; it does not stick, the next call tries a new connection |
| `InvalidInputException` (`TenantKeyException`, `AssociatedDataException`, `SegmentedException`, `KeyStatementException`, `JsonFieldException`, `InvalidKeyListException`) | the input is not one cipheron accepts |
| `KeyVersionUnavailableException` | the master version is not on this replica: not corruption |
| `UnavailableException` (`BusyException`, `NoWriterException`, `ProfileSealedException`) | retry later or on another replica (`retryAfter()`) |
| `BadResponseException` | cipheron's answer is malformed |
| `SigningKeyRevokedException`, `UnknownSigningKeyException`, `KeysStaleException` | a signature's key cannot vouch for it |
| `TenancyException`, `ContextDigestException`, `TooLargeException`, `UnsupportedException`, `InternalException`, `ClosedException`, `DeadlineExceededException` | as named |

`requestId()` is the call's `x-request-id`, which cipheron logs and audits it under; `batchLimits()` names cipheron's
limits when it refused a batch as too large for them.

## Conformance and tests

- `make java-conformance` (from the repository's root) runs the conformance kit through Go's own runner
  (`conformance.Exec`) on the Java adapter: 259 cases, none answered unsupported.
- `make java-test` runs the unit tests (the kit's vectors, HPKE against RFC 9180's test vectors, HKDF against
  RFC 5869's, the frozen set through the public API) and the integration tests against `cipherontest`'s fake cipheron,
  served by the Go harness in [harness](harness): every operation over the socket and mutual TLS, by gRPC and by the
  JSON API, the fake's impostor modes, its refusals, cipheron refusing the client's certificate, signing-key rotation
  and revocation, the pins directory's reload. The tests run on the module path, as the module.

The integration tests build the harness with the Go toolchain; without Go they are skipped.

## Building

```sh
./mvnw verify          # build, unit and integration tests
./mvnw install         # into the local repository, as io.github.nnicora:cipheron:0.1.0-SNAPSHOT
```

The Maven Wrapper downloads Maven 3.10.2 and checks it against its SHA-256 (`.mvn/wrapper/maven-wrapper.properties`).
The API is generated at build time from [proto/v1](../proto/v1) into the package `cipheron.v1`, which is internal:
nothing of it is part of the library's API, nor is anything under `io.github.nnicora.cipheron.internal`. The module
(`src/main/java/module-info.java`) exports `io.github.nnicora.cipheron` alone. gRPC and protobuf are automatic modules,
by the names their jars declare; `proto-google-common-protos` declares none, so its module name is derived from its
file name (`proto.google.common.protos`), which Maven warns about when it builds.
