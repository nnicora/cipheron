# cipheron

cipheron does an application's cryptography for it: the application asks it to encrypt, decrypt, re-encrypt or sign
data in a **profile** (a named set of keys, such as `credentials`), and never holds a key itself. cipheron runs beside
the application as a sidecar (a unix socket) or as a service on the network (mutual TLS).

This repository is cipheron's **client side and its protocol**:

- the Go client library, `github.com/nnicora/cipheron`;
- the Java client library, in [java](java);
- the protocol's contract — the wire API, the byte layouts, the conformance vectors and the frozen fixtures — which
  clients in other languages implement;
- the gRPC API definition, `proto/v1`.

cipheron's server (its binary, container image and Helm charts) is distributed separately and uses this repository at
a released version.

## Using the Go library

```sh
go get github.com/nnicora/cipheron
```

```go
c, err := cipheron.New("/run/cipheron/private/cipheron.sock",
	cipheron.WithServerUID(10443),                                     // the uid cipheron's image runs as
	cipheron.WithRequestKeyFile("/etc/app/cipheron/payments-api.key"), // the caller's Ed25519 request key
	cipheron.WithProfileFingerprint("credentials", "sha256:<what keygen ensure printed>"),
	cipheron.WithRequiredPins(),
)
if err != nil {
	return err
}
defer c.Close()

ct, err := c.Encrypt(ctx, "credentials", []byte("s3cret"))
```

The library checks every answer before returning it: answers are signed by the profile's response key, requests are
sealed to the profile's HPKE key and signed by the caller's request key, and a pinned profile refuses any other server.
Read [docs/client-library.md](docs/client-library.md) before writing production code; `go doc github.com/nnicora/cipheron`
and the package's examples are the reference.

An application imports three packages, and no other:

| package | for |
| --- | --- |
| `github.com/nnicora/cipheron` | the library |
| `github.com/nnicora/cipheron/cipherontest` | a test server that speaks the protocol, for an application's tests |
| `github.com/nnicora/cipheron/conformance` | the protocol's vectors and a runner, for a client in another language |

`wire/transport`, `wire/format` and `peercred` are the protocol's implementation, exported for cipheron's server and
for other implementers; they follow the protocol's versions, not the library's API, and an application does not import
them.

## Using the Java library

The Java client library (Java 21 or later, Maven) is in [java](java). It makes the same checks as the Go library, is
held to the same conformance vectors, and is tested against `cipherontest`. It is not published to a repository yet:
`cd java && ./mvnw install` builds it as `io.github.nnicora:cipheron:0.1.0-SNAPSHOT`.

```java
try (CipheronClient c = CipheronClient.builder("/run/cipheron/private/cipheron.sock")
        .serverUid(10443)
        .requestKeyFile(Path.of("/etc/app/cipheron/payments-api.key"))
        .profileFingerprint("credentials", "sha256:<what keygen ensure printed>")
        .requiredPins()
        .build()) {
    byte[] ct = c.encrypt("credentials", "s3cret".getBytes(StandardCharsets.UTF_8));
}
```

[java/README.md](java/README.md) is its guide: options, operations, errors, and how it is tested.

## The protocol

| document | what it is |
| --- | --- |
| [spec/api.md](spec/api.md) | the wire API and protocol, byte by byte: every message, transcript, signature, seal and stored layout, the errors, and the order of a client's checks |
| [spec/compatibility.md](spec/compatibility.md) | every versioned item, which versions a release reads and writes, and the compatibility policy |
| [spec/vectors](spec/vectors) | the conformance vectors and their JSON Schema |
| [spec/frozen](spec/frozen) | the frozen fixtures the vectors are derived from (illustrative test keys only) |
| [proto/v1](proto/v1) | the gRPC service, and its OpenAPI description |

A client in another language is held to the vectors with `conformance.Run` or the `cipheron conformance run` command,
and to the test server's impostors with `cipherontest` ([spec/api.md, Conformance kit](spec/api.md#conformance-kit)).

## Developing

Go 1.27.4 or later. The tests run under the FIPS 140-3 Go Cryptographic Module, as releases are built:

```sh
make check          # build, vet, tests (FIPS), lint, the docs and fixture checks
make test           # GOFIPS140=v1.26.0 go test ./...
make test-race      # the race detector on the client and the protocol
make proto-gen      # regenerate proto/ with the pinned generators (make install-proto-tools)
make java-test         # the Java library: build and tests, against cipherontest (Java 21: JAVA_HOME, else found)
make java-conformance  # the Java library held to the conformance vectors
```

A change to the protocol — a transcript, a layout, a label, a version — lands here first, with the spec, the vectors
and the release record (`wire/transport/testdata/release.txt`); cipheron's server then moves to the new version. The
frozen fixtures in `spec/frozen` are never regenerated to make a test pass (`make check-golden-fixtures`).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache License 2.0: see [LICENSE](LICENSE).
