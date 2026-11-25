# Changelog

Every release of `github.com/nnicora/cipheron` is listed here. A protocol change (a transcript, a layout, a label or
a version a release reads or writes) is called out as such, with what an existing deployment must do.

## Unreleased

The first release as a repository of its own: the Go client library, the protocol's specification, conformance
vectors and frozen fixtures, the gRPC API definition, and the test server.

- Transcript version 1; ciphertext formats 3, 4, 5 and 6 read and written; tenant key blob, segmented object, key
  statement, key statement export and encrypted JSON field version 1 (`wire/transport/testdata/release.txt`).
- `WithTransport(TransportGRPC | TransportHTTP)`: the JSON API over HTTP/1.1 is available through `New`.
- `IsSocketAddress`: how `New` reads an address, for tools that choose options by it.
- The Java client library (`java/`, Java 21, Maven; built from source, not yet published): every operation, over the
  socket and mutual TLS, gRPC and the JSON API, with the Go library's checks; held to the conformance vectors
  (`make java-conformance`) and tested against `cipherontest` (`make java-test`). No protocol change.
