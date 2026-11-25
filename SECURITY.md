# Security policy

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub's private vulnerability reporting: the repository's
**Security** tab, **Report a vulnerability**. Do not open a public issue, pull request or discussion for it.

A useful report says what is affected (the Go or the Java library, the protocol, the conformance kit or the test server), the
version or commit, what an attacker needs (a position on the network, a process on the host, a caller's credentials,
…) and what they gain, with steps or a test that shows it.

## Scope

In scope: the Go library, the Java library (`java/`), and everything they rely on in this repository — the request and answer signatures, the
HPKE seals, the transcripts and labels, the stored layouts, the pins and their checks, the peer-credential check on
the socket, the TLS configuration each library builds — and the protocol as [spec/api.md](spec/api.md) specifies it,
including a flaw in the specification that a conforming implementation inherits.

`cipherontest` is a test server: it is not hardened and must never hold real data; a weakness that only affects it is
not a vulnerability unless it makes a client's test pass that a real cipheron would fail. The keys in `spec/frozen` and
the conformance vectors are published test keys (ILLUSTRATIVE) and protect nothing.

## Supported versions

Until 1.0, only the latest release receives fixes.
