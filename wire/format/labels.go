package format

// labels.go — THE purpose table: every label cipheron and its clients derive a key under, sign, hash or seal under is
// built here, from typed fields, in one buffer. No variadic strings. This file holds the only spellings of a namespace
// (make check-label-namespace allowlists it by name).
//
// Why cipheron's server label words are here, in the protocol's packages, beside its clients': injectivity is a property of
// the whole namespace — every word of "cipheron/v1|", client or server, must differ from every other and from every
// shape's fixed words — and only a table that sees all of them can be checked (labels_test.go); the client library's
// packages cannot import cmd/.
// Nothing is disclosed: api.md and security.md publish every label.

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Namespace is a label namespace: 2 to 64 bytes of printable ASCII whose only "|" is the last, so no namespace begins
// another. A suite owns one. The production namespaces are built in this file only: the protocol's "cipheron/v1|"
// (HKDFSHA256AESGCM's, and every label below but SealSlot's) and the seal slots' "cipheron/seal/v1|". The zero
// Namespace is none.
type Namespace struct{ s string }

// String is the namespace's bytes.
func (n Namespace) String() string { return n.s }

// The production namespaces: their only spellings.
var (
	protocolNamespace = Namespace{"cipheron/v1|"}
	sealNamespace     = Namespace{"cipheron/seal/v1|"}
)

// testNamespacePrefix opens every TestNamespace.
const testNamespacePrefix = "cipheron-test/"

// TestNamespace is a namespace for a test's suite: "cipheron-test/v1|" for name "", "cipheron-test/<name>/v1|"
// otherwise (name: 1 to 16 bytes of [a-z0-9-]; another panics). It begins with "cipheron-test/", so it is none of the
// production namespaces and begins none of them. Only test code calls it (check-label-namespace).
func TestNamespace(name string) Namespace {
	if len(name) > 16 {
		panic(fmt.Errorf("%w: %q is not a test namespace's name", errRegistry, name))
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			panic(fmt.Errorf("%w: %q is not a test namespace's name", errRegistry, name))
		}
	}
	if name == "" {
		return Namespace{testNamespacePrefix + "v1|"}
	}
	return Namespace{testNamespacePrefix + name + "/v1|"}
}

// validNamespace reports whether ns can be a label namespace: 2 to 64 bytes of printable ASCII (0x21 to 0x7E) whose
// only "|" is the last. So no namespace begins another: one that did would hold its "|" before its own end.
func validNamespace(ns string) bool {
	if len(ns) < 2 || len(ns) > 64 || ns[len(ns)-1] != '|' {
		return false
	}
	for i := 0; i < len(ns)-1; i++ {
		if c := ns[i]; c < '!' || c > '~' || c == '|' {
			return false
		}
	}
	return true
}

// Fixed is a label of the protocol's namespace and one word: "cipheron/v1|" <word>.
type Fixed uint8

const (
	LabelSignedRequest     Fixed = iota + 1 // "signed_request": the request transcript
	LabelSignedResponse                     // "signed_response": the response transcript
	LabelDigest                             // "digest": a payload digest
	LabelFingerprint                        // "fingerprint": fingerprint derivation 1
	LabelFingerprint2                       // "fingerprint2": fingerprint derivation 2
	LabelTenantFingerprint                  // "tenant-fingerprint"
	LabelSignedKeys                         // "signed_keys": the signing-keys transcript
	LabelSigningKeyID                       // "signing-key-id": an Ed25519 signing key's id
	LabelSigningKeyID2                      // "signing-key-id2": a signing key's id of any other algorithm
	LabelContext                            // "context": the key-context digest
	LabelTenantSignature                    // "tenant-signature": a derived profile's tenant-bound message
	LabelKeyStatement                       // "key_statement"
	LabelSegment                            // "segment": a segment's associated data
	LabelJSONField                          // "json-field": a JSON field's associated data
	LabelKeysetHeader                       // "keyset-header": a keyset wrap's additional data
	LabelAuditTenant                        // "audit-tenant": the audit log's tenant pseudonym
	LabelEnsureRecordKey                    // "ensure-record-key": the ensure record's MAC key
	LabelEnsureRecord                       // "ensure-record": the ensure record's MAC
	LabelNonLiveProfile                     // "non-live-profile": the digest of a profile's non-live configuration
)

// fixedWords are the Fixed labels' words, by value.
var fixedWords = [...]string{
	LabelSignedRequest:     "signed_request",
	LabelSignedResponse:    "signed_response",
	LabelDigest:            "digest",
	LabelFingerprint:       "fingerprint",
	LabelFingerprint2:      "fingerprint2",
	LabelTenantFingerprint: "tenant-fingerprint",
	LabelSignedKeys:        "signed_keys",
	LabelSigningKeyID:      "signing-key-id",
	LabelSigningKeyID2:     "signing-key-id2",
	LabelContext:           "context",
	LabelTenantSignature:   "tenant-signature",
	LabelKeyStatement:      "key_statement",
	LabelSegment:           "segment",
	LabelJSONField:         "json-field",
	LabelKeysetHeader:      "keyset-header",
	LabelAuditTenant:       "audit-tenant",
	LabelEnsureRecordKey:   "ensure-record-key",
	LabelEnsureRecord:      "ensure-record",
	LabelNonLiveProfile:    "non-live-profile",
}

// fixedLabels are the Fixed labels, built once at initialisation: String allocates nothing.
var fixedLabels = func() (out [len(fixedWords)]string) {
	for f := 1; f < len(fixedWords); f++ {
		out[f] = protocolNamespace.s + fixedWords[f]
	}
	return out
}()

// String is the label, built once at initialisation: no allocation per call. A value outside the constants above is a
// programming error: it panics ("format: Fixed(%d) is no label").
func (f Fixed) String() string {
	if f == 0 || int(f) >= len(fixedLabels) {
		panic(fmt.Sprintf("format: Fixed(%d) is no label", uint8(f)))
	}
	return fixedLabels[f]
}

// Scoped is a label of the protocol's namespace, a profile and one word: "cipheron/v1|" <profile> "|" <word>.
type Scoped uint8

const (
	LabelStorageKey    Scoped = iota + 1 // "storage": a master version's storage data key
	LabelTenantRootKey                   // "tenant-root": a derived profile's tenant root key
	LabelTenantWrapKey                   // "tenant-wrap": a wrapped profile's tenant-wrapping key
	LabelKeysetWrap                      // "keyset-wrap": the keyset's wrapping key
	LabelKeyCheck                        // "kcv": a master version's check key
)

// scopedWords are the Scoped labels' words, each behind its "|", by value.
var scopedWords = [...]string{
	LabelStorageKey:    "|storage",
	LabelTenantRootKey: "|tenant-root",
	LabelTenantWrapKey: "|tenant-wrap",
	LabelKeysetWrap:    "|keyset-wrap",
	LabelKeyCheck:      "|kcv",
}

// For is the label of profile, which every caller has checked with transport.ValidProfile (no "|"), so one label names
// one (profile, word). A value outside the constants above panics ("format: Scoped(%d) is no label").
func (s Scoped) For(profile string) string {
	if s == 0 || int(s) >= len(scopedWords) {
		panic(fmt.Sprintf("format: Scoped(%d) is no label", uint8(s)))
	}
	return protocolNamespace.s + profile + scopedWords[s]
}

// The words of the shapes below.
const (
	wordMessage        = "|message"
	wordMessage4       = "|message4|"
	wordTenantBlobWrap = "tenant-blob-wrap"
	wordTenantStorage  = "|tenant-storage|"
	wordRequest        = "request|"
	wordResponse       = "response|"
)

// TenantMessageInfo is the item info of ciphertext formats 3 and 6 under ns: ns <profile> "|" <tenant> "|message",
// then salt (nil: the label alone). A profile name cannot contain "|", so the profile ends at the first "|" after the
// namespace, and the tenant is everything between it and the fixed "|message" suffix and the salt, whose length is
// the scheme's: the label names exactly one (profile, tenant).
func TenantMessageInfo(ns Namespace, profile, tenant string, salt []byte) string {
	var b strings.Builder
	b.Grow(len(ns.s) + len(profile) + 1 + len(tenant) + len(wordMessage) + len(salt))
	b.WriteString(ns.s)
	b.WriteString(profile)
	b.WriteByte('|')
	b.WriteString(tenant)
	b.WriteString(wordMessage)
	b.Write(salt)
	return b.String()
}

// VersionedMessageInfo is the item info of formats 4 and 5 under ns: ns <profile> "|message4|" lp(versionID)
// lp(tenant), then salt. It names the version and the tenant, so a data key presented under another (version, tenant)
// derives another key even before the tag is checked.
func VersionedMessageInfo(ns Namespace, profile, versionID, tenant string, salt []byte) string {
	var b strings.Builder
	b.Grow(len(ns.s) + len(profile) + len(wordMessage4) + 8 + len(versionID) + len(tenant) + len(salt))
	b.WriteString(ns.s)
	b.WriteString(profile)
	b.WriteString(wordMessage4)
	writeLP(&b, versionID)
	writeLP(&b, tenant)
	b.Write(salt)
	return b.String()
}

// writeLP writes s behind its 4-byte big-endian length.
func writeLP(b *strings.Builder, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	b.Write(n[:])
	b.WriteString(s)
}

// TenantBlobWrapInfo is a tenant key blob's wrap info under ns: lp(ns "tenant-blob-wrap") lp(profile) lp(tenant)
// lp(versionID), then salt (injective only for the scheme's fixed salt length). Its first byte is 0x00, so it equals
// no label that opens with a namespace.
func TenantBlobWrapInfo(ns Namespace, profile, tenant, versionID string, salt []byte) string {
	var b strings.Builder
	b.Grow(16 + len(ns.s) + len(wordTenantBlobWrap) + len(profile) + len(tenant) + len(versionID) + len(salt))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(ns.s)+len(wordTenantBlobWrap)))
	b.Write(n[:])
	b.WriteString(ns.s)
	b.WriteString(wordTenantBlobWrap)
	writeLP(&b, profile)
	writeLP(&b, tenant)
	writeLP(&b, versionID)
	b.Write(salt)
	return b.String()
}

// TenantStorage is a derived tenant's storage key info: "cipheron/v1|" <profile> "|tenant-storage|" lp(tenant).
func TenantStorage(profile, tenant string) string {
	b := make([]byte, 0, len(protocolNamespace.s)+len(profile)+len(wordTenantStorage)+4+len(tenant))
	b = append(append(append(b, protocolNamespace.s...), profile...), wordTenantStorage...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(tenant)))
	return string(append(b, tenant...))
}

// AppendRequestContext appends "cipheron/v1|request|" <profile> "|" <op>, then "|" <tenant> unless tenant is "", to
// dst: the context of a request payload's HPKE info.
func AppendRequestContext(dst []byte, profile, op, tenant string) []byte {
	return appendContext(dst, wordRequest, profile, op, tenant)
}

// AppendResponseContext is AppendRequestContext's "response|" context: a Decrypt answer's HPKE info.
func AppendResponseContext(dst []byte, profile, op, tenant string) []byte {
	return appendContext(dst, wordResponse, profile, op, tenant)
}

func appendContext(dst []byte, direction, profile, op, tenant string) []byte {
	dst = append(append(append(dst, protocolNamespace.s...), direction...), profile...)
	dst = append(append(dst, '|'), op...)
	if tenant != "" {
		dst = append(append(dst, '|'), tenant...)
	}
	return dst
}

// SealSlot is the slot context a kms_wrapped shard is bound to: "cipheron/seal/v1|" <profile> "|" <version> "|"
// <index>.
func SealSlot(profile, version string, index int) string {
	b := make([]byte, 0, len(sealNamespace.s)+len(profile)+len(version)+2+20)
	b = append(append(append(b, sealNamespace.s...), profile...), '|')
	b = append(append(b, version...), '|')
	return string(strconv.AppendInt(b, int64(index), 10))
}
