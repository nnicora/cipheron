package conformance

// generate_cases_test.go — the kit's cases of owner decision S34 and of DV-3, DV-4 and DV-5 (2026-11-19), added to the
// suite buildSuite derives: the tenant layouts from the frozen set (tenant key blobs, tenant fingerprints, tenant-signed
// messages, the version-2 fingerprint), the tenant rule and the refusals' classes from the rules, the layouts' refusals
// from the frozen bytes and the layouts' registry, and the signature edges (S not below L, a signature of the wrong
// length, a keys signature under another nonce).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

// refusedOut is the refusal output.
var refusedOut = RefusedOutput{Refused: true}

// addTenantCases adds the version-2 fingerprint, every frozen blob's header and fingerprint, every frozen tenant-signed
// message, and the tenant rule's cases.
func addTenantCases(t *testing.T, b *builder, m *fzManifest) {
	t.Helper()
	for _, f := range m.Derivations.Fingerprints {
		in := FingerprintInput{Profile: f.Profile, Tenancy: f.Tenancy,
			HPKESuite:     HPKESuiteInput{KEM: f.HPKESuite.KEM, KDF: f.HPKESuite.KDF, AEAD: f.HPKESuite.AEAD},
			HPKEPublicKey: Hex(f.HPKEPublicKey), ResponseAlgorithm: f.ResponseAlgorithm, ResponsePublicKey: Hex(f.ResponsePublicKey)}
		for _, a := range f.Additional {
			in.Additional = append(in.Additional, IdentityKeyInput{Role: a.Role,
				Suite: HPKESuiteInput{KEM: a.Suite.KEM, KDF: a.Suite.KDF, AEAD: a.Suite.AEAD}, Algorithm: a.Algorithm,
				PublicKey: Hex(a.PublicKey)})
		}
		b.add(fmt.Sprintf("fingerprint/version-%d/%s", f.Version, f.Profile), KindFingerprint,
			"an identity under another HPKE suite with an added key: fingerprint version 2, which covers the suite, the "+
				"algorithm and every added key", in, FingerprintOutput{Fingerprint: f.Fingerprint})
	}

	blob := func(id, note, profile string, k fzBlob) {
		created, err := time.Parse(time.RFC3339, k.Created)
		if err != nil {
			t.Fatal(err)
		}
		b.add("tenantKey/"+id, KindTenantKey, note, TenantKeyInput{Blob: Hex(k.Blob), Profile: profile, Tenant: k.Tenant},
			TenantKeyOutput{KeyID: Hex(k.KeyID), SigningPublicKey: Hex(k.SigningPublicKey), WrappingVersion: k.WrappingVersion,
				Created: created.Unix(), Fingerprint: k.Fingerprint})
		b.add("tenantFingerprint/"+id, KindTenantFingerprint, "the profile, the tenant, the key id and the signing key",
			TenantFingerprintInput{Profile: profile, Tenant: k.Tenant, KeyID: Hex(k.KeyID), SigningPublicKey: Hex(k.SigningPublicKey)},
			FingerprintOutput{Fingerprint: k.Fingerprint})
	}
	for _, d := range m.Profiles {
		for j, k := range d.Tenants {
			note := "a blob of the call's profile and tenant: what its header names"
			switch {
			case len(k.Tenant) == transport.MaxTenantLen:
				note = "the longest tenant id (2048 bytes, every byte from 0x21 to 0x7E in turn)"
			case strings.ContainsAny(k.Tenant, `|"\/%`):
				note = `a tenant id holding '|', '"', '\', '/' and '%'`
			case len(k.RewrappedFrom) > 0:
				note = "a rewrapped blob: its key id, signing key, creation time and fingerprint are its key's"
			}
			blob(fmt.Sprintf("%s/%d", d.Name, j), note, d.Name, k)
		}
	}
	for _, k := range m.Derivations.TenantKeys {
		blob("at-the-bound", "a blob of MaxTenantKeyLen (2369) bytes: the longest profile name, tenant id and wrapping "+
			"version id", k.Profile, k.fzBlob)
	}

	for i, s := range m.Transcripts.TenantSignedMessages {
		b.add(fmt.Sprintf("tenantSignedMessage/%s/%d", s.Profile, i), KindTenantSignedMessage,
			"lp(label) lp(profile) lp(tenant) lp(data): what a derived profile's key signs for a tenant",
			TenantSignedMessageInput{Profile: s.Profile, Tenant: s.Tenant, Data: Hex(s.Data)}, MessageOutput{Message: Hex(s.Message)})
	}

	// The tenant rule (transport.ValidTenant), written from the rule: every tenant id of the frozen set, the range's
	// ends, and what the rule refuses.
	seen := map[string]bool{}
	var frozen []string
	collect := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			frozen = append(frozen, s)
		}
	}
	for _, d := range m.Profiles {
		for _, c := range d.Ciphertexts {
			collect(c.Tenant)
		}
		for _, k := range d.Tenants {
			collect(k.Tenant)
		}
	}
	for i, s := range frozen {
		b.add(fmt.Sprintf("tenantId/frozen-%d", i), KindTenantID, "a tenant id of the frozen set", TenantIDInput{Tenant: s},
			ValidOutput{Valid: true})
	}
	longest := strings.Repeat("t", transport.MaxTenantLen)
	for _, c := range []struct {
		id, note, tenant string
		valid            bool
	}{
		{"lowest", "one byte, 0x21 ('!'): the range's first", "!", true},
		{"highest", "one byte, 0x7E ('~'): the range's last", "~", true},
		{"longest", "MaxTenantLen (2048) bytes", longest, true},
		{"empty", "no byte: a tenant id is 1 to 2048 bytes", "", false},
		{"too-long", "2049 bytes: one over MaxTenantLen", longest + "t", false},
		{"space", "a space (0x20), below the range", "t alpha", false},
		{"trailing-space", "a trailing space: no id has an invisible end", "t_alpha ", false},
		{"delete", "0x7F, above the range", "t\x7f", false},
		{"nul", "0x00, a control byte", "t\x00", false},
		{"tab", "a tab, a control byte", "t\tx", false},
		{"non-ascii", "a byte above 0x7E (UTF-8 of U+00E9)", "té", false},
	} {
		b.add("tenantId/"+c.id, KindTenantID, c.note, TenantIDInput{Tenant: c.tenant}, ValidOutput{Valid: c.valid})
	}
}

// addRefusalCases adds the layouts' refusals (S34), derived from the catalog (transport.Release().Schemes()): for every
// ciphertext format the release reads, its header cut short
// and its ciphertext one byte shorter than the format's overhead, and for the formats that name a master version an id
// of length 0, one over MaxMasterVersionIDLen and one of a byte the id grammar does not have; the format bytes and the
// blob versions no layout has; and a blob of another tenant or profile, with a trailing byte, over MaxTenantKeyLen,
// truncated, of an invalid tenant or profile, or with no creation time.
func addRefusalCases(t *testing.T, b *builder, m *fzManifest) {
	t.Helper()
	sample := map[byte][]byte{} // a frozen ciphertext of each format
	keep := func(cs []fzCiphertext) {
		for _, c := range cs {
			if sample[c.Format] == nil {
				sample[c.Format] = c.Ciphertext
			}
		}
	}
	for _, d := range m.Profiles {
		keep(d.Ciphertexts)
		for _, k := range d.Tenants {
			keep(k.Ciphertexts)
		}
	}
	ct := func(id, note string, c []byte) {
		b.add("ciphertextKeyID/refused/"+id, KindCiphertextKeyID, note, CiphertextKeyIDInput{Ciphertext: c}, refusedOut)
	}
	// The cases come from the catalog: every ciphertext scheme the release reads, in the order of its version.
	p := transport.Release()
	var layouts []format.SchemeInfo
	for i := range p.Schemes() {
		if i.Kind == "ciphertext" {
			layouts = append(layouts, i)
		}
	}
	famMagic := layouts[0].Marker[:len(layouts[0].Marker)-1]
	magic := len(famMagic)
	for _, l := range layouts {
		c := sample[byte(l.Version)]
		if c == nil {
			t.Fatalf("the frozen set has no ciphertext of %s", l.Name)
		}
		k, err := transport.ParseKeyID(p, c)
		if err != nil {
			t.Fatal(err)
		}
		f := fmt.Sprintf("format-%d", l.Version)
		ct(f+"/header-truncated", l.Name+": its header one byte short", c[:k.HeaderLen-1])
		ct(f+"/shorter-than-overhead", l.Name+": one byte shorter than the ciphertext of an empty plaintext",
			c[:transport.OverheadOf(p, k)-1])
		switch transport.NamesOf(p, k) {
		case transport.NamesTenantKey:
			ct(f+"/key-id-truncated", l.Name+": the tenant key id cut short", c[:magic+1+transport.TenantKeyIDLen-1])
		case transport.NamesMasterVersion:
			rest := c[magic+2+len(k.MasterVersion):]
			header := func(id string) []byte {
				return append(append(append(bytes.Clone(c[:magic+1]), byte(len(id))), id...), rest...)
			}
			ct(f+"/version-id-empty", l.Name+": a master version id of length 0", header(""))
			ct(f+"/version-id-too-long", fmt.Sprintf("%s: a master version id of %d bytes, one over the bound", l.Name,
				transport.MaxMasterVersionIDLen+1), header(strings.Repeat("v", transport.MaxMasterVersionIDLen+1)))
			ct(f+"/version-id-character", l.Name+": a master version id holding '/', outside [A-Za-z0-9._-]",
				header(k.MasterVersion[:len(k.MasterVersion)-1]+"/"))
			ct(f+"/version-id-space", l.Name+": a master version id holding a space", header(" "+k.MasterVersion[1:]))
		}
	}
	first, last := byte(layouts[0].Version), byte(layouts[len(layouts)-1].Version)
	var unknown []byte
	for _, v := range []byte{first - 1, last + 1, 9, 0xff} {
		if _, err := format.Read(p, transport.Ciphertexts(), uint32(v)); err != nil && !slices.Contains(unknown, v) {
			unknown = append(unknown, v)
		}
	}
	for _, v := range unknown {
		c := bytes.Clone(sample[first])
		c[magic] = v
		ct(fmt.Sprintf("format-%d", v), fmt.Sprintf("format %d: no layout has it", v), c)
	}
	other := bytes.Clone(sample[first])
	other[magic-1]++
	ct("another-magic", "another magic than "+famMagic, other)
	ct("magic-only", "the magic and nothing after it", []byte(famMagic))
	ct("empty", "no byte", []byte{})

	// The blobs: t_beta's (docs, a short tenant) and the one at the bound.
	var docs *fzBlob
	var profile string
	for _, d := range m.Profiles {
		for i, k := range d.Tenants {
			if k.Tenant == "t_beta" {
				docs, profile = &d.Tenants[i], d.Name
			}
		}
	}
	if docs == nil || len(m.Derivations.TenantKeys) != 1 {
		t.Fatal("the frozen set has no t_beta blob, or no blob at the bound")
	}
	bound := m.Derivations.TenantKeys[0]
	blob := func(id, note string, in TenantKeyInput) {
		b.add("tenantKey/refused/"+id, KindTenantKey, note, in, refusedOut)
	}
	in := func(c []byte) TenantKeyInput { return TenantKeyInput{Blob: c, Profile: profile, Tenant: docs.Tenant} }
	blob("another-tenant", "a blob of another tenant than the call's", TenantKeyInput{Blob: Hex(docs.Blob), Profile: profile,
		Tenant: docs.Tenant + "x"})
	blob("another-profile", "a blob of another profile than the call's", TenantKeyInput{Blob: Hex(docs.Blob), Profile: m.Profiles[0].Name,
		Tenant: docs.Tenant})
	for v := byte(0); v <= transport.TenantKeyVersion+1; v++ {
		if _, err := format.Read(p, transport.TenantKeys(), uint32(v)); err != nil {
			c := bytes.Clone(docs.Blob)
			c[len(transport.TenantKeyMagic)] = v
			blob(fmt.Sprintf("version-%d", v), fmt.Sprintf("version %d: no layout has it", v), in(c))
		}
	}
	another := bytes.Clone(docs.Blob)
	another[len(transport.TenantKeyMagic)-1]++
	blob("another-magic", "another magic than "+transport.TenantKeyMagic, in(another))
	blob("trailing-byte", "a byte after the sealed part", in(append(bytes.Clone(docs.Blob), 0)))
	blob("truncated", "the sealed part one byte short", in(docs.Blob[:len(docs.Blob)-1]))
	blob("over-the-bound", "the blob at MaxTenantKeyLen with a byte more", TenantKeyInput{Blob: append(bytes.Clone(bound.Blob), 0),
		Profile: bound.Profile, Tenant: bound.Tenant})
	// The header's fields, rewritten in place (each as long as before): "CPT1" | 1 | key id (16) | lp(profile) |
	// lp(tenant) | public key (32) | len | wrapping version | created (8) | salt | sealed.
	at := len(transport.TenantKeyMagic) + 1 + transport.TenantKeyIDLen + 4
	tenantAt := at + len(profile) + 4
	createdAt := tenantAt + len(docs.Tenant) + 32 + 1 + len(docs.WrappingVersion)
	if binary.BigEndian.Uint32(docs.Blob[at-4:]) != uint32(len(profile)) || string(docs.Blob[tenantAt:tenantAt+len(docs.Tenant)]) != docs.Tenant {
		t.Fatal("t_beta's blob is not of the layout this generator rewrites")
	}
	bad := bytes.Clone(docs.Blob)
	bad[tenantAt+1] = ' '
	blob("tenant-not-an-id", "the blob's tenant holds a space: not a tenant id, whatever the call names",
		TenantKeyInput{Blob: bad, Profile: profile, Tenant: string(bad[tenantAt : tenantAt+len(docs.Tenant)])})
	bad = bytes.Clone(docs.Blob)
	bad[at] -= 'a' - 'A'
	blob("profile-not-a-name", "the blob's profile holds an upper-case letter: not a profile name",
		TenantKeyInput{Blob: bad, Profile: string(bad[at : at+len(profile)]), Tenant: docs.Tenant})
	bad = bytes.Clone(docs.Blob)
	copy(bad[createdAt:createdAt+8], make([]byte, 8))
	blob("created-zero", "a creation time of 0: not after 1970", in(bad))
}

// ed25519L is the order of Ed25519's base point, L = 2^252 + 27742317777372353535851937790883648493.
var ed25519L = func() *big.Int {
	l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
}()

// plusL is sig with its S (the second 32 bytes, little-endian) increased by L: the same point equation, a non-canonical
// S that RFC 8032 (section 5.1.7) requires a verifier to refuse.
func plusL(sig []byte) []byte {
	le := func(b []byte) []byte {
		r := bytes.Clone(b)
		slices.Reverse(r)
		return r
	}
	s := new(big.Int).SetBytes(le(sig[32:]))
	s.Add(s, ed25519L)
	out := make([]byte, 32)
	s.FillBytes(out)
	return append(bytes.Clone(sig[:32]), le(out)...)
}

// addSignatureEdgeCases adds the signatures a verifier refuses whatever the key (DV-3): S not below L, 63 and 65 bytes;
// and a PublicKey answer's keys signature checked under another nonce (DV-5): a replayed answer.
func addSignatureEdgeCases(b *builder, m *fzManifest, requestKey Hex, responseKeys map[string]Hex) {
	edges := []struct{ id, note string }{
		{"s-plus-l", "S increased by L (S >= L): the same equation, refused by RFC 8032 section 5.1.7"},
		{"63-bytes", "a signature of 63 bytes"},
		{"65-bytes", "a signature of 65 bytes"},
	}
	edge := func(i int, sig []byte) []byte {
		switch i {
		case 0:
			return plusL(sig)
		case 1:
			return sig[:63]
		}
		return append(bytes.Clone(sig), 0)
	}
	r := m.Transcripts.Requests[0]
	for i, e := range edges {
		b.add(fmt.Sprintf("requestSignature/0-%s/%s", r.Op, e.id), KindRequestSignature, e.note,
			SignatureInput{PublicKey: requestKey, Transcript: Hex(r.Transcript), Signature: edge(i, r.Signature)}, ValidOutput{Valid: false})
	}
	a := m.Transcripts.Responses[0]
	for i, e := range edges {
		b.add(fmt.Sprintf("responseSignature/0-%s/%s", a.Op, e.id), KindResponseSignature, e.note,
			SignatureInput{PublicKey: responseKeys[a.Profile], Transcript: Hex(a.Transcript), Signature: edge(i, a.Signature)},
			ValidOutput{Valid: false})
	}
	d := m.Profiles[0]
	keys := make([]transport.SigningKey, 0, len(d.SigningKeys))
	for _, k := range d.SigningKeys {
		keys = append(keys, transport.SigningKey{KeyID: k.KeyID, State: transport.SigningKeyState(k.State), PublicKey: []byte(k.PublicKey)})
	}
	tx, err := transport.SigningKeysTranscript(transport.Release(), d.Name, transport.Tenancy(d.Tenancy), d.ContextDigest, flip(d.KeysNonce), keys)
	if err != nil {
		b.t.Fatal(err)
	}
	b.add("responseSignature/keys-"+d.Name+"/another-nonce", KindResponseSignature,
		"the profile's keys signature checked for a PublicKey asked under another nonce: an answer replayed from another fetch",
		SignatureInput{PublicKey: responseKeys[d.Name], Transcript: tx, Signature: Hex(d.KeysSignature)}, ValidOutput{Valid: false})
}

// addErrorClassCases adds the refusals' classes and retry rules (S34, DV-6), written from the protocol's table
// (transport.go's reasons, each with the code cipheron answers it with) and from what is not cipheron's.
func addErrorClassCases(b *builder) {
	ms := func(n int64) *int64 { return &n }
	ours := func(reason string) *ErrorInfoInput {
		return &ErrorInfoInput{Domain: transport.ErrorDomain, Reason: reason}
	}
	for _, c := range []struct {
		id, note, code string
		info           *ErrorInfoInput
		delay          *int64
		class, retry   string
		wait           int64
	}{
		{"busy", "cipheron at a limit: retried as a new request, not before the RetryInfo", "RESOURCE_EXHAUSTED",
			ours(transport.ReasonBusy), ms(1000), "busy", "transient", 1000},
		{"starting", "signed before the answering process started: nothing ran; signed again and sent once more after " +
			"the RetryInfo, whatever the operation", "UNAVAILABLE", ours(transport.ReasonStarting), ms(250), "starting", "resign", 250},
		{"starting-no-retry-info", "the start barrier without a RetryInfo: signed again at once", "UNAVAILABLE",
			ours(transport.ReasonStarting), nil, "starting", "resign", 0},
		{"no-writer", "no master version writes at the replica's clock: another replica may", "UNAVAILABLE",
			ours(transport.ReasonNoWriter), nil, "noWriter", "transient", 0},
		{"profile-sealed", "the profile is sealed on this replica", "UNAVAILABLE", ours(transport.ReasonProfileSealed), ms(5000),
			"profileSealed", "transient", 5000},
		{"audit-unavailable", "the audit trail could not record the request: nothing was done", "UNAVAILABLE",
			ours(transport.ReasonAuditUnavailable), ms(1000), "auditUnavailable", "transient", 1000},
		{"connection-lost", "UNAVAILABLE without an ErrorInfo: the connection lost, or a replica draining", "UNAVAILABLE", nil,
			nil, "unavailable", "transient", 0},
		{"unavailable-unknown-reason", "a reason this table does not have: not retried", "UNAVAILABLE",
			ours("CIPHERON_SOMETHING_ELSE"), ms(10), "unavailable", "never", 0},
		{"starting-of-another-domain", "CIPHERON_STARTING in another ErrorInfo domain is no reason of cipheron's: not " +
			"re-signed, not retried", "UNAVAILABLE", &ErrorInfoInput{Domain: "proxy.example", Reason: transport.ReasonStarting},
			ms(10), "unavailable", "never", 0},
		{"starting-on-permission", "a reason on another code than cipheron answers it with counts for nothing",
			"PERMISSION_DENIED", ours(transport.ReasonStarting), ms(10), "permissionDenied", "never", 0},
		{"busy-on-invalid", "CIPHERON_BUSY on INVALID_ARGUMENT: invalid input, never retried", "INVALID_ARGUMENT",
			ours(transport.ReasonBusy), ms(1000), "invalidInput", "never", 0},
		{"exhausted", "RESOURCE_EXHAUSTED without cipheron's busy reason (a size refusal, something on the way)",
			"RESOURCE_EXHAUSTED", nil, nil, "resourceExhausted", "never", 0},
		{"exhausted-retry-info-only", "a RetryInfo alone makes nothing retryable", "RESOURCE_EXHAUSTED", nil, ms(1000),
			"resourceExhausted", "never", 0},
		{"permission-denied", "not until the configuration changes", "PERMISSION_DENIED", nil, nil, "permissionDenied", "never", 0},
		{"invalid-input", "the same call fails the same way", "INVALID_ARGUMENT", nil, nil, "invalidInput", "never", 0},
		{"key-version-unavailable", "the version is not listed on the replica: the data is not lost", "INVALID_ARGUMENT",
			ours(transport.ReasonKeyVersionUnavailable), nil, "keyVersionUnavailable", "never", 0},
		{"associated-data", "associated data missing or not expected", "INVALID_ARGUMENT", ours(transport.ReasonAssociatedData),
			nil, "associatedData", "never", 0},
		{"batch-limit", "a batch over the configured limits", "INVALID_ARGUMENT", ours(transport.ReasonBatchLimit), nil,
			"batchLimit", "never", 0},
		{"unimplemented", "the server does not have the call", "UNIMPLEMENTED", nil, nil, "unsupported", "never", 0},
		{"internal", "a failure the server does not describe", "INTERNAL", nil, nil, "internal", "never", 0},
		{"not-found", "a code cipheron does not answer", "NOT_FOUND", nil, nil, "other", "never", 0},
	} {
		b.add("errorClass/"+c.id, KindErrorClass, c.note, ErrorClassInput{Code: c.code, ErrorInfo: c.info, RetryDelayMS: c.delay},
			ErrorClassOutput{Class: c.class, Retry: c.retry, MinWaitMS: c.wait})
	}
}
