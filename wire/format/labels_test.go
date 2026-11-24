package format

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestEveryLabelByteForByte: every label of the purpose table, spelled out.
func TestEveryLabelByteForByte(t *testing.T) {
	fixed := map[Fixed]string{
		LabelSignedRequest: "cipheron/v1|signed_request", LabelSignedResponse: "cipheron/v1|signed_response",
		LabelDigest: "cipheron/v1|digest", LabelFingerprint: "cipheron/v1|fingerprint",
		LabelFingerprint2: "cipheron/v1|fingerprint2", LabelTenantFingerprint: "cipheron/v1|tenant-fingerprint",
		LabelSignedKeys: "cipheron/v1|signed_keys", LabelSigningKeyID: "cipheron/v1|signing-key-id",
		LabelSigningKeyID2: "cipheron/v1|signing-key-id2", LabelContext: "cipheron/v1|context",
		LabelTenantSignature: "cipheron/v1|tenant-signature", LabelKeyStatement: "cipheron/v1|key_statement",
		LabelSegment: "cipheron/v1|segment", LabelJSONField: "cipheron/v1|json-field",
		LabelKeysetHeader: "cipheron/v1|keyset-header", LabelAuditTenant: "cipheron/v1|audit-tenant",
		LabelEnsureRecordKey: "cipheron/v1|ensure-record-key", LabelEnsureRecord: "cipheron/v1|ensure-record",
		LabelNonLiveProfile: "cipheron/v1|non-live-profile",
	}
	if len(fixed) != len(fixedWords)-1 {
		t.Fatalf("%d fixed labels spelled, %d in the table", len(fixed), len(fixedWords)-1)
	}
	for f, want := range fixed {
		if f.String() != want {
			t.Errorf("Fixed(%d): %q, want %q", f, f.String(), want)
		}
	}
	scoped := map[Scoped]string{LabelStorageKey: "cipheron/v1|d|storage", LabelTenantRootKey: "cipheron/v1|d|tenant-root",
		LabelTenantWrapKey: "cipheron/v1|d|tenant-wrap", LabelKeysetWrap: "cipheron/v1|d|keyset-wrap",
		LabelKeyCheck: "cipheron/v1|d|kcv"}
	for s, want := range scoped {
		if s.For("d") != want {
			t.Errorf("Scoped(%d): %q", s, s.For("d"))
		}
	}
	ns, salt := protocolNamespace, []byte{0xAA, 0xBB}
	for got, want := range map[string]string{
		TenantMessageInfo(ns, "d", "t|x", salt):                        "cipheron/v1|d|t|x|message\xAA\xBB",
		VersionedMessageInfo(ns, "d", "v1", "t", salt):                 "cipheron/v1|d|message4|\x00\x00\x00\x02v1\x00\x00\x00\x01t\xAA\xBB",
		TenantBlobWrapInfo(ns, "d", "t", "v1", salt):                   "\x00\x00\x00\x1ccipheron/v1|tenant-blob-wrap\x00\x00\x00\x01d\x00\x00\x00\x01t\x00\x00\x00\x02v1\xAA\xBB",
		TenantStorage("d", "t"):                                        "cipheron/v1|d|tenant-storage|\x00\x00\x00\x01t",
		string(AppendRequestContext([]byte("x"), "d", "encrypt", "t")): "xcipheron/v1|request|d|encrypt|t",
		string(AppendRequestContext(nil, "d", "encrypt", "")):          "cipheron/v1|request|d|encrypt",
		string(AppendResponseContext(nil, "d", "decrypt", "t")):        "cipheron/v1|response|d|decrypt|t",
		SealSlot("d", "v2", 3):                                         "cipheron/seal/v1|d|v2|3",
		TestNamespace("").String():                                     "cipheron-test/v1|",
		TestNamespace("a-1").String():                                  "cipheron-test/a-1/v1|",
		HKDFSHA256AESGCM().Namespace().String():                        "cipheron/v1|",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
	if n := testing.AllocsPerRun(10, func() { _ = LabelDigest.String() }); n != 0 {
		t.Fatalf("Fixed.String allocates %v times", n)
	}
	for _, bad := range []func(){func() { _ = Fixed(0).String() }, func() { _ = Fixed(200).String() },
		func() { _ = Scoped(0).For("d") }, func() { _ = Scoped(9).For("d") }, func() { _ = TestNamespace("A") },
		func() { _ = TestSuite("x", protocolNamespace, 32, 32, 12, 16, nil, nil) }} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			bad()
		}()
	}
}

// label is one label's shape and fields: parseLabel reads a built label back into it.
type label struct {
	shape               string
	word                string
	profile, tenant, id string
	salt                string
}

const saltLen = 32

// parseLabel reads a label of the protocol's namespace back: its shape and its fields. It decides the shape from the
// bytes alone, so two inputs that build the same bytes parse back to the same input: build is injective over all
// shapes together.
//
// contexts selects the family: the HPKE context strings (request and response), or every other label (the derivation
// infos, the transcripts' and digests' fixed labels). The two families are parsed apart on purpose: a context string of
// a profile named "request" can equal an item info of another profile ("cipheron/v1|request|docs|encrypt|x|message"
// and a salt is both a request context of profile "docs" and a format-3 info of profile "request"), and that is harmless
// — a context string is an HPKE info under a one-time or profile HPKE key, an item info an HKDF info under a data or
// storage key: no key is ever given both — but it is why injectivity is a property of each family, not of the two.
func parseLabel(b string, contexts bool) (label, bool) {
	ns := protocolNamespace.s
	if strings.HasPrefix(b, "\x00") && !contexts { // TenantBlobWrapInfo: lp(ns word) lp(profile) lp(tenant) lp(id) salt
		var f [4]string
		rest := b
		for i := range f {
			if len(rest) < 4 {
				return label{}, false
			}
			n := int(binary.BigEndian.Uint32([]byte(rest[:4])))
			if n > len(rest)-4 {
				return label{}, false
			}
			f[i], rest = rest[4:4+n], rest[4+n:]
		}
		if f[0] != ns+wordTenantBlobWrap || len(rest) != saltLen {
			return label{}, false
		}
		return label{shape: "blob", profile: f[1], tenant: f[2], id: f[3], salt: rest}, true
	}
	rest, ok := strings.CutPrefix(b, ns)
	if !ok {
		return label{}, false
	}
	for f := 1; f < len(fixedWords) && !contexts; f++ {
		if rest == fixedWords[f] {
			return label{shape: "fixed", word: fixedWords[f]}, true
		}
	}
	for _, dir := range []string{wordRequest, wordResponse} {
		if r, ok := strings.CutPrefix(rest, dir); ok && contexts {
			d, r, ok := strings.Cut(r, "|")
			if !ok {
				return label{}, false
			}
			op, tenant, _ := strings.Cut(r, "|")
			return label{shape: dir, profile: d, word: op, tenant: tenant}, true
		}
	}
	profile, r, ok := strings.Cut(rest, "|")
	if !ok {
		return label{}, false
	}
	r = "|" + r
	for s := 1; s < len(scopedWords) && !contexts; s++ {
		if r == scopedWords[s] {
			return label{shape: "scoped", profile: profile, word: scopedWords[s]}, true
		}
	}
	if contexts {
		return label{}, false
	}
	if x, ok := strings.CutPrefix(r, wordMessage4); ok && len(x) > 0 && x[0] == 0 { // lp(id) lp(tenant) salt
		if len(x) < 4 {
			return label{}, false
		}
		n := int(binary.BigEndian.Uint32([]byte(x[:4])))
		if n > len(x)-8 {
			return label{}, false
		}
		id, x := x[4:4+n], x[4+n:]
		m := int(binary.BigEndian.Uint32([]byte(x[:4])))
		if m > len(x)-4 || len(x)-4-m != saltLen {
			return label{}, false
		}
		return label{shape: "message4", profile: profile, id: id, tenant: x[4 : 4+m], salt: x[4+m:]}, true
	}
	if x, ok := strings.CutPrefix(r, wordTenantStorage); ok && len(x) > 0 && x[0] == 0 {
		if len(x) < 4 || int(binary.BigEndian.Uint32([]byte(x[:4]))) != len(x)-4 {
			return label{}, false
		}
		return label{shape: "storage", profile: profile, tenant: x[4:]}, true
	}
	// profile "|" tenant "|message" salt: the salt has the scheme's fixed length.
	if len(r) < 1+len(wordMessage)+saltLen || r[len(r)-saltLen-len(wordMessage):len(r)-saltLen] != wordMessage {
		return label{}, false
	}
	return label{shape: "message", profile: profile, tenant: r[1 : len(r)-saltLen-len(wordMessage)], salt: r[len(r)-saltLen:]}, true
}

// build is the label of x.
func build(x label) string {
	ns, salt := protocolNamespace, []byte(x.salt)
	switch x.shape {
	case "blob":
		return TenantBlobWrapInfo(ns, x.profile, x.tenant, x.id, salt)
	case "message":
		return TenantMessageInfo(ns, x.profile, x.tenant, salt)
	case "message4":
		return VersionedMessageInfo(ns, x.profile, x.id, x.tenant, salt)
	case "storage":
		return TenantStorage(x.profile, x.tenant)
	case wordRequest:
		return string(AppendRequestContext(nil, x.profile, x.word, x.tenant))
	case wordResponse:
		return string(AppendResponseContext(nil, x.profile, x.word, x.tenant))
	case "scoped":
		for s := 1; s < len(scopedWords); s++ {
			if scopedWords[s] == x.word {
				return Scoped(s).For(x.profile)
			}
		}
	case "fixed":
		for f := 1; f < len(fixedWords); f++ {
			if fixedWords[f] == x.word {
				return Fixed(f).String()
			}
		}
	}
	panic(x.shape)
}

// labelCases are adversarial inputs: tenants holding "|message", "|", "message4", "tenant-storage", a profile equal to a
// word, a version id whose length's first byte is "|", empty tenants.
func labelCases() []label {
	salt := strings.Repeat("\x7c", saltLen)
	salt2 := strings.Repeat("\x00", saltLen)
	var out []label
	for _, d := range []string{"docs", "storage", "message", "request", "kcv"} {
		for _, tn := range []string{"t", "|message", "a|b", "message4", "|tenant-storage|", "kcv", "x|message" + salt} {
			out = append(out, label{shape: "message", profile: d, tenant: tn, salt: salt},
				label{shape: "message", profile: d, tenant: tn, salt: salt2},
				label{shape: "message4", profile: d, id: "v1", tenant: tn, salt: salt},
				label{shape: "message4", profile: d, id: strings.Repeat("v", 0x7c), tenant: tn, salt: salt2},
				label{shape: "blob", profile: d, id: "v1", tenant: tn, salt: salt},
				label{shape: "storage", profile: d, tenant: tn},
				label{shape: wordRequest, profile: d, word: "encrypt", tenant: tn},
				label{shape: wordResponse, profile: d, word: "decrypt", tenant: tn})
		}
		out = append(out, label{shape: "message4", profile: d, id: "v1", tenant: "", salt: salt},
			label{shape: wordRequest, profile: d, word: "sign"}, label{shape: wordResponse, profile: d, word: "decrypt"})
		for s := 1; s < len(scopedWords); s++ {
			out = append(out, label{shape: "scoped", profile: d, word: scopedWords[s]})
		}
	}
	for f := 1; f < len(fixedWords); f++ {
		out = append(out, label{shape: "fixed", word: fixedWords[f]})
	}
	return out
}

// TestEveryLabelShapeIsInjective: parseLabel(build(x)) == x for every adversarial case, and no two cases of one family
// build the same bytes; parseLabel being a function, two different inputs never build one label, across every shape
// of a family.
func TestEveryLabelShapeIsInjective(t *testing.T) {
	seen := map[string]label{}
	for _, x := range labelCases() {
		b := build(x)
		got, ok := parseLabel(b, x.shape == wordRequest || x.shape == wordResponse)
		if !ok || got != x {
			t.Fatalf("%+v builds %q, which parses back as %+v (%v)", x, b, got, ok)
		}
		if prev, dup := seen[b]; dup && prev != x && isContext(prev) == isContext(x) {
			t.Fatalf("%+v and %+v build %q", prev, x, b)
		}
		seen[b] = x
	}
}

// FuzzEveryLabelShapeIsInjective: the same property over random fields within their validity rules (a profile and an
// operation hold no "|"; a tenant is printable ASCII; a version id of [A-Za-z0-9._-]; a salt of the scheme's length).
func FuzzEveryLabelShapeIsInjective(f *testing.F) {
	f.Add(uint8(0), "docs", "t|message", "v1", bytes.Repeat([]byte{1}, saltLen))
	f.Fuzz(func(t *testing.T, shape uint8, profile, tenant, id string, salt []byte) {
		if strings.ContainsAny(profile, "|\x00") || profile == "" || len(salt) < saltLen || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != "" || id == "" || len(id) > 32 {
			return
		}
		for i := 0; i < len(tenant); i++ {
			if tenant[i] < '!' || tenant[i] > '~' {
				return
			}
		}
		shapes := []string{"message", "message4", "blob", "storage", wordRequest, wordResponse}
		x := label{shape: shapes[int(shape)%len(shapes)], profile: profile, tenant: tenant, salt: string(salt[:saltLen])}
		switch x.shape {
		case "message4", "blob":
			x.id = id
		case "storage", wordRequest, wordResponse:
			x.salt = ""
			if x.shape != "storage" {
				x.word = "encrypt"
			}
		}
		if x.shape == "message" && tenant == "" {
			return
		}
		if got, ok := parseLabel(build(x), isContext(x)); !ok || got != x {
			t.Fatalf("%+v parses back as %+v (%v)", x, got, ok)
		}
	})
}

// isContext reports an HPKE context string's shape.
func isContext(x label) bool { return x.shape == wordRequest || x.shape == wordResponse }
