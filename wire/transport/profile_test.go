package transport

// profile_test.go — the one grammar of a profile name (ValidProfile), and every layout that carries a profile held to
// it: a tenant key blob (ParseTenantKey, AppendTenantKeyHeader), a key statement (ParseKeyStatement) and a key context
// (ContextDigest). A header no cipheron authenticated is what an offline reader prints (`cipheron client
// read-tenant-key`): a profile of control characters or bidirectional overrides never parses, so it is never printed.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// The names cipheron's configuration accepts and refuses (config.ValidProfileName is ValidProfile).
var (
	validProfiles = []string{"credentials", "client-data", "a", "a1-b2", "dev", "docs2", "x-1-y", strings.Repeat("a", 63)}
	badProfiles   = []string{"", "-a", "a-", "a--b", "1a", "A", "Dev", "a_b", "a.b", "a/b", "a|b", "a b", "a\x00",
		"a\n", "a\u202eb", "a\u009bb", "\u202ea", "\u00e4", "a\x7f", strings.Repeat("a", 64)}
)

func TestValidProfile(t *testing.T) {
	for _, ok := range validProfiles {
		if !ValidProfile(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range badProfiles {
		if ValidProfile(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	// One byte: only a lower-case letter is a name.
	for b := 0; b < 256; b++ {
		if got, want := ValidProfile(string([]byte{byte(b)})), b >= 'a' && b <= 'z'; got != want {
			t.Errorf("byte 0x%02x: ValidProfile %v, want %v", b, got, want)
		}
	}
	// Two bytes after a letter: a lower-case letter or a digit, never anything else (a hyphen cannot end a name).
	for b := 0; b < 256; b++ {
		want := b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
		if got := ValidProfile(string([]byte{'a', byte(b)})); got != want {
			t.Errorf("a then byte 0x%02x: ValidProfile %v, want %v", b, got, want)
		}
	}
	if MaxProfileLen != 63 {
		t.Fatalf("MaxProfileLen %d, the documented limit is 63", MaxProfileLen)
	}
}

// blobNaming is a tenant key blob whose profile field holds name's bytes: written for a valid profile of the same
// length, then the profile's bytes replaced — what a party that writes the store can put into a blob.
func blobNaming(t *testing.T, name string) []byte {
	t.Helper()
	blob, _, _ := testBlob(t, strings.Repeat("d", len(name)), "t_1")
	off := len(TenantKeyMagic) + 1 + TenantKeyIDLen + 4
	copy(blob[off:off+len(name)], name)
	return blob
}

// TestAReadHeaderHasAProfileName: a blob whose profile is not a profile name — a bidirectional override (U+202E), a C1
// control (U+009B, the CSI introducer), upper case, "|", an underscore — is refused by ParseTenantKey (and so never
// read: CheckTenantKey, client.ReadTenantKey, read-tenant-key); AppendTenantKeyHeader writes none; every profile name
// still parses.
func TestAReadHeaderHasAProfileName(t *testing.T) {
	for _, bad := range badProfiles {
		if bad == "" || len(bad) > MaxProfileLen {
			continue // covered by the layout test: no field to replace
		}
		if _, err := ParseTenantKey(Release(), blobNaming(t, bad)); !errors.Is(err, ErrTenantKey) {
			t.Errorf("a blob of profile %q: %v; want ErrTenantKey", bad, err)
		}
		h := testHeader(t, "docs", "t_1")
		h.Profile = bad
		if _, err := AppendTenantKeyHeader(Release(), nil, h); !errors.Is(err, ErrTenantKey) {
			t.Errorf("AppendTenantKeyHeader with profile %q: %v; want ErrTenantKey", bad, err)
		}
	}
	for _, ok := range validProfiles {
		h, err := ParseTenantKey(Release(), blobNaming(t, ok))
		if err != nil || h.Profile != ok {
			t.Errorf("a blob of profile %q: %v", ok, err)
		}
	}
}

// TestAStatementAndAContextHaveAProfileName: a key statement whose profile is not a profile name is refused by
// ParseKeyStatement (and so by VerifyKeyStatement, whatever its signature), and ContextDigest refuses such a profile;
// both accept every profile name.
func TestAStatementAndAContextHaveAProfileName(t *testing.T) {
	id, resp := testIdentity(t, TenancyShared)
	key, _ := newSigningKey(t, SigningKeyActive)
	statement := func(profile string) ([]byte, []byte) {
		st := KeyStatement{Profile: profile, IssuedAtMS: 1767225600000, ContextDigest: testContext, Identity: id,
			SigningKeys: []SigningKey{key}}
		raw, err := MarshalKeyStatement(Release(), &st)
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(resp, raw)
	}
	context := func(profile string) KeyContext {
		return KeyContext{Profile: profile, Tenancy: TenancyShared, MasterVersions: []MasterVersionCheck{{"v1", kcv(1)}},
			KeysetFingerprint: testContext, SigningKeys: []SigningKey{key}}
	}
	for _, bad := range badProfiles {
		raw, sig := statement(bad)
		if _, err := ParseKeyStatement(Release(), raw); !errors.Is(err, ErrKeyStatement) {
			t.Errorf("a statement of profile %q: %v; want ErrKeyStatement", bad, err)
		}
		if _, err := VerifyKeyStatement(Release(), raw, sig, bad, Fingerprint(bad, id)); !errors.Is(err, ErrKeyStatement) {
			t.Errorf("a signed statement of profile %q verified: %v", bad, err)
		}
		if _, err := ContextDigest(context(bad)); err == nil {
			t.Errorf("ContextDigest of profile %q: accepted", bad)
		}
	}
	for _, ok := range validProfiles {
		raw, sig := statement(ok)
		if st, err := VerifyKeyStatement(Release(), raw, sig, ok, Fingerprint(ok, id)); err != nil || st.Profile != ok ||
			!bytes.Equal(st.SigningKeys[0].KeyID, key.KeyID) {
			t.Errorf("a statement of profile %q: %v", ok, err)
		}
		if _, err := ContextDigest(context(ok)); err != nil {
			t.Errorf("ContextDigest of profile %q: %v", ok, err)
		}
	}
}
