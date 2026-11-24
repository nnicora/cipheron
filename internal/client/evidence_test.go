package client

// evidence_test.go — wave 4 (D4): ReadTenantKeyEvidence reads a blob's erasure evidence fields from its header,
// offline, and refuses what is not a blob.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/nnicora/cipheron/wire/transport"
)

func TestReadTenantKeyEvidence(t *testing.T) {
	keyID := make([]byte, transport.TenantKeyIDLen)
	_, _ = rand.Read(keyID)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h := &transport.TenantKeyHeader{Version: transport.TenantKeyVersion, KeyID: keyID, Profile: "people", Tenant: "t_1",
		SigningPublicKey: pub, WrappingVersion: "v2", Created: time.Unix(1_767_225_600, 0).UTC(),
		Salt: bytes.Repeat([]byte{0x5a}, transport.TenantKeySaltLen)}
	blob, err := transport.AppendTenantKeyHeader(transport.Release(), nil, h)
	if err != nil {
		t.Fatal(err)
	}
	sealed := make([]byte, transport.TenantSealedLen)
	_, _ = rand.Read(sealed)
	blob = append(blob, sealed...)

	e, err := ReadTenantKeyEvidence(blob)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	want := TenantKeyEvidence{Profile: h.Profile, Tenant: h.Tenant, Version: int(h.Version), KeyID: hex.EncodeToString(keyID),
		Fingerprint: transport.TenantFingerprint(h.Profile, h.Tenant, keyID, pub), WrappingVersion: h.WrappingVersion,
		Created: "2026-01-01T00:00:00Z", BlobSHA256: hex.EncodeToString(sum[:])}
	if *e != want {
		t.Errorf("\n got %+v\nwant %+v", *e, want)
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(out, &fields)
	// The record's fields are the nine below; a blob names its wrapping key by its master version alone.
	if fields["headerAuthenticated"] != false || fields["wrappingVersion"] != "v2" || len(fields) != 9 {
		t.Errorf("the JSON: %s", out)
	}
	if _, err := ReadTenantKeyEvidence([]byte("CPT1 not a blob")); err == nil {
		t.Error("a malformed blob was read")
	}
}
