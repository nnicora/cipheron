//go:build linux || darwin

package cipheron_test

// frozen_test.go — the frozen set (spec/frozen) read through the package alone: KeyID, ReadTenantKey, Verify and
// VerifyTenant, with no cipheron. cipheron's server reads the same set through the library against a real cipheron
// (every ciphertext decrypts, every signature verifies, a revoked key's is refused).

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/spec"
)

// fzHex is bytes written as hex in the frozen manifest.
type fzHex []byte

func (h *fzHex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

type fzCiphertext struct {
	Tenant         string `json:"tenant"`
	Plaintext      string `json:"plaintext"`
	AssociatedData fzHex  `json:"associatedData"`
	Format         byte   `json:"format"`
	Version        string `json:"version"`
	Ciphertext     fzHex  `json:"ciphertext"`
}

type fzSignature struct {
	Tenant    string `json:"tenant"`
	Data      string `json:"data"`
	KeyID     fzHex  `json:"keyId"`
	Signature fzHex  `json:"signature"`
}

// fzSet is the part of the frozen manifest the library reads.
type fzSet struct {
	Profiles []struct {
		Name       string `json:"name"`
		Tenancy    string `json:"tenancy"`
		KeysetFile string `json:"keysetFile"`
		Masters    []struct {
			ID  string `json:"id"`
			Key fzHex  `json:"key"`
		} `json:"masters"`
		Serve struct {
			Versions       []string `json:"versions"`
			Active         string   `json:"active"`
			SigningRevoked []string `json:"signingRevoked"`
		} `json:"serve"`
		Fingerprint   string `json:"fingerprint"`
		ContextDigest string `json:"contextDigest"`
		SigningKeys   []struct {
			KeyID     fzHex  `json:"keyId"`
			State     string `json:"state"`
			PublicKey fzHex  `json:"publicKey"`
		} `json:"signingKeys"`
		Ciphertexts []fzCiphertext `json:"ciphertexts"`
		Signatures  []fzSignature  `json:"signatures"`
		Tenants     []struct {
			Tenant          string         `json:"tenant"`
			Blob            fzHex          `json:"blob"`
			WrappingVersion string         `json:"wrappingVersion"`
			Created         string         `json:"created"`
			KeyID           fzHex          `json:"keyId"`
			Fingerprint     string         `json:"fingerprint"`
			Ciphertexts     []fzCiphertext `json:"ciphertexts"`
			Signatures      []fzSignature  `json:"signatures"`
		} `json:"tenants"`
		Objects []struct {
			Plaintext      string `json:"plaintext"`
			AssociatedData fzHex  `json:"associatedData"`
			Object         fzHex  `json:"object"`
		} `json:"objects"`
		JSON []struct {
			Tenant         string   `json:"tenant"`
			RecordID       string   `json:"recordId"`
			Pointers       []string `json:"pointers"`
			AssociatedData fzHex    `json:"associatedData"`
			Plain          string   `json:"plain"`
			Encrypted      string   `json:"encrypted"`
		} `json:"json"`
	} `json:"profiles"`
}

func loadFrozenSet(t *testing.T) *fzSet {
	t.Helper()
	b, err := spec.Frozen.ReadFile("frozen/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var s fzSet
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Profiles) != 3 {
		t.Fatalf("%d profiles", len(s.Profiles))
	}
	return &s
}

// TestTheFrozenSetThroughThePackage: with no cipheron, every ciphertext names its key (formats 4 and 5: its master
// version; 3 and 6: its tenant key's id), every blob reads as frozen, every signature verifies with the package's
// functions — a derived tenant's only as its tenant's.
func TestTheFrozenSetThroughThePackage(t *testing.T) {
	s := loadFrozenSet(t)
	checkKey := func(c fzCiphertext, tenantKeyID []byte) {
		t.Helper()
		k, err := cipheron.KeyID(c.Ciphertext)
		want := c.Version
		if tenantKeyID != nil {
			want = "tenant-key:" + hex.EncodeToString(tenantKeyID)
		}
		if err != nil || k.Format != c.Format || k.String() != want || k.AssociatedData != (len(c.AssociatedData) > 0) {
			t.Fatalf("%+v %v, want %s (format %d)", k, err, want, c.Format)
		}
	}
	n := 0
	for _, d := range s.Profiles {
		pub := map[string][]byte{}
		for _, k := range d.SigningKeys {
			pub[string(k.KeyID)] = k.PublicKey
		}
		for _, c := range d.Ciphertexts {
			checkKey(c, nil)
		}
		for _, sg := range d.Signatures {
			p := pub[string(sg.KeyID)]
			if sg.Tenant == "" && (!cipheron.Verify(p, []byte(sg.Data), sg.Signature) || cipheron.VerifyTenant(p, d.Name, "t", []byte(sg.Data), sg.Signature)) {
				t.Fatalf("%s: the signature over %q", d.Name, sg.Data)
			}
			if sg.Tenant != "" && (!cipheron.VerifyTenant(p, d.Name, sg.Tenant, []byte(sg.Data), sg.Signature) ||
				cipheron.VerifyTenant(p, d.Name, sg.Tenant+"x", []byte(sg.Data), sg.Signature) || cipheron.Verify(p, []byte(sg.Data), sg.Signature)) {
				t.Fatalf("%s: the signature of %s over %q", d.Name, sg.Tenant, sg.Data)
			}
			n++
		}
		for _, b := range d.Tenants {
			info, err := cipheron.ReadTenantKey(b.Blob)
			if err != nil || info.Version != 1 || info.Profile != d.Name || info.Tenant != b.Tenant || !bytes.Equal(info.KeyID, b.KeyID) ||
				info.Fingerprint != b.Fingerprint || info.WrappingVersion != b.WrappingVersion ||
				info.Created.UTC().Format(time.RFC3339) != b.Created {
				t.Fatalf("%s/%s: %+v %v", d.Name, b.Tenant, info, err)
			}
			for _, c := range b.Ciphertexts {
				checkKey(c, b.KeyID)
			}
			for _, sg := range b.Signatures {
				if !cipheron.Verify(info.SigningPublicKey, []byte(sg.Data), sg.Signature) {
					t.Fatalf("%s/%s: the signature over %q", d.Name, b.Tenant, sg.Data)
				}
				n++
			}
		}
	}
	if n != 11 {
		t.Fatalf("%d signatures", n)
	}
}
