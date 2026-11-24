//go:build linux || darwin

package cipheron_test

// fakeblob_test.go — the test fake refuses a tenant key blob whose header was altered, as cipheron does (security
// review 2026-11-19, CL-7): cipheron opens a blob with its whole header as the additional data, so a blob that keeps its
// key id but carries another signing public key, tenant field byte, creation time or salt — or whose sealed part was
// changed — does not open, and the call is INVALID_ARGUMENT (ErrInvalidInput). Against the fake, Encrypt and Sign get
// the same answer, never a ciphertext made for a header the fake did not write.

import (
	"errors"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestTheFakeRefusesAnAlteredTenantBlob(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	ctx := ctxFor(t, 30*time.Second)
	k, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	h, err := transport.ParseTenantKey(transport.Release(), k.Blob)
	if err != nil {
		t.Fatal(err)
	}
	pubOff := len(h.AAD) - transport.TenantKeySaltLen - 8 - 1 - len(h.WrappingVersion) - len(h.SigningPublicKey)
	flipped := func(off int) []byte {
		b := append([]byte(nil), k.Blob...)
		b[off] ^= 0x01
		return b
	}
	for name, blob := range map[string][]byte{
		"a byte of the signing public key": flipped(pubOff),
		"a byte of the creation time":      flipped(len(h.AAD) - transport.TenantKeySaltLen - 1),
		"a byte of the salt":               flipped(len(h.AAD) - 1),
		"a byte of the sealed part":        flipped(len(h.AAD) + 3),
	} {
		if _, err := transport.CheckTenantKey(transport.Release(), blob, "docs", "t_1"); err != nil {
			t.Fatalf("%s: the altered blob does not even parse: %v", name, err)
		}
		tn := c.Tenant("docs", "t_1", blob)
		if _, err := tn.Encrypt(ctx, []byte("p")); !errors.Is(err, cipheron.ErrInvalidInput) || errors.Is(err, cipheron.ErrServerIdentity) {
			t.Errorf("%s: Encrypt: %v; want ErrInvalidInput, as cipheron answers", name, err)
		}
		if _, err := tn.Sign(ctx, []byte("d")); !errors.Is(err, cipheron.ErrInvalidInput) || errors.Is(err, cipheron.ErrServerIdentity) {
			t.Errorf("%s: Sign: %v; want ErrInvalidInput, as cipheron answers", name, err)
		}
	}
	// The blob the fake made, and the rewrapped one, still serve.
	tn := c.Tenant("docs", "t_1", k.Blob)
	if _, err := tn.Encrypt(ctx, []byte("p")); err != nil {
		t.Fatalf("the blob as made: %v", err)
	}
	nk, err := c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Tenant("docs", "t_1", nk.Blob).Sign(ctx, []byte("d")); err != nil {
		t.Fatalf("the rewrapped blob: %v", err)
	}
	if _, err := tn.Sign(ctx, []byte("d")); err != nil {
		t.Fatalf("the blob before the rewrap: %v", err)
	}
}
