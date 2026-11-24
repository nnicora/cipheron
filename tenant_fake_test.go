//go:build linux || darwin

package cipheron_test

// tenant_fake_test.go — the library's checks of a perTenant profile's answers, wrapped and derived, against the
// fake (cipherontest) switched into the ways an impostor or a broken server answers: none is ever
// returned.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestTheWrappedTenantAnswersAreVerified(t *testing.T) {
	fake := cipherontest.New(t, "docs", "plain")
	fake.MakePerTenant("docs")
	sock := fake.ServeSocket(t)
	c := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	ctx := ctxFor(t, 30*time.Second)

	k, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	// The fake writes version 1, as cipheron does.
	if info, err := cipheron.ReadTenantKey(k.Blob); err != nil || info.Version != transport.TenantKeyVersion ||
		!bytes.Equal(info.KeyID, k.KeyID) || info.Fingerprint != k.Fingerprint || info.WrappingVersion != "v1" ||
		info.Created.IsZero() {
		t.Fatalf("CreateTenantKey's blob: %+v %v", info, err)
	}
	tn := c.Tenant("docs", "t_1", k.Blob)
	ct, err := tn.Encrypt(ctx, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := cipheron.KeyID(ct); err != nil || kid.Format != transport.FormatTenantKey || !bytes.Equal(kid.TenantKeyID, k.KeyID) {
		t.Fatalf("a wrapped tenant's ciphertext names its key: %+v %v", kid, err)
	}
	if pt, err := tn.Decrypt(ctx, ct); err != nil || string(pt) != "p" {
		t.Fatalf("Decrypt: %q %v", pt, err)
	}
	sig, err := tn.Sign(ctx, []byte("d"))
	if err != nil || !bytes.Equal(sig.KeyID, k.KeyID) || !cipheron.Verify(k.SigningPublicKey, []byte("d"), sig.Bytes) {
		t.Fatalf("Sign: %+v %v", sig, err)
	}
	if ok, err := tn.Verify(ctx, []byte("d"), sig.Bytes, sig.KeyID); !ok || err != nil {
		t.Fatalf("Verify: %v %v", ok, err)
	}
	if ok, _ := tn.Verify(ctx, []byte("d"), sig.Bytes, make([]byte, 16)); ok {
		t.Fatal("Verify under another key id")
	}
	if fp, err := tn.Fingerprint(); err != nil || fp != k.Fingerprint {
		t.Fatalf("Fingerprint: %q %v", fp, err)
	}
	// The tenant's own key rotated by the service: a new key, and the row moved to it.
	k2, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	moved, err := tn.ReEncrypt(ctx, ct, k2.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := cipheron.KeyID(moved); !bytes.Equal(kid.TenantKeyID, k2.KeyID) {
		t.Fatalf("ReEncrypt to the new key: %s", kid)
	}
	if pt, err := c.Tenant("docs", "t_1", k2.Blob).Decrypt(ctx, moved); err != nil || string(pt) != "p" {
		t.Fatalf("Decrypt under the new key: %q %v", pt, err)
	}
	if _, err := tn.Decrypt(ctx, moved); !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("the moved row under the old key: %v", err)
	}

	for _, c2 := range []struct {
		mode cipherontest.Mode
		call string
		want error
	}{
		{cipherontest.ForeignResponseSignature, "create", cipheron.ErrServerIdentity},
		{cipherontest.NoResponseSignature, "create", cipheron.ErrServerIdentity},
		{cipherontest.OtherTenantBlob, "create", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "encrypt", cipheron.ErrServerIdentity},
		{cipherontest.OtherKeyIDCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.WrongFormatCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.JunkCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "decrypt", cipheron.ErrServerIdentity},
		{cipherontest.GarbledPlaintext, "decrypt", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.NoResponseSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.ForeignSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.ShortSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.UnknownKeyID, "sign", cipheron.ErrServerIdentity},
		{cipherontest.ForeignResponseSignature, "reencrypt", cipheron.ErrServerIdentity},
		{cipherontest.OtherKeyIDCiphertext, "reencrypt", cipheron.ErrBadResponse},
		{cipherontest.WrongFormatCiphertext, "reencrypt", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "rewrap", cipheron.ErrServerIdentity},
		{cipherontest.NoResponseSignature, "rewrap", cipheron.ErrServerIdentity},
		{cipherontest.RewrapOtherKeyID, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.RewrapOtherSigningKey, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.RewrapOtherFingerprint, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.RewrapOtherCreated, "rewrap", cipheron.ErrBadResponse},
	} {
		fake.SetMode(c2.mode)
		var got []byte
		var err error
		switch c2.call {
		case "create":
			var nk cipheron.TenantKey
			nk, err = c.CreateTenantKey(ctx, "docs", "t_2")
			got = nk.Blob
		case "encrypt":
			got, err = tn.Encrypt(ctx, []byte("p"))
		case "decrypt":
			got, err = tn.Decrypt(ctx, ct)
		case "sign":
			var s cipheron.Signature
			s, err = tn.Sign(ctx, []byte("d"))
			got = s.Bytes
		case "reencrypt":
			got, err = tn.ReEncrypt(ctx, ct, k2.Blob)
		case "rewrap":
			var nk cipheron.TenantKey
			nk, err = c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob)
			got = nk.Blob
		}
		if !errors.Is(err, c2.want) || errors.Is(err, cipheron.ErrServerKeyChanged) {
			t.Errorf("mode %d, %s: %v, want %v", c2.mode, c2.call, err, c2.want)
		}
		if got != nil {
			t.Errorf("mode %d, %s: an answer was returned", c2.mode, c2.call)
		}
	}
	fake.SetMode(cipherontest.Honest)

	// Tenancy refused before anything is sent, both ways; a blob of another tenant or none, and the pin.
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("a shared Encrypt in a perTenant profile: %v", err)
	}
	if _, err := c.Tenant("plain", "t_1", fake.NewTenantKey("plain", "t_1")).Encrypt(ctx, []byte("p")); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("a tenant call in a shared profile: %v", err)
	}
	if _, err := c.CreateTenantKey(ctx, "plain", "t_1"); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("CreateTenantKey in a shared profile: %v", err)
	}
	if _, err := tn.ReEncrypt(ctx, ct, nil); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("a wrapped ReEncrypt without a target: %v", err)
	}
	if _, err := tn.ReEncrypt(ctx, ct, fake.NewTenantKey("docs", "t_2")); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("a wrapped ReEncrypt to another tenant's key: %v", err)
	}
	for name, h := range map[string]*cipheron.Tenant{
		"another tenant's blob": c.Tenant("docs", "t_2", k.Blob),
		"no blob":               c.Tenant("docs", "t_1", nil),
		"not a tenant id":       c.Tenant("docs", "t 1", k.Blob),
	} {
		if _, err := h.Sign(ctx, []byte("p")); !errors.Is(err, cipheron.ErrTenantKey) || !errors.Is(err, cipheron.ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	pinned := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithTenantFingerprint("docs", "t_1", k.Fingerprint))
	if _, err := pinned.Tenant("docs", "t_1", k.Blob).Sign(ctx, []byte("p")); err != nil {
		t.Fatalf("the pinned key: %v", err)
	}
	other := fake.NewTenantKey("docs", "t_1")
	if _, err := pinned.Tenant("docs", "t_1", other).Sign(ctx, []byte("p")); !errors.Is(err, cipheron.ErrTenantKey) ||
		!strings.Contains(err.Error(), "not the pinned") {
		t.Fatalf("another key under the pin: %v", err)
	}
	if _, err := pinned.RewrapTenantKey(ctx, "docs", "t_1", other); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("RewrapTenantKey of another key under the pin: %v", err)
	}
	if _, err := cipheron.New(sock, cipheron.WithAnyServer(), cipheron.WithTenantFingerprint("docs", "t 1", k.Fingerprint)); err == nil {
		t.Fatal("a pin of a malformed tenant id")
	}
	if _, err := cipheron.New(sock, cipheron.WithAnyServer(), cipheron.WithTenantFingerprint("docs", "t_1", "sha256:x")); err == nil {
		t.Fatal("a malformed tenant pin")
	}
	if _, err := cipheron.ReadTenantKey([]byte("CPT1")); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("ReadTenantKey of junk: %v", err)
	}
}

// TestABlobOfAnotherVersionIsRefused: a wrapped profile's CreateTenantKey or RewrapTenantKey answered with a blob of
// another version — signed by the profile's response key over the request, but a version this protocol does not have
// — is refused (ErrBadResponse). The version-1 key cipheron answers is accepted and works, and every other check of the
// answers holds: another tenant's blob, another key id, signing key, fingerprint or creation time, a foreign or
// missing response signature, a ciphertext under another key, of the other family or too long are refused.
func TestABlobOfAnotherVersionIsRefused(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	sock := fake.ServeSocket(t)
	c := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	ctx := ctxFor(t, 30*time.Second)
	fake.SetMode(cipherontest.UnknownVersionBlob)
	if got, err := c.CreateTenantKey(ctx, "docs", "t_2"); !errors.Is(err, cipheron.ErrBadResponse) || got.Blob != nil {
		t.Fatalf("CreateTenantKey answered a blob of another version: %v, want ErrBadResponse", err)
	}
	fake.SetMode(cipherontest.Honest)

	k, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	info, err := cipheron.ReadTenantKey(k.Blob)
	if err != nil || info.Version != transport.TenantKeyVersion || !bytes.Equal(info.KeyID, k.KeyID) ||
		info.Fingerprint != k.Fingerprint || info.Created.IsZero() {
		t.Fatalf("CreateTenantKey's blob: %+v %v", info, err)
	}
	tn := c.Tenant("docs", "t_1", k.Blob)
	ct, err := tn.Encrypt(ctx, []byte("p"))
	if kid, _ := cipheron.KeyID(ct); err != nil || kid.Format != transport.FormatTenantKey || !bytes.Equal(kid.TenantKeyID, k.KeyID) {
		t.Fatalf("Encrypt: %s %v", kid, err)
	}
	if pt, err := tn.Decrypt(ctx, ct); err != nil || string(pt) != "p" {
		t.Fatalf("Decrypt: %q %v", pt, err)
	}
	if s, err := tn.Sign(ctx, []byte("d")); err != nil || !cipheron.Verify(k.SigningPublicKey, []byte("d"), s.Bytes) {
		t.Fatalf("Sign: %v", err)
	}
	nk, err := c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if ni, err := cipheron.ReadTenantKey(nk.Blob); err != nil || ni.Version != transport.TenantKeyVersion ||
		!bytes.Equal(ni.KeyID, k.KeyID) || nk.Fingerprint != k.Fingerprint || bytes.Equal(nk.Blob, k.Blob) {
		t.Fatalf("the rewrapped blob: %+v %v", ni, err)
	}
	if pt, err := c.Tenant("docs", "t_1", nk.Blob).Decrypt(ctx, ct); err != nil || string(pt) != "p" {
		t.Fatalf("the row under the rewrapped blob: %q %v", pt, err)
	}
	for _, c2 := range []struct {
		mode cipherontest.Mode
		call string
		want error
	}{
		{cipherontest.OtherTenantBlob, "create", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "create", cipheron.ErrServerIdentity},
		{cipherontest.NoResponseSignature, "create", cipheron.ErrServerIdentity},
		{cipherontest.RewrapOtherKeyID, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.RewrapOtherSigningKey, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.RewrapOtherFingerprint, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.RewrapOtherCreated, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.UnknownVersionBlob, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "rewrap", cipheron.ErrServerIdentity},
		{cipherontest.AnsweredOtherSigningKey, "create", cipheron.ErrBadResponse},
		{cipherontest.AnsweredOtherSigningKey, "rewrap", cipheron.ErrBadResponse},
		{cipherontest.OtherKeyIDCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.WrongFormatCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.LongCiphertext, "encrypt", cipheron.ErrBadResponse},
	} {
		fake.SetMode(c2.mode)
		var got []byte
		var err error
		switch c2.call {
		case "create":
			var nk cipheron.TenantKey
			nk, err = c.CreateTenantKey(ctx, "docs", "t_3")
			got = nk.Blob
		case "rewrap":
			var nk cipheron.TenantKey
			nk, err = c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob)
			got = nk.Blob
		case "encrypt":
			got, err = tn.Encrypt(ctx, []byte("p"))
		}
		if !errors.Is(err, c2.want) || got != nil {
			t.Errorf("mode %d, %s: %v, want %v", c2.mode, c2.call, err, c2.want)
		}
	}
	fake.SetMode(cipherontest.Honest)
}

// TestRewrapTenantKey: a blob moves to the current wrapping version with the same key inside; the pin
// survives; the old and new blob both work; a retired wrapping version is ErrKeyVersionUnavailable, and listing it
// again restores the blob.
func TestRewrapTenantKey(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	sock := fake.ServeSocket(t)
	ctx := ctxFor(t, 30*time.Second)
	v1 := fake.NewTenantKey("docs", "t_1")
	info, err := cipheron.ReadTenantKey(v1)
	if err != nil || info.Version != transport.TenantKeyVersion || info.WrappingVersion != "v1" || info.Created.IsZero() {
		t.Fatalf("a blob under v1: %+v %v", info, err)
	}
	c := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithTenantFingerprint("docs", "t_1", info.Fingerprint))
	old := c.Tenant("docs", "t_1", v1)
	ct, err := old.Encrypt(ctx, []byte("kept"))
	if err != nil {
		t.Fatal(err)
	}
	fake.SetWriteVersion("docs", "v2")
	nk, err := c.RewrapTenantKey(ctx, "docs", "t_1", v1)
	if err != nil {
		t.Fatal(err)
	}
	ni, err := cipheron.ReadTenantKey(nk.Blob)
	if err != nil || ni.Version != transport.TenantKeyVersion || ni.WrappingVersion != "v2" ||
		!bytes.Equal(ni.KeyID, info.KeyID) || nk.Fingerprint != info.Fingerprint || !ni.Created.Equal(info.Created) {
		t.Fatalf("the rewrapped blob: %+v %v", ni, err)
	}
	for name, blob := range map[string][]byte{"old blob": v1, "new blob": nk.Blob} {
		if pt, err := c.Tenant("docs", "t_1", blob).Decrypt(ctx, ct); err != nil || string(pt) != "kept" {
			t.Errorf("%s: %q %v", name, pt, err)
		}
	}
	// A blob rewrapped again keeps its key; a blob created with a time keeps it.
	again, err := c.RewrapTenantKey(ctx, "docs", "t_1", nk.Blob)
	if err != nil || !bytes.Equal(again.KeyID, nk.KeyID) {
		t.Fatalf("a second rewrap: %v", err)
	}
	created := fake.NewTenantKey("docs", "t_9")
	ci, _ := cipheron.ReadTenantKey(created)
	if r, err := c.RewrapTenantKey(ctx, "docs", "t_9", created); err != nil {
		t.Fatal(err)
	} else if ri, _ := cipheron.ReadTenantKey(r.Blob); !ri.Created.Equal(ci.Created) || ri.Created.IsZero() {
		t.Fatalf("the creation time: %v, want %v", ri.Created, ci.Created)
	}

	fake.RetireVersion("docs", "v1")
	if _, err := old.Decrypt(ctx, ct); !errors.Is(err, cipheron.ErrKeyVersionUnavailable) || errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("a blob of a retired wrapping version: %v", err)
	}
	if pt, err := c.Tenant("docs", "t_1", nk.Blob).Decrypt(ctx, ct); err != nil || string(pt) != "kept" {
		t.Fatalf("the rewrapped blob after the retirement: %q %v", pt, err)
	}
	fake.ListVersion("docs", "v1")
	if pt, err := old.Decrypt(ctx, ct); err != nil || string(pt) != "kept" {
		t.Fatalf("un-retired: %q %v", pt, err)
	}
	// Refused before anything is sent: a blob of another tenant, and in a profile that has no blobs.
	if _, err := c.RewrapTenantKey(ctx, "docs", "t_2", nk.Blob); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("another tenant's blob: %v", err)
	}
}

// TestDerivedTenants: a derived profile's handle carries the tenant only; its ciphertexts are format 4; Sign is
// by the profile's signing keys over the tenant-bound message, verified with VerifyTenant and refused for another
// tenant; a blob, CreateTenantKey and RewrapTenantKey are refused before anything is sent; every forged answer
// is refused.
func TestDerivedTenants(t *testing.T) {
	fake := cipherontest.New(t, "prof", "other")
	fake.MakeDerived("prof")
	sock := fake.ServeSocket(t)
	c := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("prof", fake.Fingerprint("prof")))
	ctx := ctxFor(t, 30*time.Second)

	keys, err := c.Keys(ctx, "prof")
	if err != nil || keys.Tenancy != cipheron.TenancyDerived || len(keys.SigningKeys) != 1 {
		t.Fatalf("Keys: %+v %v", keys, err)
	}
	a, b := c.Tenant("prof", "t_a", nil), c.Tenant("prof", "t_b", nil)
	ct, err := a.Encrypt(ctx, []byte("a's"))
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := cipheron.KeyID(ct); err != nil || kid.Format != transport.FormatVersioned || kid.MasterVersion != "v1" {
		t.Fatalf("a derived tenant's ciphertext: %+v %v", kid, err)
	}
	if pt, err := a.Decrypt(ctx, ct); err != nil || string(pt) != "a's" {
		t.Fatalf("Decrypt: %q %v", pt, err)
	}
	if _, err := b.Decrypt(ctx, ct); !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("another tenant's Decrypt: %v", err)
	}
	moved, err := a.ReEncrypt(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := a.Decrypt(ctx, moved); err != nil || string(pt) != "a's" {
		t.Fatalf("Decrypt of the re-encrypted: %q %v", pt, err)
	}

	sig, err := a.Sign(ctx, []byte("doc"))
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.Active()
	if !bytes.Equal(sig.KeyID, active.KeyID) ||
		!cipheron.VerifyTenant(active.PublicKey, "prof", "t_a", []byte("doc"), sig.Bytes) ||
		cipheron.VerifyTenant(active.PublicKey, "prof", "t_b", []byte("doc"), sig.Bytes) ||
		cipheron.Verify(active.PublicKey, []byte("doc"), sig.Bytes) ||
		!okTenantWithKeys(keys.SigningKeys, "prof", "t_a", []byte("doc"), sig.Bytes, sig.KeyID) {
		t.Fatal("a derived signature is not the tenant-bound one")
	}
	if ok, err := a.Verify(ctx, []byte("doc"), sig.Bytes, sig.KeyID); !ok || err != nil {
		t.Fatalf("Verify: %v %v", ok, err)
	}
	if ok, err := b.Verify(ctx, []byte("doc"), sig.Bytes, sig.KeyID); ok || err != nil {
		t.Fatalf("another tenant's Verify: %v %v", ok, err)
	}

	// Refusals before anything is sent.
	if _, err := c.Tenant("prof", "t_a", fake.NewTenantKey("prof", "t_a")).Encrypt(ctx, []byte("x")); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("a blob in a derived profile: %v", err)
	}
	// The blob is checked against the handle's profile and tenant when the handle is made, before the profile's
	// tenancy is known (that takes its keys): a well-formed blob of ANOTHER profile or tenant is ErrTenantKey, not
	// ErrTenancy, even in a derived profile, and nothing is asked of cipheron (the context is already over). Only a
	// blob naming this profile and tenant reaches the tenancy check (ErrTenancy, above).
	over, end := context.WithCancel(ctx)
	end()
	for name, blob := range map[string][]byte{
		"another profile's": fake.NewTenantKey("other", "t_a"),
		"another tenant's":  fake.NewTenantKey("prof", "t_b"),
		"not a":             []byte("a blob"),
	} {
		if _, err := c.Tenant("prof", "t_a", blob).Encrypt(over, []byte("x")); !errors.Is(err, cipheron.ErrTenantKey) ||
			errors.Is(err, cipheron.ErrTenancy) || errors.Is(err, context.Canceled) {
			t.Fatalf("%s blob for a derived profile's tenant: %v; want ErrTenantKey", name, err)
		}
	}
	if _, err := a.ReEncrypt(ctx, ct, []byte("CPT1")); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("a target blob in a derived profile: %v", err)
	}
	if _, err := c.CreateTenantKey(ctx, "prof", "t_a"); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("CreateTenantKey in a derived profile: %v", err)
	}
	if _, err := c.RewrapTenantKey(ctx, "prof", "t_a", fake.NewTenantKey("prof", "t_a")); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("RewrapTenantKey in a derived profile: %v", err)
	}
	if _, err := c.Encrypt(ctx, "prof", []byte("x")); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("a shared call in a derived profile: %v", err)
	}
	if _, err := a.Fingerprint(); !errors.Is(err, cipheron.ErrTenancy) {
		t.Fatalf("a derived tenant's fingerprint: %v", err)
	}
	if _, err := c.Tenant("prof", "t a", nil).Encrypt(ctx, []byte("x")); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("a malformed tenant id: %v", err)
	}

	for _, c2 := range []struct {
		mode cipherontest.Mode
		call string
		want error
	}{
		{cipherontest.ForeignResponseSignature, "encrypt", cipheron.ErrServerIdentity},
		{cipherontest.WrongFormatCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.JunkCiphertext, "encrypt", cipheron.ErrBadResponse},
		{cipherontest.GarbledPlaintext, "decrypt", cipheron.ErrBadResponse},
		{cipherontest.ForeignResponseSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.NoResponseSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.ForeignSignature, "sign", cipheron.ErrServerIdentity},
		{cipherontest.UnknownKeyID, "sign", cipheron.ErrServerIdentity},
		{cipherontest.WrongFormatCiphertext, "reencrypt", cipheron.ErrBadResponse},
	} {
		fake.SetMode(c2.mode)
		var got []byte
		var err error
		switch c2.call {
		case "encrypt":
			got, err = a.Encrypt(ctx, []byte("p"))
		case "decrypt":
			got, err = a.Decrypt(ctx, ct)
		case "sign":
			var s cipheron.Signature
			s, err = a.Sign(ctx, []byte("d"))
			got = s.Bytes
		case "reencrypt":
			got, err = a.ReEncrypt(ctx, ct, nil)
		}
		if !errors.Is(err, c2.want) || got != nil {
			t.Errorf("mode %d, %s: %v (answer %v), want %v", c2.mode, c2.call, err, got != nil, c2.want)
		}
	}
}
