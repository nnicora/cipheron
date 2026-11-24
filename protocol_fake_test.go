package cipheron_test

// protocol_fake_test.go — the protocol's hardening, through this package's API against the fake: a revoked signing
// key (Verify, a derived tenant's Verify, VerifyWithKeys), what this protocol does not have — refused as
// ErrBadResponse when cipheron answers it, as ErrInvalidInput when the caller hands it in, and never as
// ErrServerIdentity — the options, and tenant key blob version 1. The protocol client's own tests
// (internal/client, protocol_test.go) cover the maximum key age in depth.

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// okWithKeys and okTenantWithKeys are VerifyWithKeys and VerifyTenantWithKeys as a yes or no: true only for (true,
// nil). The tests written before they answered an error use them.
func okWithKeys(keys []cipheron.SigningKey, data, sig, keyID []byte) bool {
	ok, err := cipheron.VerifyWithKeys(keys, data, sig, keyID)
	return ok && err == nil
}

func okTenantWithKeys(keys []cipheron.SigningKey, profile, tenant string, data, sig, keyID []byte) bool {
	ok, err := cipheron.VerifyTenantWithKeys(keys, profile, tenant, data, sig, keyID)
	return ok && err == nil
}

// TestARevokedSigningKeyThroughTheLibrary: a signature under a revoked key is (false, ErrSigningKeyRevoked) from the
// Client's Verify, a derived tenant's Verify and the offline VerifyWithKeys and VerifyTenantWithKeys; the raw-key
// Verify still checks the bytes (state-agnostic, on purpose); Keys reports the state.
func TestARevokedSigningKeyThroughTheLibrary(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs", "prof")
	fake.MakeDerived("prof")
	sock := fake.ServeSocket(t)
	signer := newClient(t, sock, cipheron.WithAnyServer())
	shared, err := signer.Sign(ctx, "docs", []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := signer.Tenant("prof", "t_a", nil).Sign(ctx, []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"docs", "prof"} {
		fake.RotateSigning(d)
	}
	fake.RevokeSigning("docs", shared.KeyID)
	fake.RevokeSigning("prof", derived.KeyID)

	c := newClient(t, sock, cipheron.WithAnyServer())
	if ok, err := c.Verify(ctx, "docs", []byte("d"), shared.Bytes, shared.KeyID); ok || !errors.Is(err, cipheron.ErrSigningKeyRevoked) {
		t.Fatalf("Verify: %v, %v; want ErrSigningKeyRevoked", ok, err)
	}
	if ok, err := c.Tenant("prof", "t_a", nil).Verify(ctx, []byte("d"), derived.Bytes, derived.KeyID); ok ||
		!errors.Is(err, cipheron.ErrSigningKeyRevoked) {
		t.Fatalf("a derived tenant's Verify: %v, %v; want ErrSigningKeyRevoked", ok, err)
	}
	k, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := k.SigningKey(shared.KeyID)
	if key.State != cipheron.SigningKeyRevoked {
		t.Fatalf("Keys: the revoked key is %q", key.State)
	}
	if ok, err := cipheron.VerifyWithKeys(k.SigningKeys, []byte("d"), shared.Bytes, shared.KeyID); ok ||
		!errors.Is(err, cipheron.ErrSigningKeyRevoked) {
		t.Fatalf("VerifyWithKeys: %v, %v", ok, err)
	}
	if !cipheron.Verify(key.PublicKey, []byte("d"), shared.Bytes) {
		t.Fatal("the raw-key Verify is state-agnostic")
	}
	pk, err := c.Keys(ctx, "prof")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cipheron.VerifyTenantWithKeys(pk.SigningKeys, "prof", "t_a", []byte("d"), derived.Bytes, derived.KeyID); ok ||
		!errors.Is(err, cipheron.ErrSigningKeyRevoked) {
		t.Fatalf("VerifyTenantWithKeys: %v, %v", ok, err)
	}
	// A state that is none of the three, and a key id the list does not name, in the offline functions: the list
	// given is the caller's input (ErrInvalidInput); a key id it does not name is ErrUnknownSigningKey.
	unknown := []cipheron.SigningKey{{KeyID: key.KeyID, State: "compromisedSince", PublicKey: key.PublicKey}}
	if ok, err := cipheron.VerifyWithKeys(unknown, []byte("d"), shared.Bytes, shared.KeyID); ok || !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("VerifyWithKeys, an unknown state: %v, %v", ok, err)
	}
	if ok, err := cipheron.VerifyWithKeys(k.SigningKeys, []byte("d"), shared.Bytes, make([]byte, 16)); ok ||
		!errors.Is(err, cipheron.ErrUnknownSigningKey) {
		t.Fatalf("VerifyWithKeys, a key id not listed: %v, %v", ok, err)
	}
	// A replica that has not learnt the revocation signs with the revoked key, its answer signed under its own (older)
	// key context. This Client never saw that context — every PublicKey answer it had came with the revocation — so the
	// answer verifies under no context it accepts: refused as not the profile's cipheron, nothing returned.
	fake.SetMode(cipherontest.SignRevoked)
	if s, err := c.Sign(ctx, "docs", []byte("d")); !errors.Is(err, cipheron.ErrServerIdentity) || s.Bytes != nil {
		t.Fatalf("a Sign answer under a revoked key, of a context this client never saw: %v", err)
	}
	// A Client that saw that context (it fetched the keys before the revocation) verifies the answer, and refuses the
	// revoked key it names once the list it judges by is fetched again.
	fake.SetMode(cipherontest.Honest)
	fake.UnrevokeSigning("docs", shared.KeyID)
	seen := newClient(t, sock, cipheron.WithAnyServer())
	if _, err := seen.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", shared.KeyID)
	if _, err := seen.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.SetMode(cipherontest.SignRevoked)
	if s, err := seen.Sign(ctx, "docs", []byte("d")); !errors.Is(err, cipheron.ErrSigningKeyRevoked) || s.Bytes != nil {
		t.Fatalf("a Sign answer under a revoked key: %v", err)
	}
	fake.SetMode(cipherontest.Honest)
}

// TestWhatThisProtocolDoesNotHaveIsRefused: what cipheron answers, signed, that this protocol does not have — a
// ciphertext format, a tenant key blob version — is ErrBadResponse, and not ErrInvalidInput nor ErrServerIdentity; a
// tenancy this protocol does not have cannot be authenticated (the fingerprint and the keys transcript hold the
// tenancy's name) and is ErrServerIdentity, not ErrBadResponse; a ciphertext of such a format the caller hands to
// Decrypt or KeyID is ErrInvalidInput, and not ErrBadResponse; an operation the server does not have is
// ErrUnsupported, its status kept.
func TestWhatThisProtocolDoesNotHaveIsRefused(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs", "wrapped", "newer")
	fake.MakePerTenant("wrapped")
	sock := fake.ServeSocket(t)
	c := newClient(t, sock, cipheron.WithAnyServer())
	ct, err := c.Encrypt(ctx, "docs", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	newer := append([]byte(nil), ct...)
	newer[len(transport.CiphertextMagic)] = cipherontest.UnknownFormat

	answered := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, cipheron.ErrBadResponse) || errors.Is(err, cipheron.ErrInvalidInput) ||
			errors.Is(err, cipheron.ErrServerIdentity) {
			t.Errorf("%s: %v, want ErrBadResponse alone", name, err)
		}
	}
	given := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, cipheron.ErrInvalidInput) || !errors.Is(err, transport.ErrCiphertextFormat) ||
			errors.Is(err, cipheron.ErrBadResponse) {
			t.Errorf("%s: %v, want ErrInvalidInput", name, err)
		}
	}
	_, err = c.Decrypt(ctx, "docs", newer)
	given("Decrypt of an unknown format", err)
	_, err = c.ReEncrypt(ctx, "docs", newer)
	given("ReEncrypt of an unknown format", err)
	_, err = cipheron.KeyID(newer)
	given("KeyID of an unknown format", err)
	if _, err := cipheron.KeyID([]byte("not a ciphertext")); !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Errorf("KeyID of bytes that are not a ciphertext: %v", err)
	}

	fake.SetMode(cipherontest.UnknownFormatCiphertext)
	_, err = c.Encrypt(ctx, "docs", []byte("p"))
	answered("an Encrypt answer in an unknown format", err)
	fake.SetMode(cipherontest.UnknownVersionBlob)
	_, err = c.CreateTenantKey(ctx, "wrapped", "t_1")
	answered("a tenant key blob of an unknown version", err)
	fake.SetMode(cipherontest.UnknownTenancy)
	if _, err = c.Encrypt(ctx, "newer", []byte("p")); !errors.Is(err, cipheron.ErrServerIdentity) || errors.Is(err, cipheron.ErrBadResponse) {
		t.Errorf("an unknown tenancy: %v, want ErrServerIdentity", err)
	}
	fake.SetMode(cipherontest.Honest)

	fake.Fail(cipherontest.Unimplemented)
	_, err = c.Encrypt(ctx, "docs", []byte("p"))
	fake.Fail(cipherontest.NoFault)
	if !errors.Is(err, cipheron.ErrUnsupported) || status.Code(err) != codes.Unimplemented {
		t.Errorf("UNIMPLEMENTED: %v, want ErrUnsupported", err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("served again: %v", err)
	}
}

// TestTheRoundTwoOptions: WithKeysMaxAge refuses what is out of bounds at New.
func TestTheRoundTwoOptions(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	sock := fake.ServeSocket(t)
	for name, o := range map[string]cipheron.Option{
		"max age 1s":  cipheron.WithKeysMaxAge(time.Second),
		"max age 25h": cipheron.WithKeysMaxAge(25 * time.Hour),
	} {
		if c, err := cipheron.New(sock, cipheron.WithAnyServer(), o); err == nil {
			_ = c.Close()
			t.Errorf("%s was accepted", name)
		}
	}
	c := newClient(t, sock, cipheron.WithAnyServer(), cipheron.WithKeysMaxAge(time.Minute))
	if _, err := c.Encrypt(ctxFor(t, 30*time.Second), "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
}

// TestTenantKeyBlobVersionThroughTheLibrary: version 1 is accepted (and ReadTenantKey reads it); a rewrap answered
// as a blob of another version is ErrBadResponse.
func TestTenantKeyBlobVersionThroughTheLibrary(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer())
	k, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	if i, err := cipheron.ReadTenantKey(k.Blob); err != nil || i.Version != transport.TenantKeyVersion {
		t.Fatalf("a version-1 blob: %+v %v", i, err)
	}
	fake.SetMode(cipherontest.UnknownVersionBlob)
	if _, err := c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob); !errors.Is(err, cipheron.ErrBadResponse) {
		t.Fatalf("a blob of another version answered: %v, want ErrBadResponse", err)
	}
	fake.SetMode(cipherontest.Honest)
	if r, err := c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob); err != nil || r.Fingerprint != k.Fingerprint {
		t.Fatalf("an honest rewrap: %v", err)
	}
}
