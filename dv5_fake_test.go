package cipheron_test

// dv5_fake_test.go — the answers a client must refuse that the test server produces on request (DV-5, 2026-11-19): a
// ciphertext made without the associated data the call asked for, a signing key in a state the protocol does not have
// in a validly signed list, and a PublicKey answer replayed from another request.

import (
	"errors"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestAnAnswerWithoutTheAssociatedDataIsRefused: an Encrypt or a ReEncrypt made with associated data, answered with a
// signed ciphertext made without it (format 4, or format 3 in a wrapped profile), is ErrBadResponse, and nothing is
// returned — in a shared, a derived and a wrapped profile.
func TestAnAnswerWithoutTheAssociatedDataIsRefused(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	aad := cipheron.WithAssociatedData([]byte("ledger:row:1"))
	fake := cipherontest.New(t, "docs", "people", "files")
	fake.MakeDerived("people")
	fake.MakePerTenant("files")
	blob := fake.NewTenantKey("files", "t_1")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")),
		cipheron.WithProfileFingerprint("people", fake.Fingerprint("people")),
		cipheron.WithProfileFingerprint("files", fake.Fingerprint("files")))
	shared, err := c.Encrypt(ctx, "docs", []byte("p"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := transport.ParseKeyID(transport.Release(), shared); err != nil || !k.AssociatedData {
		t.Fatalf("an honest answer: %+v %v", k, err)
	}
	fake.SetMode(cipherontest.AssociatedDataDropped)
	calls := map[string]func() ([]byte, error){
		"shared encrypt": func() ([]byte, error) { return c.Encrypt(ctx, "docs", []byte("p"), aad) },
		"shared reencrypt": func() ([]byte, error) {
			return c.ReEncrypt(ctx, "docs", shared, aad, cipheron.WithTargetAssociatedData([]byte("ledger:row:1")))
		},
		"derived encrypt": func() ([]byte, error) { return c.Tenant("people", "t_1", nil).Encrypt(ctx, []byte("p"), aad) },
		"wrapped encrypt": func() ([]byte, error) { return c.Tenant("files", "t_1", blob).Encrypt(ctx, []byte("p"), aad) },
	}
	for name, call := range calls {
		if got, err := call(); !errors.Is(err, cipheron.ErrBadResponse) || got != nil {
			t.Errorf("%s: %x, %v; want ErrBadResponse", name, got, err)
		}
	}
	// Without associated data the mode changes nothing: the answer is the honest one.
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("a call without associated data: %v", err)
	}
}

// TestASignedUnknownSigningKeyStateAndAReplayedKeyListAreRefused: a PublicKey answer whose validly signed list holds
// a key in a state the protocol does not have is ErrBadResponse; and a PublicKey answer replayed from another request
// nonce is ErrServerIdentity. Nothing of either is cached: the next honest answer serves.
func TestASignedUnknownSigningKeyStateAndAReplayedKeyListAreRefused(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	for _, c := range []struct {
		mode cipherontest.Mode
		want error
	}{
		{cipherontest.UnknownSigningKeyState, cipheron.ErrBadResponse},
		{cipherontest.ReplayedKeys, cipheron.ErrServerIdentity},
	} {
		fake := cipherontest.New(t, "docs")
		fake.SetMode(c.mode)
		cl := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
		if got, err := cl.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, c.want) || got != nil {
			t.Errorf("mode %d: %x, %v; want %v", c.mode, got, err, c.want)
		}
		fake.SetMode(cipherontest.Honest)
		if _, err := cl.Encrypt(ctx, "docs", []byte("p")); err != nil {
			t.Errorf("mode %d, then honest: %v", c.mode, err)
		}
	}
}
