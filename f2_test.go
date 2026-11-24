package cipheron_test

// f2_test.go — the re-review fixes (F2) through this package's API: a key list that is not one profile's is
// ErrInvalidInput from VerifyWithKeys and VerifyTenantWithKeys. The protocol client's own tests
// (internal/client, f2_test.go) cover the rest.

import (
	"errors"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
)

// TestVerifyWithKeysRefusesJoinedLists: an older list joined with a newer one (a key id twice) is ErrInvalidInput,
// never (true, nil) under the key the newer list revokes, in either order; each list alone answers as before.
func TestVerifyWithKeysRefusesJoinedLists(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer())
	sig, err := c.Sign(ctx, "docs", []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	fake.RotateSigning("docs")
	before, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	fake.RevokeSigning("docs", sig.KeyID)
	after, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cipheron.VerifyWithKeys(after.SigningKeys, []byte("d"), sig.Bytes, sig.KeyID); ok ||
		!errors.Is(err, cipheron.ErrSigningKeyRevoked) {
		t.Fatalf("the newer list alone: %v, %v; want ErrSigningKeyRevoked", ok, err)
	}
	for name, keys := range map[string][]cipheron.SigningKey{
		"old ++ new": append(append([]cipheron.SigningKey{}, before.SigningKeys...), after.SigningKeys...),
		"new ++ old": append(append([]cipheron.SigningKey{}, after.SigningKeys...), before.SigningKeys...),
	} {
		ok, err := cipheron.VerifyWithKeys(keys, []byte("d"), sig.Bytes, sig.KeyID)
		if ok || !errors.Is(err, cipheron.ErrInvalidInput) || errors.Is(err, cipheron.ErrSigningKeyRevoked) {
			t.Errorf("%s: %v, %v; want ErrInvalidInput", name, ok, err)
		}
		ok, err = cipheron.VerifyTenantWithKeys(keys, "docs", "t_1", []byte("d"), sig.Bytes, sig.KeyID)
		if ok || !errors.Is(err, cipheron.ErrInvalidInput) {
			t.Errorf("%s (tenant): %v, %v; want ErrInvalidInput", name, ok, err)
		}
	}
}
