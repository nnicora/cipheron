package cipheron_test

// identityclass_test.go — an identity failure is never classified as the caller's invalid input (security review
// 2026-11-19, CL-3): a key statement that is forged, or that is not the answer's, in a PublicKey answer is the
// answering party's failure — ErrServerIdentity — whatever the call that fetched the keys, never ErrInvalidInput,
// although its cause is also ErrKeyStatement.

import (
	"errors"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
)

func TestAForgedKeyStatementIsNotInvalidInput(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	for _, m := range []cipherontest.Mode{cipherontest.ForgedKeyStatement, cipherontest.MismatchedKeyStatement} {
		fake := cipherontest.New(t, "docs")
		fake.SetMode(m)
		c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
		calls := map[string]func() error{
			"Encrypt":      func() error { _, err := c.Encrypt(ctx, "docs", []byte("x")); return err },
			"Keys":         func() error { _, err := c.Keys(ctx, "docs"); return err },
			"KeyStatement": func() error { _, err := c.KeyStatement(ctx, "docs"); return err },
		}
		for name, call := range calls {
			err := call()
			if !errors.Is(err, cipheron.ErrServerIdentity) || errors.Is(err, cipheron.ErrInvalidInput) {
				t.Errorf("mode %d, %s: %v; want ErrServerIdentity and not ErrInvalidInput", m, name, err)
			}
		}
	}
}
