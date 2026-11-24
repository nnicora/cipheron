//go:build linux || darwin

package cipheron_test

import (
	"testing"

	"github.com/nnicora/cipheron"
)

// keyOf is cipheron.KeyID of ct; it fails the test when ct names no key.
func keyOf(t *testing.T, ct []byte) cipheron.CiphertextKey {
	t.Helper()
	k, err := cipheron.KeyID(ct)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	return k
}
