package cipherontest

// modified_test.go — the test server refuses a modified ciphertext as cipheron does. (That its stored items are
// cipheron's own — its ciphertexts open under cipheron's envelope, its tenant key blobs unwrap under cipheron's
// tenantkey — is checked with cipheron's server.)

import (
	"testing"
)

// TestTheFakeRefusesAModifiedCiphertextAsCipheronDoes: a ciphertext of the fake's own key with one byte changed does
// not decrypt, and the fake answers it with its status (InvalidArgument, "the ciphertext could not be decrypted"),
// never the layout framework's error value.
func TestTheFakeRefusesAModifiedCiphertextAsCipheronDoes(t *testing.T) {
	s := New(t, "docs")
	k := s.profile("docs")
	ct := s.encryptVersioned(k, "docs", "", []byte("a row"), nil)
	ct[len(ct)-1] ^= 1
	if _, err := s.open(k, "docs", "", nil, ct, nil); err != errFakeOpen { //nolint:errorlint // the very value
		t.Fatalf("a modified ciphertext: %v", err)
	}
}
