package cipherontest

import (
	"testing"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestTheUnknownNumbersAreNotRead: UnknownBlobVersion is a tenant key blob version, and UnknownFormat a ciphertext
// format, that the release does not read — so the answers made with them stay unknown to a client. A release
// that reads either one fails here, and the fake's number is moved with it.
func TestTheUnknownNumbersAreNotRead(t *testing.T) {
	if _, err := format.Read(transport.Release(), transport.TenantKeys(), uint32(UnknownBlobVersion)); err == nil {
		t.Fatalf("the tenant key blob family reads UnknownBlobVersion %d", UnknownBlobVersion)
	}
	if _, err := format.Read(transport.Release(), transport.Ciphertexts(), uint32(UnknownFormat)); err == nil {
		t.Fatalf("the ciphertext family reads UnknownFormat %d", UnknownFormat)
	}
}
