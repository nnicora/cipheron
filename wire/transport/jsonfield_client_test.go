package transport_test

// jsonfield_client_test.go — the encrypted JSON field kind as the client library sees it: encrypting refuses a field
// that holds an encrypted value of a version the release reads ("encrypted already"), and only those.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/internal/client"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestTheClientRefusesAFieldOfEveryReadVersion: a field holding "cipheron:v1:..." is refused as encrypted already; one
// holding "cipheron:v2:..." — a version the release does not read — is encrypted like any string.
func TestTheClientRefusesAFieldOfEveryReadVersion(t *testing.T) {
	ctx := context.Background()
	fake := cipherontest.New(t, "docs")
	c, err := client.DialGRPC(fake.ServeSocket(t), client.WithServerUID(uint32(os.Getuid())))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	const v1, v2 = `{"a":"cipheron:v1:AQID"}`, `{"a":"cipheron:v2:AQID"}`
	encrypts := func(step, doc string, want bool) {
		t.Helper()
		out, err := c.EncryptJSONFields(ctx, "docs", []byte(doc), "r1", []string{"/a"})
		switch {
		case want && err != nil:
			t.Fatalf("%s: %s not encrypted: %v", step, doc, err)
		case !want && (!errors.Is(err, transport.ErrJSONField) || !strings.Contains(err.Error(), "encrypted already")):
			t.Fatalf("%s: %s encrypted (%s, %v)", step, doc, out, err)
		}
	}
	encrypts("before", v1, false)
	encrypts("before", v2, true)
	// A policy that reads version 2 takes a "cipheron:v2:" value as an encrypted field (transport's
	// TestTheJSONFieldVersionLifecycle); the client holds the release, under which it is a string like any.
	encrypts("again", v2, true)
}
