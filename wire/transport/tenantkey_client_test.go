package transport_test

// tenantkey_client_test.go — the tenant key blob kind as the client library sees it: the client reads blobs under the
// release, and refuses an answer of a version the release does not read.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/internal/client"
)

// TestTheClientTakesAnAnsweredBlobOfEveryReadVersion: cipherontest's UnknownVersionBlob answers a signed blob of
// version 2. The client holds the release, which does not read version 2: it refuses the answer (ErrBadResponse). That
// a policy reading version 2 takes such a blob is the transport's TestTheTenantKeyBlobVersionLifecycle.
func TestTheClientTakesAnAnsweredBlobOfEveryReadVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	fake := cipherontest.New(t, "docs")
	fake.MakePerTenant("docs")
	c, err := client.DialGRPC(fake.ServeSocket(t), client.WithServerUID(uint32(os.Getuid())),
		client.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	k, err := c.CreateTenantKey(ctx, "docs", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	const v2 = cipherontest.UnknownBlobVersion
	fake.SetMode(cipherontest.UnknownVersionBlob)
	if _, err := c.CreateTenantKey(ctx, "docs", "t_2"); !errors.Is(err, client.ErrBadResponse) {
		t.Fatalf("version %d not read: CreateTenantKey answered it: %v, want ErrBadResponse", v2, err)
	}
	// The client's blob of version 1 still rewraps: the refusal is of the answer's version alone.
	fake.SetMode(cipherontest.Honest)
	if _, err := c.RewrapTenantKey(ctx, "docs", "t_1", k.Blob); err != nil {
		t.Fatalf("a version-1 blob after a refused version-2 answer: %v", err)
	}
}
