//go:build linux || darwin

package cipheron_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
)

// A SEGMENT TOO LARGE FOR CIPHERON'S REQUESTS SAYS WHAT TO DO: each segment travels in one request, so against a
// cipheron accepting requests of 1 MiB (its default maxRequestBytes) a 1 MiB segment is refused — ErrTooLarge, naming
// the segment size and the remedy — for an object and a stream alike, while a 700 KiB segment is served.
func TestASegmentTooLargeForCipheronSaysWhatToDo(t *testing.T) {
	ctx := context.Background()
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocketMax(t, 1<<20), cipheron.WithServerUID(myUID()))
	data := bytes.Repeat([]byte{7}, 3<<20)
	_, err := c.EncryptObject(ctx, profile, data, cipheron.WithSegmentSize(1<<20))
	if !errors.Is(err, cipheron.ErrTooLarge) || !strings.Contains(err.Error(), "lower WithSegmentSize") {
		t.Fatalf("EncryptObject with 1 MiB segments: %v", err)
	}
	var out bytes.Buffer
	_, err = c.EncryptStream(ctx, profile, &out, bytes.NewReader(data), int64(len(data)), cipheron.WithSegmentSize(1<<20))
	if !errors.Is(err, cipheron.ErrTooLarge) || !strings.Contains(err.Error(), "lower WithSegmentSize") {
		t.Fatalf("EncryptStream with 1 MiB segments: %v", err)
	}
	obj, err := c.EncryptObject(ctx, profile, data, cipheron.WithSegmentSize(700<<10))
	if err != nil {
		t.Fatalf("EncryptObject with 700 KiB segments: %v", err)
	}
	if pt, err := c.DecryptObject(ctx, profile, obj); err != nil || !bytes.Equal(pt, data) {
		t.Fatalf("DecryptObject: %v", err)
	}
}

// A SEGMENT TOO LARGE FOR THIS CLIENT'S MESSAGES IS REFUSED BEFORE ANYTHING IS SENT: a segment size whose request
// cannot fit WithMaxMessageBytes is ErrTooLarge, naming both remedies, and cipheron sees no call.
func TestASegmentTooLargeForTheClientIsRefusedBeforeSending(t *testing.T) {
	ctx := context.Background()
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()), cipheron.WithMaxMessageBytes(64<<10))
	roundTrip(t, c, []byte("the keys, fetched")) // the profile's keys are held: the next call needs none
	calls := func() int64 { v, a, r := fake.Auth(); return v + a + r }
	before := calls()
	_, err := c.EncryptObject(ctx, profile, bytes.Repeat([]byte{1}, 256<<10), cipheron.WithSegmentSize(128<<10))
	if !errors.Is(err, cipheron.ErrTooLarge) || !strings.Contains(err.Error(), "raise WithMaxMessageBytes") {
		t.Fatalf("EncryptObject with a segment over the client's messages: %v", err)
	}
	if n := calls() - before; n != 0 {
		t.Fatalf("cipheron saw %d call(s) for a segment refused before sending", n)
	}
}

// AN INVALID TENANT ID IS NAMED BOUNDED: a refusal quotes at most its first 32 bytes and its length, so an id of
// thousands of bytes (or any bytes) never floods a log through the error.
func TestAnInvalidTenantIDIsNamedBounded(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	long := strings.Repeat("a", 3000) + " "
	_, err := c.CreateTenantKey(context.Background(), profile, long)
	if err == nil || !strings.Contains(err.Error(), "… (3001 bytes) is not a tenant id") || len(err.Error()) > 400 {
		t.Fatalf("CreateTenantKey with a 3001-byte id: %d bytes of error: %.120q", len(err.Error()), err)
	}
}
