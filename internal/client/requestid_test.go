package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/wire/transport"
)

// TestEveryCallHasARequestID (OB-11): a call's context gets an id — the caller's own when its outgoing metadata has a
// usable one, else a new random one, which replaces an unusable value.
func TestEveryCallHasARequestID(t *testing.T) {
	ctx, id := withRequestID(context.Background())
	if len(id) != 32 || outgoingRequestID(ctx) != id {
		t.Fatalf("a new id: %q (outgoing %q)", id, outgoingRequestID(ctx))
	}
	own := metadata.AppendToOutgoingContext(context.Background(), transport.RequestIDMetadataKey, "order-42")
	if _, id := withRequestID(own); id != "order-42" {
		t.Fatalf("the caller's id: %q", id)
	}
	for _, bad := range []string{strings.Repeat("x", maxRequestIDLen+1), "a\nb", "é"} {
		ctx := metadata.AppendToOutgoingContext(context.Background(), transport.RequestIDMetadataKey, bad)
		ctx, id := withRequestID(ctx)
		md, _ := metadata.FromOutgoingContext(ctx)
		if id == bad || len(md.Get(transport.RequestIDMetadataKey)) != 1 || md.Get(transport.RequestIDMetadataKey)[0] != id {
			t.Fatalf("an unusable id %q: sent %v", bad, md.Get(transport.RequestIDMetadataKey))
		}
	}
}

// TestTheIDChangesNothingOfTheError: text, gRPC status, errors.Is and errors.As answer as without it, through wraps.
func TestTheIDChangesNothingOfTheError(t *testing.T) {
	st := status.Error(codes.PermissionDenied, "permission denied")
	err := fmt.Errorf("cipheron: call: %w", withID(st, "rid-1"))
	if RequestIDOf(err) != "rid-1" || err.Error() != "cipheron: call: "+st.Error() {
		t.Fatalf("%v / %q", err, RequestIDOf(err))
	}
	if status.Code(withID(st, "rid-1")) != codes.PermissionDenied || status.Convert(withID(st, "rid-1")).Message() != "permission denied" {
		t.Fatal("the status changed")
	}
	plain := withID(ErrClosed, "rid-2")
	if !errors.Is(plain, ErrClosed) || plain.Error() != ErrClosed.Error() || RequestIDOf(plain) != "rid-2" {
		t.Fatalf("a plain error: %v", plain)
	}
	if _, ok := status.FromError(plain); ok {
		t.Fatal("a plain error gained a gRPC status")
	}
	if withID(nil, "x") != nil || RequestIDOf(errors.New("x")) != "" || RequestIDOf(withID(withID(st, "a"), "b")) != "a" {
		t.Fatal("nil, none, or a second id")
	}
	joined := errors.Join(errors.New("other"), withID(st, "rid-3"))
	if RequestIDOf(joined) != "rid-3" {
		t.Fatal("an id inside errors.Join")
	}
}

// TestTheObserverIsToldTheFixedKinds (OB-12).
func TestTheObserverIsToldTheFixedKinds(t *testing.T) {
	var got []string
	c := &Client{observer: func(profile, kind string) { got = append(got, profile+"/"+kind) }}
	for _, e := range []error{fmt.Errorf("%w: x", ErrContextDigest), ErrServerKeyChanged,
		identityFailure(errors.New("x")), ErrBadResponse, ErrKeysStale, ErrClosed, nil,
		status.Error(codes.PermissionDenied, "permission denied")} {
		c.observe("records", e)
	}
	want := []string{"records/context_digest", "records/server_key_changed",
		"records/server_identity", "records/keys_stale"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("observed %v; want %v", got, want)
	}
	(&Client{}).observe("d", ErrKeysStale) // no observer: nothing
	if len(ObserverKinds) != 6 {
		t.Fatal(ObserverKinds)
	}
}
