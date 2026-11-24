package cipherontest

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// rawClient is a bare gRPC client of the fake's socket: requests exactly as the test builds them.
func rawClient(t *testing.T, s *Server) cipheronv1.CipherServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+s.ServeSocket(t), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return cipheronv1.NewCipherServiceClient(conn)
}

func nonce(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTheFakeRefusesUnknownFieldsOverGRPC (parity with cipheron's strictFields): a request carrying a field the API
// does not have — at the top level, or inside a message it holds (RequestAuth) — is INVALID_ARGUMENT naming the
// field, before the service sees it; the same request without it is served.
func TestTheFakeRefusesUnknownFieldsOverGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := New(t, "docs")
	c := rawClient(t, s)

	ok := &cipheronv1.PublicKeyRequest{Profile: "docs", RequestNonce: nonce(t, transport.NonceLen)}
	if _, err := c.PublicKey(ctx, ok); err != nil {
		t.Fatalf("a well-formed PublicKey: %v", err)
	}

	unknown := &cipheronv1.PublicKeyRequest{Profile: "docs", RequestNonce: nonce(t, transport.NonceLen)}
	unknown.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 999, protowire.VarintType), 1))
	calls := s.PublicKeyCalls()
	_, err := c.PublicKey(ctx, unknown)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a top-level unknown field: %v, want INVALID_ARGUMENT", err)
	}
	if s.PublicKeyCalls() != calls {
		t.Fatal("the service saw a request with an unknown field")
	}

	// Nested: an unknown field inside RequestAuth of an operation request.
	auth := &cipheronv1.RequestAuth{TimestampMs: time.Now().UnixMilli(), Signature: make([]byte, 64)}
	auth.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 77, protowire.BytesType), []byte("x")))
	_, err = c.Encrypt(ctx, &cipheronv1.EncryptRequest{Profile: "docs", RequestNonce: nonce(t, transport.NonceLen), Auth: auth})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || !containsAll(st.Message(), "77", "RequestAuth") {
		t.Fatalf("a nested unknown field: %v, want INVALID_ARGUMENT naming field 77 in RequestAuth", err)
	}
}

// TestTheFakesPublicKeyRefusesAMalformedNonce (parity with cipheron's PublicKey, S33): a request_nonce that is not
// transport.NonceLen bytes, none included, is INVALID_ARGUMENT; 16 bytes are answered.
func TestTheFakesPublicKeyRefusesAMalformedNonce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := rawClient(t, New(t, "docs"))
	for _, n := range []int{0, 1, 8, transport.NonceLen - 1, transport.NonceLen + 1, 32} {
		_, err := c.PublicKey(ctx, &cipheronv1.PublicKeyRequest{Profile: "docs", RequestNonce: nonce(t, n)})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("a %d-byte nonce: %v, want INVALID_ARGUMENT", n, err)
		}
	}
	for _, n := range []int{transport.NonceLen} {
		if _, err := c.PublicKey(ctx, &cipheronv1.PublicKeyRequest{Profile: "docs", RequestNonce: nonce(t, n)}); err != nil {
			t.Errorf("a %d-byte nonce: %v, want an answer", n, err)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
