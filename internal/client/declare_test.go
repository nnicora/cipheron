package client

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestEveryGRPCCallDeclaresItsSize: the gRPC connections' interceptor sends the request message's size — its protobuf
// encoding, what gRPC sends — as the one value of transport.RequestBytesMetadataKey, replacing whatever the caller's
// context put there, and leaves the rest of the metadata as it was; an empty message declares 1.
func TestEveryGRPCCallDeclaresItsSize(t *testing.T) {
	declared := func(ctx context.Context, req any) metadata.MD {
		t.Helper()
		var got metadata.MD
		err := declareRequestBytes(ctx, "/cipheron.v1.CipherService/Encrypt", req, nil, nil,
			func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				got, _ = metadata.FromOutgoingContext(ctx)
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	req := &cipheronv1.EncryptRequest{Profile: "d", Enc: make([]byte, 65), SealedPlaintext: bytes.Repeat([]byte{1}, 300<<10)}
	own := metadata.AppendToOutgoingContext(context.Background(), transport.RequestBytesMetadataKey, "7",
		transport.RequestBytesMetadataKey, "x", transport.RequestIDMetadataKey, "order-42")
	md := declared(own, req)
	if v := md.Get(transport.RequestBytesMetadataKey); len(v) != 1 || v[0] != strconv.Itoa(proto.Size(req)) {
		t.Fatalf("declared %v, want [%d]", v, proto.Size(req))
	}
	if v := md.Get(transport.RequestIDMetadataKey); len(v) != 1 || v[0] != "order-42" {
		t.Fatalf("the caller's other metadata: %v", v)
	}
	if mdOwn, _ := metadata.FromOutgoingContext(own); len(mdOwn.Get(transport.RequestBytesMetadataKey)) != 2 {
		t.Fatal("the caller's context was changed")
	}
	if v := declared(context.Background(), &cipheronv1.PublicKeyRequest{}).Get(transport.RequestBytesMetadataKey); len(v) != 1 || v[0] != "1" {
		t.Fatalf("an empty message declared %v", v)
	}
	if n, ok := transport.ParseRequestBytes(md.Get(transport.RequestBytesMetadataKey)[0]); !ok || n != int64(proto.Size(req)) {
		t.Fatalf("the declaration does not parse as cipheron reads it: %d %v", n, ok)
	}
}

// TestASegmentRequestFitsTheDefaultRequestSize: the largest request one segment of transport.MaxSegmentSize travels in,
// each batch kind a segmented object uses with every field at its largest — the profile, the tenant, the tenant key
// blobs, the recipient key, the associated data, the nonce and the signature — is within transport.SegmentRequestBytes
// (cipheron's default maxRequestBytes), its payload (transport.BatchBytes) within transport.DefaultBatchMaxBytes, and
// what it holds beyond its payload within transport.MaxBatchFraming.
func TestASegmentRequestFitsTheDefaultRequestSize(t *testing.T) {
	n := func(size int) []byte { return make([]byte, size) }
	profile, tenant := string(bytes.Repeat([]byte{'a'}, transport.MaxProfileLen)), string(bytes.Repeat([]byte{'t'}, transport.MaxTenantLen))
	auth := &cipheronv1.RequestAuth{TimestampMs: 1<<63 - 1, Signature: n(64)}
	ct, aad := n(transport.MaxSegmentSize+transport.MaxSegmentOverhead), n(transport.MaxAssociatedDataLen)
	blob := n(transport.MaxTenantKeyLen)
	for name, c := range map[string]struct {
		req     proto.Message
		payload int64
	}{
		"EncryptBatch": {&cipheronv1.EncryptBatchRequest{Profile: profile, Tenant: tenant, TenantKey: blob, RequestNonce: n(transport.NonceLen),
			Auth: auth, Items: []*cipheronv1.EncryptBatchItem{{Enc: n(transport.EncLen),
				SealedPlaintext: n(transport.MaxSegmentSize + transport.SealOverhead), AssociatedData: aad}}},
			transport.BatchBytes(blob) + transport.SealedItemBytes(transport.MaxSegmentSize, transport.MaxAssociatedDataLen)},
		"DecryptBatch": {&cipheronv1.DecryptBatchRequest{Profile: profile, Tenant: tenant, TenantKey: blob, RecipientPublicKey: n(transport.PublicKeyLen),
			RequestNonce: n(transport.NonceLen), Auth: auth, Items: []*cipheronv1.DecryptBatchItem{{Ciphertext: ct, AssociatedData: aad}}},
			transport.BatchBytes(blob, n(transport.PublicKeyLen), ct, aad)},
		"ReEncryptBatch": {&cipheronv1.ReEncryptBatchRequest{Profile: profile, Tenant: tenant, TenantKey: blob, ToTenantKey: blob,
			RequestNonce: n(transport.NonceLen), Auth: auth, Items: []*cipheronv1.ReEncryptBatchItem{{Ciphertext: ct,
				AssociatedData: aad, ToAssociatedData: aad}}},
			transport.BatchBytes(blob, blob, ct, aad, aad)},
	} {
		size := int64(proto.Size(c.req))
		if size > transport.SegmentRequestBytes {
			t.Errorf("%s: a segment's request is %d bytes, over %d", name, size, transport.SegmentRequestBytes)
		}
		if c.payload > transport.DefaultBatchMaxBytes || c.payload > int64(batchFixedBytes+transport.MaxSegmentItemBytes) {
			t.Errorf("%s: a segment's payload is %d bytes, over %d", name, c.payload, transport.DefaultBatchMaxBytes)
		}
		if size-c.payload > transport.MaxBatchFraming {
			t.Errorf("%s: %d bytes beyond the payload, over MaxBatchFraming %d", name, size-c.payload, transport.MaxBatchFraming)
		}
	}
}
