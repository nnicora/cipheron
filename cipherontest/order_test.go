package cipherontest

// order_test.go — the fake follows cipheron's admission (owner decisions S11 and S2): for a profile with a request key the
// request's auth is verified before the grant, so a request that does not verify is refused for its signature whatever
// is granted; and a re-encryption to other associated data than the stored ciphertext's is served only where decrypt
// (the source profile) and encrypt (the profile the new ciphertext is made in) are granted.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

func nonce16() []byte {
	n := make([]byte, transport.NonceLen)
	_, _ = rand.Read(n)
	return n
}

func TestTheFakeVerifiesAKeyedRequestBeforeItsGrant(t *testing.T) {
	s := New(t, "a")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	s.RequireRequestKey("a", pub)
	s.Grant("a", transport.OpSign) // no encrypt
	encrypt := func(key ed25519.PrivateKey) error {
		n, junk := nonce16(), []byte("junk")
		d := transport.EncryptDigest(junk, junk, "", nil)
		ts := time.Now().UnixMilli()
		_, err := s.Encrypt(context.Background(), &cipheronv1.EncryptRequest{Profile: "a", Enc: junk, SealedPlaintext: junk,
			RequestNonce: n, Auth: &cipheronv1.RequestAuth{TimestampMs: ts,
				Signature: ed25519.Sign(key, transport.RequestTranscript(transport.Release(), "a", transport.OpEncrypt, ts, n, d))}})
		return err
	}
	if err := encrypt(stranger); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another key's signature: %v", err)
	}
	if verified, _, refused := s.Auth(); verified != 0 || refused != 1 {
		t.Fatalf("another key's signature, an operation not granted: %d verified, %d refused; want the signature judged "+
			"(refused) before the grant", verified, refused)
	}
	if err := encrypt(priv); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the profile's key, an operation not granted: %v", err)
	}
	if verified, _, _ := s.Auth(); verified != 1 {
		t.Fatalf("the profile's key, an operation not granted: %d verified; want the signature verified first", verified)
	}
}

func TestTheFakeReBindsOnlyForDecryptAndEncrypt(t *testing.T) {
	s := New(t, "a", "b")
	ctx := context.Background()
	row1, row2 := []byte("rows/1"), []byte("rows/2")
	ct := s.encryptVersioned(s.profile("a"), "a", "", []byte("the row"), row1)
	reencrypt := func(toProfile string, toAAD []byte) error {
		_, err := s.ReEncrypt(ctx, &cipheronv1.ReEncryptRequest{Profile: "a", Ciphertext: ct, RequestNonce: nonce16(),
			AssociatedData: row1, ToAssociatedData: toAAD, ToProfile: toProfile})
		return err
	}
	batch := func(toAAD []byte) (*cipheronv1.ItemError, error) {
		r, err := s.ReEncryptBatch(ctx, &cipheronv1.ReEncryptBatchRequest{Profile: "a", RequestNonce: nonce16(),
			Items: []*cipheronv1.ReEncryptBatchItem{{Ciphertext: ct, AssociatedData: row1, ToAssociatedData: toAAD}}})
		if err != nil {
			return nil, err
		}
		return r.GetResults()[0].GetError(), nil
	}

	s.Grant("a", transport.OpReEncrypt, transport.OpExport)
	s.Grant("b", transport.OpImport)
	for name, err := range map[string]error{"within": reencrypt("", row1), "across": reencrypt("b", row1)} {
		if err != nil {
			t.Fatalf("%s, the binding kept: %v", name, err)
		}
	}
	for name, err := range map[string]error{"within": reencrypt("", row2), "across": reencrypt("b", row2),
		"within, a target's only": reencrypt("", nil)} {
		want := codes.PermissionDenied
		if name == "within, a target's only" {
			want = codes.InvalidArgument // associated data dropped: the shape's refusal, for everyone
		}
		if status.Code(err) != want {
			t.Fatalf("%s, reencrypt (or export and import) alone, other associated data: %v; want %s", name, err, want)
		}
	}
	if e, err := batch(row2); err != nil || codes.Code(e.GetCode()) != codes.PermissionDenied {
		t.Fatalf("a batch item to other associated data, reencrypt alone: %v %v", e, err)
	}

	// decrypt on the source and encrypt where the new ciphertext is made: served.
	s.Grant("a", transport.OpReEncrypt, transport.OpExport, transport.OpDecrypt, transport.OpEncrypt)
	if err := reencrypt("", row2); err != nil {
		t.Fatalf("within, decrypt and encrypt granted: %v", err)
	}
	if e, err := batch(row2); err != nil || e != nil {
		t.Fatalf("a batch item, decrypt and encrypt granted: %v %v", e, err)
	}
	if err := reencrypt("b", row2); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("across, no encrypt on the target: %v", err)
	}
	s.Grant("b", transport.OpImport, transport.OpEncrypt)
	if err := reencrypt("b", row2); err != nil {
		t.Fatalf("across, decrypt on the source and encrypt on the target: %v", err)
	}
}
