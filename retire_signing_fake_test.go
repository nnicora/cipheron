//go:build linux || darwin

package cipheron_test

// retire_signing_fake_test.go — two lifecycle stages the fake models for an application's tests: a master version's
// retirement (RetireVersion, cipheron's removal of the version from the list), whose refusal is cipheron's — the same
// code, reason and message, so the application's handling of ErrKeyVersionUnavailable is what it tests — and a
// signing key published verify-only before it signs (AddSigningKey, then ActivateSigning: signing.generations, then
// signing.activeGeneration), signatures under either key verifying. reencrypt_e2e_test.go holds the fake's refusal
// to a real cipheron's.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
)

func TestTheFakeRetiresAVersion(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs", "files")
	fake.MakePerTenant("files")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")),
		cipheron.WithProfileFingerprint("files", fake.Fingerprint("files")))
	ct0, err := c.Encrypt(ctx, "docs", []byte("under v1"))
	if err != nil || keyOf(t, ct0).String() != "v1" {
		t.Fatalf("a row under v1: %v", err)
	}
	k0, err := c.CreateTenantKey(ctx, "files", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	f0, err := c.Tenant("files", "t_1", k0.Blob).Encrypt(ctx, []byte("a file of a blob under v1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"docs", "files"} {
		fake.SetWriteVersion(d, "v2") // v2 created and activated; v1 still listed
	}
	c = newClient(t, fake.SocketPath(), cipheron.WithAnyServer()) // a pod restarted with the new pins
	ct1, err := c.Encrypt(ctx, "docs", []byte("under v2"))
	if err != nil || keyOf(t, ct1).String() != "v2" {
		t.Fatalf("a row under v2: %v", err)
	}
	if _, err := c.Decrypt(ctx, "docs", ct0); err != nil {
		t.Fatalf("a row under v1, still listed: %v", err)
	}

	// v1 removed from the list: what it made is refused as cipheron refuses it — ErrKeyVersionUnavailable, not
	// ErrInvalidInput (not corrupt, not lost), with cipheron's message; the context digest changes.
	before := fake.ContextDigest("docs")
	fake.RetireVersion("docs", "v1")
	if fake.ContextDigest("docs") == before {
		t.Fatal("retiring a version did not change the key-context digest")
	}
	c = newClient(t, fake.SocketPath(), cipheron.WithAnyServer())
	_, err = c.Decrypt(ctx, "docs", ct0)
	if !errors.Is(err, cipheron.ErrKeyVersionUnavailable) || errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("a row of a retired version: %v", err)
	}
	if st, _ := status.FromError(err); !strings.Contains(st.Message(), cipherontest.KeyVersionUnavailable) {
		t.Fatalf("the refusal's message: %q", st.Message())
	}
	if _, err := c.ReEncrypt(ctx, "docs", ct0); !errors.Is(err, cipheron.ErrKeyVersionUnavailable) {
		t.Fatalf("ReEncrypt of a row of a retired version: %v", err)
	}
	res, err := c.DecryptBatch(ctx, "docs", []cipheron.BatchItem{{Data: ct0}, {Data: ct1}})
	if err != nil || !errors.Is(res[0].Err, cipheron.ErrKeyVersionUnavailable) || res[1].Err != nil || string(res[1].Value) != "under v2" {
		t.Fatalf("a batch of both versions: %+v %v", res, err)
	}
	// Retirement only refuses: listed again, v1's rows read, and the digest is the one before.
	fake.ListVersion("docs", "v1")
	if fake.ContextDigest("docs") != before {
		t.Fatal("listed again: another key-context digest")
	}
	c = newClient(t, fake.SocketPath(), cipheron.WithAnyServer())
	for _, ct := range [][]byte{ct0, ct1} {
		if _, err := c.Decrypt(ctx, "docs", ct); err != nil {
			t.Fatalf("listed again: %v", err)
		}
	}

	// A blob wrapped under a retired version: every call of its tenant is refused, with cipheron's message for a
	// tenant key; a new blob is wrapped under the writer.
	fake.RetireVersion("files", "v1")
	c = newClient(t, fake.SocketPath(), cipheron.WithAnyServer())
	_, err = c.Tenant("files", "t_1", k0.Blob).Decrypt(ctx, f0)
	if !errors.Is(err, cipheron.ErrKeyVersionUnavailable) || errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("a file under a blob of a retired version: %v", err)
	}
	if st, _ := status.FromError(err); !strings.Contains(st.Message(), "the key version of this tenant key is not available") {
		t.Fatalf("the blob's refusal: %q", st.Message())
	}
	if _, err := c.RewrapTenantKey(ctx, "files", "t_1", k0.Blob); !errors.Is(err, cipheron.ErrKeyVersionUnavailable) {
		t.Fatalf("a rewrap of a blob of a retired version: %v", err)
	}
	k2, err := c.CreateTenantKey(ctx, "files", "t_2")
	if err != nil {
		t.Fatal(err)
	}
	if info, err := cipheron.ReadTenantKey(k2.Blob); err != nil || info.WrappingVersion != "v2" {
		t.Fatalf("a new blob with v1 retired: %+v %v", info, err)
	}
}

func TestTheFakePublishesASigningKeyBeforeItSigns(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	key1 := fake.ActiveKeyID("docs")
	sig1, err := c.Sign(ctx, "docs", []byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	install, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	states := func(keys []cipheron.SigningKey) map[string]string {
		out := map[string]string{}
		for _, k := range keys {
			out[string(k.KeyID)] = k.State
		}
		return out
	}

	// Stage 7: key 2 published verify-only — listed, a new digest — while key 1 signs.
	d1 := fake.ContextDigest("docs")
	key2 := fake.AddSigningKey("docs")
	d2 := fake.ContextDigest("docs")
	if d2 == d1 {
		t.Fatal("a signing key published did not change the key-context digest")
	}
	c = newClient(t, fake.SocketPath(), cipheron.WithAnyServer())
	published, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if st := states(published.SigningKeys); len(st) != 2 || st[string(key1)] != cipheron.SigningKeyActive ||
		st[string(key2)] != cipheron.SigningKeyVerifyOnly {
		t.Fatalf("the published keys: %v", st)
	}
	if s, err := c.Sign(ctx, "docs", []byte("still key 1")); err != nil || !bytes.Equal(s.KeyID, key1) {
		t.Fatalf("a signature while key 2 is verify-only: %x %v", s.KeyID, err)
	}

	// Stage 8: key 2 signs, key 1 verify-only; the digest is stage 7's.
	fake.ActivateSigning("docs", key2)
	if fake.ContextDigest("docs") != d2 || !bytes.Equal(fake.ActiveKeyID("docs"), key2) {
		t.Fatal("the activation moved the digest, or did not activate key 2")
	}
	sig2, err := c.Sign(ctx, "docs", []byte("after"))
	if err != nil || !bytes.Equal(sig2.KeyID, key2) {
		t.Fatalf("a signature after the activation: %x %v", sig2.KeyID, err)
	}
	c = newClient(t, fake.SocketPath(), cipheron.WithAnyServer())
	now, err := c.Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if st := states(now.SigningKeys); st[string(key1)] != cipheron.SigningKeyVerifyOnly || st[string(key2)] != cipheron.SigningKeyActive {
		t.Fatalf("the keys after the activation: %v", st)
	}
	// Either key's signatures verify: online, and offline with the list published at stage 7 (key 2 known before it
	// signed) or now. The install's list does not know key 2: nothing verified.
	for name, keys := range map[string][]cipheron.SigningKey{"stage 7's list": published.SigningKeys, "today's list": now.SigningKeys} {
		for _, s := range []struct {
			data string
			sig  cipheron.Signature
		}{{"before", sig1}, {"after", sig2}} {
			if ok, err := cipheron.VerifyWithKeys(keys, []byte(s.data), s.sig.Bytes, s.sig.KeyID); !ok || err != nil {
				t.Fatalf("%s, a signature under %x: %v %v", name, s.sig.KeyID, ok, err)
			}
			if ok, err := c.Verify(ctx, "docs", []byte(s.data), s.sig.Bytes, s.sig.KeyID); !ok || err != nil {
				t.Fatalf("online, a signature under %x: %v %v", s.sig.KeyID, ok, err)
			}
		}
	}
	if ok, err := cipheron.VerifyWithKeys(install.SigningKeys, []byte("after"), sig2.Bytes, sig2.KeyID); ok ||
		!errors.Is(err, cipheron.ErrUnknownSigningKey) {
		t.Fatalf("the install's list, a signature under key 2: %v %v", ok, err)
	}
}
