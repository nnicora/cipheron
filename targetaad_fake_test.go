//go:build linux || darwin

package cipheron_test

// targetaad_fake_test.go — owner decisions R8 (2026-11-18) and S2 (2026-11-19): a re-encryption keeps the caller's
// associated data — it never drops it without a word, and never changes it. Every re-encryption of the library —
// ReEncrypt, ReEncryptAcross (shared and tenant scopes), the tenant forms, ReEncryptBatch, and the helpers
// ReEncryptJSONFields, ReEncryptObject and ReEncryptStream — given WithAssociatedData (a batch item: AssociatedData)
// and no WithTargetAssociatedData (ToAssociatedData), or other associated data as the target, or a target's only, is
// refused before anything is sent: ErrAssociatedData, which is ErrInvalidInput, naming the option. For the helpers the
// rule is on the caller's part: their own binding (record and pointer, object id and position) is always sent and
// always the same, so cipheron could not see the caller's part. With the same associated data as the target each call
// is served, and the binding is kept.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestAReEncryptionNeverDropsTheCallersAssociatedData(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	profiles := []string{"docs", "archive", "files", "vault"}
	fake := cipherontest.New(t, profiles...)
	fake.MakePerTenant("files")
	fake.MakePerTenant("vault")
	opts := []cipheron.Option{cipheron.WithAnyServer()}
	for _, d := range profiles {
		opts = append(opts, cipheron.WithProfileFingerprint(d, fake.Fingerprint(d)))
	}
	c := newClient(t, fake.ServeSocket(t), opts...)
	bound := []byte("records/r-1")
	aad, keep := cipheron.WithAssociatedData(bound), cipheron.WithTargetAssociatedData(bound)
	ptrs := []string{"/iban"}
	doc := []byte(`{"iban":"DE89370400440532013000","id":"r-1"}`)
	pt := random(t, 3*transport.MinSegmentSize+5)
	seg := cipheron.WithSegmentSize(transport.MinSegmentSize)
	must := func(b []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	ct := must(c.Encrypt(ctx, "docs", []byte("the row"), aad))
	fields := must(c.EncryptJSONFields(ctx, "docs", doc, "r-1", ptrs, aad))
	obj := must(c.EncryptObject(ctx, "docs", pt, seg, aad))
	fk, err := c.CreateTenantKey(ctx, "files", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	vk, err := c.CreateTenantKey(ctx, "vault", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	t1, v1 := c.Tenant("files", "t_1", fk.Blob), c.Tenant("vault", "t_1", vk.Blob)
	tct := must(t1.Encrypt(ctx, []byte("the file"), aad))
	tfields := must(t1.EncryptJSONFields(ctx, doc, "r-1", ptrs, aad))
	tobj := must(t1.EncryptObject(ctx, pt, seg, aad))

	// Each call, and how its result is read back (with the options given).
	type call struct {
		do   func(...cipheron.CallOption) ([]byte, error)
		read func([]byte, ...cipheron.CallOption) ([]byte, error)
		want []byte
	}
	stream := func(f func(*bytes.Buffer, ...cipheron.CallOption) (int64, error)) func(...cipheron.CallOption) ([]byte, error) {
		return func(o ...cipheron.CallOption) ([]byte, error) {
			var out bytes.Buffer
			n, err := f(&out, o...)
			if err != nil && (n != 0 || out.Len() != 0) {
				t.Errorf("a refused stream wrote %d bytes", out.Len())
			}
			return out.Bytes(), err
		}
	}
	readDocs := func(b []byte, o ...cipheron.CallOption) ([]byte, error) { return c.Decrypt(ctx, "docs", b, o...) }
	readFields := func(b []byte, o ...cipheron.CallOption) ([]byte, error) {
		return c.DecryptJSONFields(ctx, "docs", b, "r-1", ptrs, o...)
	}
	readObject := func(b []byte, o ...cipheron.CallOption) ([]byte, error) { return c.DecryptObject(ctx, "docs", b, o...) }
	readTenantFields := func(b []byte, o ...cipheron.CallOption) ([]byte, error) {
		return t1.DecryptJSONFields(ctx, b, "r-1", ptrs, o...)
	}
	readTenantObject := func(b []byte, o ...cipheron.CallOption) ([]byte, error) { return t1.DecryptObject(ctx, b, o...) }
	calls := map[string]call{
		"ReEncrypt": {func(o ...cipheron.CallOption) ([]byte, error) { return c.ReEncrypt(ctx, "docs", ct, o...) },
			readDocs, []byte("the row")},
		"ReEncryptAcross": {func(o ...cipheron.CallOption) ([]byte, error) {
			return c.ReEncryptAcross(ctx, cipheron.Scope{Profile: "docs"}, cipheron.Scope{Profile: "archive"}, ct, o...)
		}, func(b []byte, o ...cipheron.CallOption) ([]byte, error) { return c.Decrypt(ctx, "archive", b, o...) }, []byte("the row")},
		"ReEncryptAcross, tenant scopes": {func(o ...cipheron.CallOption) ([]byte, error) {
			return c.ReEncryptAcross(ctx, cipheron.Scope{Profile: "files", Tenant: "t_1", TenantKey: fk.Blob},
				cipheron.Scope{Profile: "vault", Tenant: "t_1", TenantKey: vk.Blob}, tct, o...)
		}, func(b []byte, o ...cipheron.CallOption) ([]byte, error) { return v1.Decrypt(ctx, b, o...) }, []byte("the file")},
		"Tenant.ReEncrypt": {func(o ...cipheron.CallOption) ([]byte, error) { return t1.ReEncrypt(ctx, tct, fk.Blob, o...) },
			func(b []byte, o ...cipheron.CallOption) ([]byte, error) { return t1.Decrypt(ctx, b, o...) }, []byte("the file")},
		"ReEncryptJSONFields": {func(o ...cipheron.CallOption) ([]byte, error) {
			return c.ReEncryptJSONFields(ctx, "docs", fields, "r-1", ptrs, o...)
		}, readFields, doc},
		"Tenant.ReEncryptJSONFields": {func(o ...cipheron.CallOption) ([]byte, error) {
			return t1.ReEncryptJSONFields(ctx, tfields, "r-1", ptrs, fk.Blob, o...)
		}, readTenantFields, doc},
		"ReEncryptObject": {func(o ...cipheron.CallOption) ([]byte, error) { return c.ReEncryptObject(ctx, "docs", obj, o...) },
			readObject, pt},
		"Tenant.ReEncryptObject": {func(o ...cipheron.CallOption) ([]byte, error) {
			return t1.ReEncryptObject(ctx, tobj, fk.Blob, o...)
		}, readTenantObject, pt},
		"ReEncryptStream": {stream(func(out *bytes.Buffer, o ...cipheron.CallOption) (int64, error) {
			return c.ReEncryptStream(ctx, "docs", out, bytes.NewReader(obj), o...)
		}), readObject, pt},
		"Tenant.ReEncryptStream": {stream(func(out *bytes.Buffer, o ...cipheron.CallOption) (int64, error) {
			return t1.ReEncryptStream(ctx, out, bytes.NewReader(tobj), fk.Blob, o...)
		}), readTenantObject, pt},
	}

	// sent counts every request the fake saw: a signed or unsigned operation, a PublicKey.
	sent := func() int64 {
		v, a, r := fake.Auth()
		return v + a + r + fake.PublicKeyCalls() + fake.BatchCalls()
	}
	for name, cl := range calls {
		before := sent()
		out, err := cl.do(aad)
		if out != nil || !errors.Is(err, cipheron.ErrAssociatedData) || !errors.Is(err, cipheron.ErrInvalidInput) ||
			!strings.Contains(errText(err), "WithTargetAssociatedData") {
			t.Errorf("%s with WithAssociatedData alone: %d bytes, %v; want ErrAssociatedData naming WithTargetAssociatedData",
				name, len(out), err)
		}
		if sent() != before {
			t.Errorf("%s with WithAssociatedData alone: %d requests sent", name, sent()-before)
		}
		// Other associated data as the target's, or a target's alone: a re-binding, refused before anything is sent.
		for what, opts := range map[string][]cipheron.CallOption{
			"other target associated data":     {aad, cipheron.WithTargetAssociatedData([]byte("records/r-2"))},
			"a target's associated data alone": {keep},
		} {
			out, err := cl.do(opts...)
			if out != nil || !errors.Is(err, cipheron.ErrAssociatedData) || !errors.Is(err, cipheron.ErrInvalidInput) ||
				!errors.Is(err, transport.ErrAssociatedDataChanged) || sent() != before {
				t.Errorf("%s with %s: %d bytes, %v (%d requests sent); want ErrAssociatedData, nothing sent", name, what,
					len(out), err, sent()-before)
			}
		}
		// The same associated data as the target's: served, and the binding kept.
		out, err = cl.do(aad, keep)
		if err != nil {
			t.Errorf("%s with the target's: %v", name, err)
			continue
		}
		if got, err := cl.read(out, aad); err != nil || !bytes.Equal(got, cl.want) {
			t.Errorf("%s: the new data does not read with its associated data: %v", name, err)
		}
		if _, err := cl.read(out); err == nil {
			t.Errorf("%s: the new data reads without its associated data", name)
		}
	}

	// ReEncryptBatch: an item with AssociatedData and no ToAssociatedData, or with other ToAssociatedData, refuses the
	// whole batch before anything is sent; with the same, the items are served.
	for name, batch := range map[string]func([]cipheron.BatchItem) ([]cipheron.BatchResult, error){
		"ReEncryptBatch": func(items []cipheron.BatchItem) ([]cipheron.BatchResult, error) {
			return c.ReEncryptBatch(ctx, "docs", items)
		},
		"Tenant.ReEncryptBatch": func(items []cipheron.BatchItem) ([]cipheron.BatchResult, error) {
			return t1.ReEncryptBatch(ctx, items, fk.Blob)
		},
	} {
		data := ct
		if strings.HasPrefix(name, "Tenant") {
			data = tct
		}
		before := sent()
		rs, err := batch([]cipheron.BatchItem{{Data: data, AssociatedData: bound, ToAssociatedData: bound},
			{Data: data, AssociatedData: bound}})
		if rs != nil || !errors.Is(err, cipheron.ErrAssociatedData) || !errors.Is(err, cipheron.ErrInvalidInput) ||
			!strings.Contains(errText(err), "batch item 1") || sent() != before {
			t.Errorf("%s with an item's AssociatedData alone: %v, %v (%d requests sent)", name, rs, err, sent()-before)
		}
		rs, err = batch([]cipheron.BatchItem{{Data: data, AssociatedData: bound, ToAssociatedData: bound},
			{Data: data, AssociatedData: bound, ToAssociatedData: []byte("records/r-2")}})
		if rs != nil || !errors.Is(err, transport.ErrAssociatedDataChanged) || !strings.Contains(errText(err), "batch item 1") ||
			sent() != before {
			t.Errorf("%s with an item's other ToAssociatedData: %v, %v (%d requests sent)", name, rs, err, sent()-before)
		}
		if rs, err := batch([]cipheron.BatchItem{{Data: data, AssociatedData: bound, ToAssociatedData: bound}}); err != nil ||
			len(rs) != 1 || rs[0].Err != nil {
			t.Errorf("%s with the target's: %v, %v", name, rs, err)
		}
	}

	// No associated data on either side: served. A target's only would add a binding — a re-binding as well: refused
	// before anything is sent.
	plain := must(c.Encrypt(ctx, "docs", []byte("the note")))
	out, err := c.ReEncrypt(ctx, "docs", plain)
	if err != nil {
		t.Fatalf("no associated data: %v", err)
	}
	if got, err := c.Decrypt(ctx, "docs", out); err != nil || string(got) != "the note" {
		t.Fatalf("no associated data, read back: %q %v", got, err)
	}
	before := sent()
	if out, err = c.ReEncrypt(ctx, "docs", plain, keep); out != nil || !errors.Is(err, transport.ErrAssociatedDataChanged) ||
		sent() != before {
		t.Fatalf("a target's associated data only: %v (%d requests sent)", err, sent()-before)
	}
}
