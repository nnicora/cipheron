//go:build linux || darwin

package cipheron_test

// wavec_fake_test.go — the deep review's wave C against the fake (cipherontest): the fake's grants follow cipheron's
// (D-A: a cross-profile ReEncrypt is export on the source and import on the target; reencrypt is within a profile).

import (
	"errors"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

func TestTheFakesCrossProfileGrants(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	for _, tc := range []struct {
		name string
		a, b []transport.Operation
		ok   bool
	}{
		{"reencrypt on both", []transport.Operation{transport.OpEncrypt, transport.OpReEncrypt},
			[]transport.Operation{transport.OpReEncrypt, transport.OpDecrypt}, false},
		{"export and import", []transport.Operation{transport.OpEncrypt, transport.OpExport},
			[]transport.Operation{transport.OpImport}, true},
		{"export without import", []transport.Operation{transport.OpEncrypt, transport.OpExport},
			[]transport.Operation{transport.OpReEncrypt}, false},
		{"import without export", []transport.Operation{transport.OpEncrypt, transport.OpReEncrypt},
			[]transport.Operation{transport.OpImport}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := cipherontest.New(t, "a", "b")
			fake.Grant("a", tc.a...)
			fake.Grant("b", tc.b...)
			c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("a", fake.Fingerprint("a")),
				cipheron.WithProfileFingerprint("b", fake.Fingerprint("b")))
			ct, err := c.Encrypt(ctx, "a", []byte("m"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.ReEncryptAcross(ctx, cipheron.Scope{Profile: "a"}, cipheron.Scope{Profile: "b"}, ct)
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, cipheron.ErrPermissionDenied)) {
				t.Fatalf("ok %v: %v", tc.ok, err)
			}
		})
	}
	// Within a profile: reencrypt, not export.
	fake := cipherontest.New(t, "a")
	fake.Grant("a", transport.OpEncrypt, transport.OpExport, transport.OpImport)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("a", fake.Fingerprint("a")))
	ct, err := c.Encrypt(ctx, "a", []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReEncrypt(ctx, "a", ct); !errors.Is(err, cipheron.ErrPermissionDenied) {
		t.Fatalf("within a profile granted export and import only: %v", err)
	}
	if _, err := c.Decrypt(ctx, "a", ct); !errors.Is(err, cipheron.ErrPermissionDenied) {
		t.Fatalf("decrypt not granted: %v", err)
	}
}

// TestTheFakesRetenantIsCipherons: a cross-profile ReEncrypt that changes the tenant (transport.ChangesTenant: another
// tenant, or a move between a shared and a perTenant profile, either way) needs retenant on the SOURCE profile, as in
// cipheron (cmd/cipheron/app/server retenant_test.go runs the same moves); export and import alone keep the tenant.
func TestTheFakesRetenantIsCipherons(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	profiles := []string{"s1", "s2", "w1", "w2", "d1", "d2"}
	fake := cipherontest.New(t, profiles...)
	fake.MakePerTenant("w1")
	fake.MakePerTenant("w2")
	fake.MakeDerived("d1")
	fake.MakeDerived("d2")
	var opts []cipheron.Option
	for _, d := range profiles {
		opts = append(opts, cipheron.WithProfileFingerprint(d, fake.Fingerprint(d)))
	}
	c := newClient(t, fake.ServeSocket(t), append(opts, cipheron.WithAnyServer())...)
	blob := func(profile, tenant string) []byte { return fake.NewTenantKey(profile, tenant) }
	w1a, w2a, w2b := blob("w1", "t_a"), blob("w2", "t_a"), blob("w2", "t_b")
	scope := func(profile, tenant string, key []byte) cipheron.Scope {
		return cipheron.Scope{Profile: profile, Tenant: tenant, TenantKey: key}
	}
	for _, tc := range []struct {
		name     string
		from, to cipheron.Scope
		open     string // the tenant the moved record opens for ("" in a shared profile)
		changes  bool
	}{
		{"shared to shared", scope("s1", "", nil), scope("s2", "", nil), "", false},
		{"wrapped, the same tenant named", scope("w1", "t_a", w1a), scope("w2", "t_a", w2a), "t_a", false},
		{"derived, the same tenant", scope("d1", "t_a", nil), scope("d2", "t_a", nil), "t_a", false},
		{"derived to wrapped, the same tenant", scope("d1", "t_a", nil), scope("w2", "t_a", w2a), "t_a", false},
		{"wrapped, another tenant", scope("w1", "t_a", w1a), scope("w2", "t_b", w2b), "t_b", true},
		{"derived, another tenant", scope("d1", "t_a", nil), scope("d2", "t_b", nil), "t_b", true},
		{"shared to wrapped", scope("s1", "", nil), scope("w2", "t_a", w2a), "t_a", true},
		{"wrapped to shared", scope("w1", "t_a", w1a), scope("s2", "", nil), "", true},
		{"derived to shared", scope("d1", "t_a", nil), scope("s2", "", nil), "", true},
		{"shared to derived", scope("s1", "", nil), scope("d2", "t_a", nil), "t_a", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := func(from, to []transport.Operation) {
				for _, d := range profiles {
					fake.Grant(d, transport.GrantableOperations()...)
				}
				fake.Grant(tc.from.Profile, from...)
				fake.Grant(tc.to.Profile, to...)
			}
			grant(transport.GrantableOperations(), transport.GrantableOperations())
			var ct []byte
			var err error
			if tc.from.Tenant == "" {
				ct, err = c.Encrypt(ctx, tc.from.Profile, []byte("m"))
			} else {
				ct, err = c.Tenant(tc.from.Profile, tc.from.Tenant, tc.from.TenantKey).Encrypt(ctx, []byte("m"))
			}
			if err != nil {
				t.Fatal(err)
			}
			exportImport := []transport.Operation{transport.OpExport, transport.OpImport}
			for _, g := range []struct {
				name     string
				from, to []transport.Operation
				ok       bool
			}{
				{"export and import", exportImport, exportImport, !tc.changes},
				{"retenant in the source", append(exportImport, transport.OpRetenant), exportImport, true},
				{"retenant in the target only", exportImport, append(exportImport, transport.OpRetenant), !tc.changes},
			} {
				grant(g.from, g.to)
				moved, err := c.ReEncryptAcross(ctx, tc.from, tc.to, ct)
				if g.ok != (err == nil) || (!g.ok && !errors.Is(err, cipheron.ErrPermissionDenied)) {
					t.Fatalf("%s: ok %v: %v", g.name, g.ok, err)
				}
				if !g.ok {
					continue
				}
				// The moved record opens for the target tenant.
				grant(transport.GrantableOperations(), transport.GrantableOperations())
				var pt []byte
				if tc.open == "" {
					pt, err = c.Decrypt(ctx, tc.to.Profile, moved)
				} else {
					pt, err = c.Tenant(tc.to.Profile, tc.open, tc.to.TenantKey).Decrypt(ctx, moved)
				}
				if err != nil || string(pt) != "m" {
					t.Fatalf("%s: the moved record: %q, %v", g.name, pt, err)
				}
			}
		})
	}
}

// TestTheBatchSplitterCountsAsCipheron (P9): the client's batch splitter counts a batch's payload as cipheron's
// batch.maxBytes does (transport.BatchBytes: an EncryptBatch item's encapsulated key and seal tag included), so a
// segmented object under a limit equal to the splitter's budget is never refused.
func TestTheBatchSplitterCountsAsCipheron(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	fake.SetBatchMaxBytes(transport.DefaultBatchMaxBytes * 3 / 4)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	obj := make([]byte, 200*8192)
	enc, err := c.EncryptObject(ctx, "docs", obj, cipheron.WithSegmentSize(8192))
	if err != nil {
		t.Fatal(err)
	}
	if n := fake.BatchRefusals(); n != 0 {
		t.Fatalf("the splitter's batches were refused %d time(s): it does not count as cipheron does", n)
	}
	if _, err := c.DecryptObject(ctx, "docs", enc); err != nil || fake.BatchRefusals() != 0 {
		t.Fatalf("decrypt: %v (%d refusals)", err, fake.BatchRefusals())
	}
}
