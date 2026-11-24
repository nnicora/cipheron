//go:build linux || darwin

package client

// answercontext_test.go — owner decision S3 (review finding CL-1) and the fixes that came with it: every answer's
// response signature covers the key-context digest of the replica that made it, and the client verifies it under the
// digests it accepts now (the context pins in force, else the digests the profile's verified PublicKey answers gave);
// the cached keys of a profile whose fetch or answer was of an unpinned context are not used until a pinned replica
// answers (CL-1, fixNow); keys a fetch stored are held to the pin set the fetch began under, never taken as checked
// under a newer one (CL-1, fixNow: the live-pins stamping window); a fingerprint pin added live holds for Keys and
// KeyStatement of a profile already cached (CL-8); and the writer pin (WithWriterVersionPin) holds every answer that
// makes new data to the master versions it names.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestAnAnswerOfAnotherContextIsRefused (S3): a replica of the profile — the right identity, the right response key —
// that answers a data call under a key context the client does not accept is refused, whatever the cached keys say,
// with nothing returned: pinned, as ErrServerIdentity when the context is one no PublicKey answer showed this client
// (it cannot be told from a forged answer); unpinned, the same. The honest answer of the same replica is served.
func TestAnAnswerOfAnotherContextIsRefused(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	digest := fake.ContextDigest("docs")
	for name, opts := range map[string][]Option{
		"pinned":   {WithProfileFingerprint("docs", fake.Fingerprint("docs")), WithContextDigestPin("docs", digest)},
		"unpinned": nil,
	} {
		c := dialFake(t, fake, false, opts...)
		if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
			t.Fatalf("%s: the honest answer: %v", name, err)
		}
		fake.SetMode(cipherontest.AnswerOtherContext)
		for op, call := range map[string]func() ([]byte, error){
			"Encrypt": func() ([]byte, error) { return c.Encrypt(ctx, "docs", []byte("p")) },
			"Sign": func() ([]byte, error) {
				s, err := c.Sign(ctx, "docs", []byte("d"))
				return s.Bytes, err
			},
			"EncryptBatch": func() ([]byte, error) {
				r, err := c.EncryptBatch(ctx, "docs", []BatchItem{{Data: []byte("p")}})
				if r != nil {
					return []byte("results"), err
				}
				return nil, err
			},
		} {
			out, err := call()
			if out != nil || !errors.Is(err, ErrServerIdentity) || !strings.Contains(err.Error(), "key context") {
				t.Errorf("%s, %s from a replica on another context: %q %v; want ErrServerIdentity, nothing returned", name, op,
					out, err)
			}
		}
		fake.SetMode(cipherontest.Honest)
		if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
			t.Fatalf("%s: the honest answer again: %v", name, err)
		}
	}
}

// TestAStaleContextFailsEveryCall (CL-1: TestProbeCLContextPinOnlyOnFetch turned around): a client pinned to D1
// encrypts; the replica moves to another key context D2 (a master version listed: the digest changes); a key fetch
// is ErrContextDigest — and so is the next Encrypt, whose answer is signed under D2, and a Verify, which answers from
// the cached list and must not use it once a fetch was refused. A replica back on D1 serves again.
func TestAStaleContextFailsEveryCall(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	d1 := fake.ContextDigest("docs")
	c := dialFake(t, fake, false, WithProfileFingerprint("docs", fake.Fingerprint("docs")), WithContextDigestPin("docs", d1))
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
	s := signedBy(t, c, "docs", []byte("d"))
	fake.ListVersion("docs", "v2") // another master version list: another key context
	if fake.ContextDigest("docs") == d1 {
		t.Fatal("the fake's context did not move")
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) || errors.Is(err, ErrServerIdentity) {
		t.Fatalf("Encrypt answered on another context, keys cached on the pinned one: %v; want ErrContextDigest", err)
	}
	// A fresh client, which has only the keys of D1 cached: its key fetch is refused, and from then on its cached keys
	// are not used — a Verify, which answers from the cached list, included.
	c = dialFake(t, fake, false, WithProfileFingerprint("docs", fake.Fingerprint("docs")), WithContextDigestPin("docs", d1))
	fake.RetireVersion("docs", "v2")
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	fake.ListVersion("docs", "v2")
	if _, err := c.Keys(ctx, "docs"); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("Keys: %v; want ErrContextDigest", err)
	}
	if ok, err := c.Verify(ctx, "docs", []byte("d"), s.Bytes, s.KeyID); ok || !errors.Is(err, ErrContextDigest) {
		t.Fatalf("Verify from the cached list after the refused fetch: %v, %v; want ErrContextDigest", ok, err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("Encrypt after the refused fetch: %v; want ErrContextDigest", err)
	}
	fake.RetireVersion("docs", "v2") // back on the pinned context
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("a replica on the pinned context again: %v", err)
	}
	if ok, err := c.Verify(ctx, "docs", []byte("d"), s.Bytes, s.KeyID); !ok || err != nil {
		t.Fatalf("Verify on the pinned context again: %v, %v", ok, err)
	}
}

// TestANarrowRefusesAnAnswerOfAContextSeenBefore (S3): a client pinned to the old and the new context saw both; the
// pins narrow to the new one; a replica that lags the change (here: it has not learnt a signing-key revocation) and
// answers under the old context is refused — ErrContextDigest, as the context is one the profile's keys gave — even
// though this client verified that context before, and the honest replica's answers keep being served.
func TestANarrowRefusesAnAnswerOfAContextSeenBefore(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	old := fake.ActiveKeyID("docs")
	fake.RotateSigning("docs") // the old key verify-only
	dOld := fake.ContextDigest("docs")
	fake.RevokeSigning("docs", old)
	dNew := fake.ContextDigest("docs")
	fake.UnrevokeSigning("docs", old)
	c := dialFake(t, fake, false, WithContextDigestPin("docs", dOld, dNew))
	if k, err := c.Keys(ctx, "docs"); err != nil || k.ContextDigest != dOld {
		t.Fatalf("the old context: %v", err)
	}
	fake.RevokeSigning("docs", old)
	if k, err := c.Keys(ctx, "docs"); err != nil || k.ContextDigest != dNew {
		t.Fatalf("the new context: %v", err)
	}
	p := c.pinsNow()
	c.pins.Store(&pinSet{fingerprints: p.fingerprints, context: map[string][]string{"docs": {dNew}}, writers: p.writers})
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("the narrowed pins, an honest answer: %v", err)
	}
	fake.SetMode(cipherontest.SignRevoked) // a replica that lags the revocation: its answers are signed under dOld
	if ct, err := c.Encrypt(ctx, "docs", []byte("p")); ct != nil || !errors.Is(err, ErrContextDigest) || !strings.Contains(err.Error(), dOld) {
		t.Fatalf("an answer of the old context after the narrow: %v; want ErrContextDigest naming it", err)
	}
	fake.SetMode(cipherontest.Honest)
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("the honest replica again: %v", err)
	}
}

// TestAnUnseenContextIsNeverRetried: an answer that verifies under no key context the client accepts — in a profile
// without a context pin, one no verified PublicKey answer gave, the key fetch it causes included — is ErrServerIdentity
// at once, with or without WithRetry and a context pin: it cannot be told from a party that is not the profile's
// cipheron, and an identity failure is never sent again (a replica a rollout brings in is accepted through the pins'
// widen, roll, narrow, or once a key fetch shows its context).
func TestAnUnseenContextIsNeverRetried(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	retries := 0
	observe := WithObserver(func(_, kind string) {
		if kind == KindRetry {
			retries++
			fake.SetMode(cipherontest.Honest) // a retry would reach a replica on a context the client knows
		}
	})
	policy := WithRetry(RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	for name, opts := range map[string][]Option{
		"unpinned, with retry":    {observe, policy},
		"unpinned, without retry": {observe},
		"pinned, with retry":      {observe, policy, WithContextDigestPin("docs", fake.ContextDigest("docs"))},
	} {
		c := dialFake(t, fake, false, opts...)
		if _, err := c.Keys(ctx, "docs"); err != nil {
			t.Fatal(err)
		}
		retries = 0
		fake.SetMode(cipherontest.AnswerOtherContext)
		ct, err := c.Encrypt(ctx, "docs", []byte("p"))
		fake.SetMode(cipherontest.Honest)
		if !errors.Is(err, ErrServerIdentity) || ct != nil || retries != 0 {
			t.Errorf("%s: %v (%d retries); want ErrServerIdentity and no retry", name, err, retries)
		}
	}
}

// TestAnUnpinnedClientFollowsTheProfilesContexts: without a context pin a context the profile's verified keys gave is
// accepted — a context change is learnt from the fetch the first answer under it causes — while one no PublicKey
// answer gave is not (TestAnAnswerOfAnotherContextIsRefused).
func TestAnUnpinnedClientFollowsTheProfilesContexts(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false)
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
	calls := fake.PublicKeyCalls()
	fake.ListVersion("docs", "v2")
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("an answer under the profile's new context: %v", err)
	}
	if fake.PublicKeyCalls()-calls != 1 {
		t.Fatalf("%d key fetches to learn the new context, want 1", fake.PublicKeyCalls()-calls)
	}
	fake.RetireVersion("docs", "v2") // a replica back on the older context: seen before, accepted without a fetch
	calls = fake.PublicKeyCalls()
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil || fake.PublicKeyCalls() != calls {
		t.Fatalf("an answer under a context seen before: %v (%d fetches)", err, fake.PublicKeyCalls()-calls)
	}
}

// TestKeysFetchedUnderOlderPinsAreCheckedAgain (CL-1, the live-pins stamping window): a fetch that began under pins
// {D1, D2} and stored D2's keys after the pins narrowed to {D1} — and after another call checked the keys cached then
// under the narrowed pins — is never taken as checked under them: the Keys call that made it is ErrContextDigest (what
// load returns is held to the pins in force when it returns), and the next call holds the stored keys to {D1}, fetches
// again, and is ErrContextDigest.
func TestKeysFetchedUnderOlderPinsAreCheckedAgain(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	d1 := fake.ContextDigest("docs")
	fake.ListVersion("docs", "v2")
	d2 := fake.ContextDigest("docs")
	fake.RetireVersion("docs", "v2")
	c := dialFake(t, fake, false, WithContextDigestPin("docs", d1, d2))
	if _, err := c.Keys(ctx, "docs"); err != nil { // D1's keys, checked under {D1, D2}
		t.Fatal(err)
	}
	wide := c.pinsNow()
	fake.ListVersion("docs", "v2") // the replica moves to D2
	release := fake.HoldPublicKey()
	fetched := make(chan error, 1)
	go func() {
		_, err := c.Keys(ctx, "docs") // begins under {D1, D2}, answers D2
		fetched <- err
	}()
	waitFor(t, func() bool { return fake.PublicKeyCalls() >= 2 })
	narrow := &pinSet{fingerprints: wide.fingerprints, context: map[string][]string{"docs": {d1}}, writers: wide.writers}
	c.pins.Store(narrow)
	if _, err := c.cached(ctx, "docs"); err != nil { // D1's keys, checked under the narrowed pins
		t.Fatalf("the keys cached on D1 under the narrowed pins: %v", err)
	}
	release()
	if err := <-fetched; !errors.Is(err, ErrContextDigest) || !strings.Contains(err.Error(), d2) {
		t.Fatalf("Keys, its fetch begun under the wide pins and answered D2 after the narrow: %v; want ErrContextDigest "+
			"naming D2", err)
	}
	if k, ok := c.cachedKeys("docs"); !ok || k.ContextDigest != d2 {
		t.Fatal("the fetch did not store D2's keys")
	}
	if _, err := c.cached(ctx, "docs"); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("D2's keys, stored by a fetch begun under the wide pins: %v; want ErrContextDigest", err)
	}
}

// TestAFetchBegunUnderOlderPinsIsCheckedForTheCallThatMadeIt (CL-1, the live-pins stamping window, the call that
// fetches): a call that finds no usable cached keys — none cached (cached), or the profile's marked refused after a
// fetch of an unpinned context (Verify) — fetches them; the fetch begins under pins {D1, D2} and its D2 answer arrives
// after the pins narrowed to {D1}. The call that made the fetch holds what it stored to the narrowed pins before using
// it: ErrContextDigest, nothing verified — never keys checked only under the pins it began under.
func TestAFetchBegunUnderOlderPinsIsCheckedForTheCallThatMadeIt(t *testing.T) {
	for _, name := range []string{"not cached, cached", "marked refused, Verify"} {
		t.Run(name, func(t *testing.T) {
			ctx := ctxT(t)
			fake := cipherontest.New(t, "docs")
			d1 := fake.ContextDigest("docs")
			fake.ListVersion("docs", "v2")
			d2 := fake.ContextDigest("docs")
			fake.RetireVersion("docs", "v2")
			c := dialFake(t, fake, false, WithContextDigestPin("docs", d1, d2))
			call := func() error {
				_, err := c.cached(ctx, "docs")
				return err
			}
			if name == "marked refused, Verify" {
				s := signedBy(t, c, "docs", []byte("d")) // D1's keys cached
				fake.ListVersion("docs", "v3")           // a context neither pin names
				if _, err := c.Keys(ctx, "docs"); !errors.Is(err, ErrContextDigest) || !c.contextRefused("docs") {
					t.Fatalf("a fetch of an unpinned context: %v (marked %v); want ErrContextDigest, the profile marked", err,
						c.contextRefused("docs"))
				}
				fake.RetireVersion("docs", "v3")
				call = func() error {
					ok, err := c.Verify(ctx, "docs", []byte("d"), s.Bytes, s.KeyID)
					if ok {
						return errors.New("the signature verified")
					}
					return err
				}
			}
			fake.ListVersion("docs", "v2") // the replica on D2
			if fake.ContextDigest("docs") != d2 {
				t.Fatal("the fake is not on D2")
			}
			calls := fake.PublicKeyCalls()
			release := fake.HoldPublicKey()
			done := make(chan error, 1)
			go func() { done <- call() }() // its fetch begins under {D1, D2}
			waitFor(t, func() bool { return fake.PublicKeyCalls() > calls })
			wide := c.pinsNow()
			c.pins.Store(&pinSet{fingerprints: wide.fingerprints, context: map[string][]string{"docs": {d1}}, writers: wide.writers})
			release()
			if err := <-done; !errors.Is(err, ErrContextDigest) || !strings.Contains(err.Error(), d2) {
				t.Fatalf("the call whose fetch stored D2's keys after the narrow: %v; want ErrContextDigest naming D2", err)
			}
		})
	}
}

// waitFor polls ok until it holds (or the test's context ends).
func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	ctx := ctxT(t)
	for !ok() {
		select {
		case <-ctx.Done():
			t.Fatal("timed out")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestKeysHonourAFingerprintPinAddedForACachedProfile (CL-8): a profile trusted on first use and cached; a fingerprint
// pin added live (the pins directory) that its identity does not match: Keys and KeyStatement are ErrServerIdentity,
// as Encrypt is.
func TestKeysHonourAFingerprintPinAddedForACachedProfile(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs", "other")
	c := dialFake(t, fake, false)
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	p := c.pinsNow()
	c.pins.Store(&pinSet{fingerprints: map[string]string{"docs": fake.Fingerprint("other")}, context: p.context,
		writers: p.writers})
	if _, err := c.Keys(ctx, "docs"); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("Keys: %v; want ErrServerIdentity", err)
	}
	if _, err := c.KeyStatement(ctx, "docs"); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("KeyStatement: %v; want ErrServerIdentity", err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("Encrypt: %v; want ErrServerIdentity", err)
	}
}

// TestTheWriterPinHoldsNewData (S3, the writer): with WithWriterVersionPin, an answer whose new ciphertext — Encrypt,
// ReEncrypt, EncryptBatch, an object's segments — or tenant key blob — CreateTenantKey, RewrapTenantKey,
// RewrapTenantKeyBatch — is made under a master version the pin does not name is ErrContextDigest, nothing returned;
// under a pinned one it is served; a read of any listed version is not held to it. A widen, a switch and a narrow move
// the pin with the writer.
func TestTheWriterPinHoldsNewData(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs", "files")
	fake.MakePerTenant("files")
	c := dialFake(t, fake, false, WithWriterVersionPin("docs", "v1"), WithWriterVersionPin("files", "v1"))
	old, err := c.Encrypt(ctx, "docs", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := c.CreateTenantKey(ctx, "files", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	// A rewrap under the pinned version is served (the blobs below are refused for the writer's version alone).
	if _, err := c.RewrapTenantKey(ctx, "files", "t_1", blob.Blob); err != nil {
		t.Fatalf("RewrapTenantKey under the pinned writer: %v", err)
	}
	if rs, err := c.RewrapTenantKeyBatch(ctx, "files", []TenantKeyRef{{Tenant: "t_1", Blob: blob.Blob}}); err != nil ||
		len(rs) != 1 || rs[0].Err != nil {
		t.Fatalf("RewrapTenantKeyBatch under the pinned writer: %v %v", rs, err)
	}
	fake.SetWriteVersion("docs", "v2") // a replica that writes under a version the pin does not name
	fake.SetWriteVersion("files", "v2")
	refused := func(what string, out any, err error) {
		t.Helper()
		if !errors.Is(err, ErrContextDigest) || !strings.Contains(err.Error(), `"v2"`) {
			t.Errorf("%s under an unpinned writer: %v %v; want ErrContextDigest naming the version", what, out, err)
		}
	}
	ct, err := c.Encrypt(ctx, "docs", []byte("p"))
	refused("Encrypt", ct, err)
	ct, err = c.ReEncrypt(ctx, "docs", old)
	refused("ReEncrypt", ct, err)
	rs, err := c.EncryptBatch(ctx, "docs", []BatchItem{{Data: []byte("p")}})
	refused("EncryptBatch", rs, err)
	obj, err := c.EncryptObject(ctx, "docs", []byte("an object"))
	refused("EncryptObject", obj, err)
	tk, err := c.CreateTenantKey(ctx, "files", "t_2")
	refused("CreateTenantKey", tk, err)
	rw, err := c.RewrapTenantKey(ctx, "files", "t_1", blob.Blob)
	refused("RewrapTenantKey", rw, err)
	rws, err := c.RewrapTenantKeyBatch(ctx, "files", []TenantKeyRef{{Tenant: "t_1", Blob: blob.Blob}})
	refused("RewrapTenantKeyBatch", rws, err)
	if ct != nil || rs != nil || obj != nil || tk != nil || rw != nil || rws != nil {
		t.Fatal("an answer under an unpinned writer was returned")
	}
	if pt, err := c.Decrypt(ctx, "docs", old); err != nil || string(pt) != "p" {
		t.Fatalf("a read is not held to the writer pin: %q %v", pt, err)
	}
	// The pin widened to both, then the writer switched: served.
	w := dialFake(t, fake, false, WithWriterVersionPin("docs", "v1", "v2"))
	if ct, err := w.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("a widened writer pin: %v", err)
	} else if k, _ := transport.ParseKeyID(transport.Release(), ct); k.MasterVersion != "v2" {
		t.Fatalf("the new ciphertext's version: %q", k.MasterVersion)
	}
	// No writer pin: any version.
	if _, err := dialFake(t, fake, false).Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("no writer pin: %v", err)
	}
}

// TestWithWriterVersionPinRefusesWhatIsNotAVersion: the option's own refusals, and the joining of two lists.
func TestWithWriterVersionPinRefusesWhatIsNotAVersion(t *testing.T) {
	for name, opt := range map[string]Option{
		"no profile":    WithWriterVersionPin("", "v1"),
		"no version":    WithWriterVersionPin("docs"),
		"not a version": WithWriterVersionPin("docs", "v 1"),
		"too many versions": func(o *options) {
			for i := range MaxWriterVersionPins + 1 {
				WithWriterVersionPin("docs", "v"+string(rune('a'+i)))(o)
			}
		},
	} {
		var o options
		opt(&o)
		if len(o.errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	var o options
	WithWriterVersionPin("docs", "v1")(&o)
	WithWriterVersionPin("docs", "v2", "v1")(&o)
	if len(o.errs) != 0 || strings.Join(o.writerPins["docs"], ",") != "v1,v2" {
		t.Fatalf("joined: %v %v", o.writerPins, o.errs)
	}
}
