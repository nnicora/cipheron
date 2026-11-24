//go:build linux || darwin

package client

// review5_test.go — the regression tests of the client review's findings: Verify tells a key it does not know from
// a signature that does not verify (B); Close is idempotent, refuses calls, and never lets a request be signed
// with a wiped key (C); options (D); the pins directory is read whole or not at all (E); no redirect is followed
// (F); TLS 1.3 unless the caller says otherwise (G); the reconnect hurry is bounded (H); HTTP statuses (J); the
// HTTP pool and the gRPC dial parameters (N, O).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// longAgo makes the Client's last fetch of profile's keys (or last Verify attempt) long past: the next Verify
// naming an unknown key id may fetch.
func longAgo(t *testing.T, c *Client, profile string) {
	t.Helper()
	v, ok := c.fetched.Load(profile)
	if !ok {
		t.Fatal("the profile's keys were never fetched")
	}
	stamp, ok := v.(*atomic.Pointer[time.Time])
	if !ok {
		t.Fatalf("the profile's fetch stamp: got %T", v)
	}
	stamp.Store(new(time.Time))
}

// TestVerifyTellsAnUnknownKeyFromAForgedSignature (finding B): Verify answers (false, nil) only for a key it knows
// under which the signature does not verify. A key id it does not know is ErrUnknownSigningKey — while the list
// may not be fetched again (a genuine signature just after a rotation is then NOT reported as false), when the
// fetch fails (the error carries the fetch's too), and when a list fetched now does not name it — and a later
// Verify of the same genuine signature succeeds.
func TestVerifyTellsAnUnknownKeyFromAForgedSignature(t *testing.T) {
	const profile = "credentials"
	s, _, _ := newKeysServer(t, profile)
	s.id.Tenancy = transport.TenancyShared
	pub1, priv1 := keyPair(t)
	pub2, priv2 := keyPair(t)
	id1, id2 := transport.SigningKeyID(pub1), transport.SigningKeyID(pub2)
	s.set(t, pub1, []ed25519.PublicKey{pub1})
	c := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20})
	ctx := context.Background()
	if _, err := c.Keys(ctx, profile); err != nil {
		t.Fatal(err)
	}
	doc := []byte("invoice #42")
	sig1 := ed25519.Sign(priv1, doc)

	// A key the Client knows: true, or false with no error.
	if ok, err := c.Verify(ctx, profile, doc, sig1, id1); !ok || err != nil {
		t.Fatalf("a genuine signature under a known key: %v, %v", ok, err)
	}
	for name, v := range map[string]struct{ data, sig []byte }{
		"another document":      {[]byte("invoice #43"), sig1},
		"another key's":         {doc, ed25519.Sign(priv2, doc)},
		"a truncated signature": {doc, sig1[:63]},
	} {
		if ok, err := c.Verify(ctx, profile, v.data, v.sig, id1); ok || err != nil {
			t.Fatalf("%s under a known key: %v, %v; want false, nil", name, ok, err)
		}
	}

	// A signing rotation the Client has not learnt: the genuine signature under the new key is not "false".
	s.set(t, pub2, []ed25519.PublicKey{pub1, pub2})
	sig2 := ed25519.Sign(priv2, doc)
	calls := s.calls.Load()
	ok, err := c.Verify(ctx, profile, doc, sig2, id2)
	if ok || !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("a genuine signature under a key not learnt yet, the list just fetched: %v, %v; want ErrUnknownSigningKey", ok, err)
	}
	if !strings.Contains(err.Error(), hex.EncodeToString(id2)) || !strings.Contains(err.Error(), profile) {
		t.Errorf("the error does not name the key id and the profile: %v", err)
	}
	if n := s.calls.Load() - calls; n != 0 {
		t.Fatalf("the suppressed refresh made %d PublicKey calls", n)
	}
	// Once the list may be fetched again, the same signature verifies.
	longAgo(t, c, profile)
	if ok, err := c.Verify(ctx, profile, doc, sig2, id2); !ok || err != nil {
		t.Fatalf("the same signature once the list was fetched again: %v, %v", ok, err)
	}
	if n := s.calls.Load() - calls; n != 1 {
		t.Fatalf("learning the rotation made %d PublicKey calls, want 1", n)
	}
	// And the old key's signatures still verify.
	if ok, err := c.Verify(ctx, profile, doc, sig1, id1); !ok || err != nil {
		t.Fatalf("the old key's signature after the rotation: %v, %v", ok, err)
	}

	// A key id no list names, after a fresh fetch that completed: ErrUnknownSigningKey too (the owner's choice),
	// with no other error under it.
	stranger := make([]byte, transport.SigningKeyIDLen)
	longAgo(t, c, profile)
	calls = s.calls.Load()
	ok, err = c.Verify(ctx, profile, doc, sig1, stranger)
	if ok || !errors.Is(err, ErrUnknownSigningKey) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a key id a fresh list does not name: %v, %v", ok, err)
	}
	if n := s.calls.Load() - calls; n != 1 {
		t.Fatalf("a fresh fetch for an unknown key id: %d PublicKey calls, want 1", n)
	}

	// The fetch fails: ErrUnknownSigningKey, and the fetch's error.
	longAgo(t, c, profile)
	s.fail.Store(true)
	ok, err = c.Verify(ctx, profile, doc, sig1, stranger)
	if ok || !errors.Is(err, ErrUnknownSigningKey) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a refresh that failed: %v, %v; want ErrUnknownSigningKey and the fetch's error", ok, err)
	}
	s.fail.Store(false)

	// A key id that is not one: no fetch, however long ago the last one.
	longAgo(t, c, profile)
	calls = s.calls.Load()
	for _, id := range [][]byte{nil, {}, id1[:15], append(append([]byte(nil), id1...), 0)} {
		if ok, err := c.Verify(ctx, profile, doc, sig1, id); ok || !errors.Is(err, ErrUnknownSigningKey) {
			t.Fatalf("a %d-byte key id: %v, %v", len(id), ok, err)
		}
	}
	if n := s.calls.Load() - calls; n != 0 {
		t.Fatalf("malformed key ids made %d PublicKey calls", n)
	}

	// A Client whose first call in the profile is the Verify (what a one-shot verifier is): the list it fetched for
	// that call is as new as a refresh would make it, so the answer is "it does not name it" — one fetch, and no
	// "try again", which would be wrong.
	one := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20})
	calls = s.calls.Load()
	ok, err = one.Verify(ctx, profile, doc, sig1, stranger)
	if ok || !errors.Is(err, ErrUnknownSigningKey) || strings.Contains(err.Error(), "try again") ||
		!strings.Contains(err.Error(), "fetched now") {
		t.Fatalf("a fresh Client's Verify of an unknown key id: %v, %v", ok, err)
	}
	if n := s.calls.Load() - calls; n != 1 {
		t.Fatalf("a fresh Client's Verify of an unknown key id made %d PublicKey calls, want 1", n)
	}
	// Its next one, moments later, is the suppressed case: the list is no longer this call's.
	if _, err := one.Verify(ctx, profile, doc, sig1, stranger); !errors.Is(err, ErrUnknownSigningKey) || !strings.Contains(err.Error(), "try again") {
		t.Fatalf("the same Client's second Verify: %v", err)
	}
	if ok, err := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20}).Verify(ctx, profile, doc, sig2, id2); !ok || err != nil {
		t.Fatalf("a fresh Client's Verify of a genuine signature: %v, %v", ok, err)
	}

	// The flood protection holds: many callers with garbage key ids at once cost one fetch, not one each.
	longAgo(t, c, profile)
	calls = s.calls.Load()
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := make([]byte, transport.SigningKeyIDLen)
			_, _ = rand.Read(id)
			if ok, err := c.Verify(ctx, profile, doc, sig1, id); ok || !errors.Is(err, ErrUnknownSigningKey) {
				t.Errorf("a garbage key id: %v, %v", ok, err)
			}
		}()
	}
	wg.Wait()
	if n := s.calls.Load() - calls; n != 1 {
		t.Fatalf("64 concurrent Verifies of garbage key ids made %d PublicKey calls, want 1", n)
	}
}

// TestATenantsVerify (finding B): a derived profile's tenant verifies under the profile's list, so a key id it
// cannot resolve is ErrUnknownSigningKey as for the Client's own Verify — and the signature is the tenant's only
// over the tenant-bound message.
func TestATenantsVerify(t *testing.T) {
	const profile = "profiles"
	s, _, _ := newKeysServer(t, profile) // a derived profile
	pub, priv := keyPair(t)
	s.set(t, pub, []ed25519.PublicKey{pub})
	c := newClient([]rpc{s}, newIdentityState(), &plan{maxMessage: 1 << 20})
	ctx := context.Background()
	acme, globex := c.Tenant(profile, "t_acme", nil), c.Tenant(profile, "t_globex", nil)
	doc := []byte("consent v3")
	sig := ed25519.Sign(priv, transport.TenantSignedMessage(profile, "t_acme", doc))
	id := transport.SigningKeyID(pub)
	if ok, err := acme.Verify(ctx, doc, sig, id); !ok || err != nil {
		t.Fatalf("the tenant's signature: %v, %v", ok, err)
	}
	if ok, err := globex.Verify(ctx, doc, sig, id); ok || err != nil {
		t.Fatalf("another tenant's signature under a known key: %v, %v; want false, nil", ok, err)
	}
	calls := s.calls.Load()
	if ok, err := acme.Verify(ctx, doc, sig, make([]byte, transport.SigningKeyIDLen)); ok || !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("a key id the list does not name: %v, %v; want ErrUnknownSigningKey", ok, err)
	}
	if !strings.Contains(fmt.Sprint(func() error {
		_, err := acme.Verify(ctx, doc, sig, make([]byte, transport.SigningKeyIDLen))
		return err
	}()), "t_acme") {
		t.Error("the error does not name the tenant")
	}
	if n := s.calls.Load() - calls; n != 0 {
		t.Fatalf("%d PublicKey calls for an unknown key id right after a fetch", n)
	}
}

// closeCase is a Client of a fake that requires request signatures, over one transport.
type closeCase struct {
	name string
	dial func(t *testing.T, fake *cipherontest.Server, key ed25519.PrivateKey) *Client
}

func closeCases() []closeCase {
	const profile = "credentials"
	opts := func(fake *cipherontest.Server, key ed25519.PrivateKey) []Option {
		return []Option{WithServerUID(uint32(os.Getuid())), WithRequestKey(key), WithProfileFingerprint(profile, fake.Fingerprint(profile))}
	}
	return []closeCase{
		{"gRPC", func(t *testing.T, fake *cipherontest.Server, key ed25519.PrivateKey) *Client {
			t.Helper()
			c, err := DialGRPC(fake.ServeSocket(t), opts(fake, key)...)
			if err != nil {
				t.Fatal(err)
			}
			return c
		}},
		{"HTTP", func(t *testing.T, fake *cipherontest.Server, key ed25519.PrivateKey) *Client {
			t.Helper()
			c, err := DialHTTP(fake.ServeHTTPSocket(t), opts(fake, key)...)
			if err != nil {
				t.Fatal(err)
			}
			return c
		}},
	}
}

// TestCloseRefusesCallsAndIsIdempotent (finding C): after Close every call answers ErrClosed — not an error
// wrapping context.Canceled — and sends nothing, over gRPC and over HTTP (never a call signed with the wiped key); a
// second Close returns nil; the key is wiped.
func TestCloseRefusesCallsAndIsIdempotent(t *testing.T) {
	const profile = "credentials"
	for _, tc := range closeCases() {
		t.Run(tc.name, func(t *testing.T) {
			fake := cipherontest.New(t, profile)
			pub, key := keyPair(t)
			fake.RequireRequestKey(profile, pub)
			c := tc.dial(t, fake, key)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ct, err := c.Encrypt(ctx, profile, []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := c.Sign(ctx, profile, []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := c.Close(); err != nil {
				t.Fatalf("a second Close: %v", err)
			}
			for i, b := range c.requestKey {
				if b != 0 {
					t.Fatalf("the request key is not wiped (byte %d)", i)
				}
			}
			if !bytesNonZero(key) {
				t.Fatal("Close wiped the caller's key, not the Client's copy")
			}
			verified, absent, refused := fake.Auth()
			keyCalls := fake.PublicKeyCalls()
			tenant := c.Tenant(profile, "t_1", nil)
			calls := map[string]func() error{
				"Encrypt":         func() error { _, err := c.Encrypt(ctx, profile, []byte("x")); return err },
				"Decrypt":         func() error { _, err := c.Decrypt(ctx, profile, ct); return err },
				"ReEncrypt":       func() error { _, err := c.ReEncrypt(ctx, profile, ct); return err },
				"Sign":            func() error { _, err := c.Sign(ctx, profile, []byte("x")); return err },
				"Verify":          func() error { _, err := c.Verify(ctx, profile, []byte("x"), sig.Bytes, sig.KeyID); return err },
				"Keys":            func() error { _, err := c.Keys(ctx, profile); return err },
				"Keys, uncached":  func() error { _, err := c.Keys(ctx, "other"); return err },
				"CreateTenantKey": func() error { _, err := c.CreateTenantKey(ctx, profile, "t_1"); return err },
				"RewrapTenantKey": func() error { _, err := c.RewrapTenantKey(ctx, profile, "t_1", []byte("blob")); return err },
				"Tenant.Encrypt":  func() error { _, err := tenant.Encrypt(ctx, []byte("x")); return err },
				"Tenant.Decrypt":  func() error { _, err := tenant.Decrypt(ctx, ct); return err },
				"Tenant.ReEncrypt": func() error {
					_, err := tenant.ReEncrypt(ctx, ct, nil)
					return err
				},
				"Tenant.Sign":   func() error { _, err := tenant.Sign(ctx, []byte("x")); return err },
				"Tenant.Verify": func() error { _, err := tenant.Verify(ctx, []byte("x"), sig.Bytes, sig.KeyID); return err },
			}
			for name, call := range calls {
				err := call()
				if !errors.Is(err, ErrClosed) {
					t.Errorf("%s after Close: %v; want ErrClosed", name, err)
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("%s after Close reads as the caller's context: %v", name, err)
				}
			}
			if v, a, r := fake.Auth(); v != verified || a != absent || r != refused || fake.PublicKeyCalls() != keyCalls {
				t.Fatalf("a call after Close reached cipheron: auth verified %d→%d, absent %d→%d, refused %d→%d, PublicKey %d→%d",
					verified, v, absent, a, refused, r, keyCalls, fake.PublicKeyCalls())
			}
		})
	}
}

func bytesNonZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return true
		}
	}
	return false
}

// TestCloseEndsACallInFlightWithErrClosed (finding C): a call Close cuts short answers ErrClosed, not a
// cancellation that reads as the caller's own.
func TestCloseEndsACallInFlightWithErrClosed(t *testing.T) {
	const profile = "credentials"
	fake := cipherontest.New(t, profile)
	release := fake.HoldPublicKey()
	defer release()
	c, err := DialGRPC(fake.ServeSocket(t), WithServerUID(uint32(os.Getuid())))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.Encrypt(ctx, profile, []byte("x"))
		done <- err
	}()
	for deadline := time.Now().Add(10 * time.Second); fake.PublicKeyCalls() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the call never reached the fake")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) || errors.Is(err, context.Canceled) {
			t.Fatalf("a call Close cut short: %v; want ErrClosed", err)
		}
		if status.Code(err) != codes.Canceled {
			t.Errorf("what gRPC answered is not kept under ErrClosed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not end the call in flight")
	}
}

// TestCloseConcurrentWithCallsNeverSignsWithAWipedKey (finding C; run it with -race): Close while calls are
// signing and sending — two Closes at once. No request ever reaches cipheron with a signature that does not
// verify (which is what a request signed with a zeroed key is), every call that fails fails with ErrClosed, and
// the race detector sees the key read and wiped under one lock.
func TestCloseConcurrentWithCallsNeverSignsWithAWipedKey(t *testing.T) {
	const profile = "credentials"
	rounds := 12
	if testing.Short() {
		rounds = 3
	}
	for _, tc := range closeCases() {
		t.Run(tc.name, func(t *testing.T) {
			for round := range rounds {
				fake := cipherontest.New(t, profile)
				pub, key := keyPair(t)
				fake.RequireRequestKey(profile, pub)
				c := tc.dial(t, fake, key)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if _, err := c.Encrypt(ctx, profile, []byte("warm")); err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				var served atomic.Int64
				errs := make(chan error, 16)
				for range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for {
							if _, err := c.Encrypt(ctx, profile, []byte("x")); err != nil {
								errs <- err
								return
							}
							served.Add(1)
						}
					}()
				}
				time.Sleep(time.Duration(1+round%5) * time.Millisecond)
				var closers sync.WaitGroup
				for range 2 {
					closers.Add(1)
					go func() {
						defer closers.Done()
						if err := c.Close(); err != nil {
							t.Errorf("Close: %v", err)
						}
					}()
				}
				closers.Wait()
				wg.Wait()
				cancel()
				close(errs)
				for err := range errs {
					if !errors.Is(err, ErrClosed) {
						t.Fatalf("round %d: a call concurrent with Close failed with %v; want ErrClosed", round, err)
					}
				}
				if _, _, refused := fake.Auth(); refused != 0 {
					t.Fatalf("round %d: %d requests reached cipheron with a signature that does not verify "+
						"(signed with a wiped key?), after %d served", round, refused, served.Load())
				}
				// And afterwards nothing goes out. A call Close cut short answered ErrClosed at once, but its request,
				// signed before the wipe, may still be in the in-process server's handler: wait until the server's
				// count settles before taking the baseline, or that late arrival reads as a call made after Close.
				verified, _, _ := fake.Auth()
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
					time.Sleep(20 * time.Millisecond)
					v, _, _ := fake.Auth()
					if v == verified {
						break
					}
					verified = v
				}
				if _, err := c.Encrypt(ctx, profile, []byte("x")); !errors.Is(err, ErrClosed) {
					t.Fatalf("round %d: after Close: %v", round, err)
				}
				if v, _, r := fake.Auth(); v != verified || r != 0 {
					t.Fatalf("round %d: a call after Close reached cipheron", round)
				}
			}
		})
	}
}

// TestOptions (finding D): a nil Option is skipped; WithRequestKey copies the key when the option is made, and
// each client holds its own copy; a second, different answer to one question is refused, and an equal one is not.
func TestOptions(t *testing.T) {
	const profile = "credentials"
	fake := cipherontest.New(t, profile)
	pub, key := keyPair(t)
	fake.RequireRequestKey(profile, pub)
	sock := fake.ServeSocket(t)
	uid := uint32(os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// nil options, anywhere in the list.
	c, err := DialGRPC(sock, nil, WithServerUID(uid), nil, WithRequestKey(key), nil)
	if err != nil {
		t.Fatalf("nil options: %v", err)
	}
	if _, err := c.Encrypt(ctx, profile, []byte("x")); err != nil {
		t.Fatalf("a client made with nil options: %v", err)
	}
	_ = c.Close()
	if _, err := DialHTTP(sock, nil, WithAnyServer()); err != nil {
		t.Fatalf("nil options over HTTP: %v", err)
	}
	if _, err := resolve(sock, nil); err == nil {
		t.Fatal("no option at all is still refused for a socket (WithServerUID or WithAnyServer)")
	}

	// The key is copied when the option is made: the caller wipes its slice before the client exists.
	mine := append(ed25519.PrivateKey(nil), key...)
	opt := WithRequestKey(mine)
	for i := range mine {
		mine[i] = 0
	}
	first, err := DialGRPC(sock, WithServerUID(uid), opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Encrypt(ctx, profile, []byte("x")); err != nil {
		t.Fatalf("a key wiped by its owner after WithRequestKey returned: %v", err)
	}
	// The option makes a second client, and closing the first does not wipe the second's key (nor the option's).
	second, err := DialGRPC(sock, WithServerUID(uid), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Encrypt(ctx, profile, []byte("x")); err != nil {
		t.Fatalf("the second client of one option, after the first closed: %v", err)
	}
	third, err := DialGRPC(sock, WithServerUID(uid), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
	if _, err := third.Encrypt(ctx, profile, []byte("x")); err != nil {
		t.Fatalf("a client made from the option after another of its clients closed: %v", err)
	}
	if _, _, refused := fake.Auth(); refused != 0 {
		t.Fatalf("%d requests were signed with a key that is not the caller's", refused)
	}

	// Two answers to one question.
	_, other := keyPair(t)
	dir := t.TempDir()
	ca := cipherontest.NewCA(t, "ca")
	leaf := ca.Client(t, "spiffe://prod.example.org/app")
	cert := cipherontest.Write(t, dir, "c.crt", leaf.ChainPEM, 0o644)
	keyFile := cipherontest.Write(t, dir, "c.key", leaf.KeyPEM, 0o600)
	caFile := cipherontest.Write(t, dir, "ca.pem", ca.PEM, 0o644)
	_, reqFile := cipherontest.RequestKey(t, dir, "request.key")
	const network = "cipheron.prod.svc:8443"
	const idA, idB = "spiffe://prod.example.org/cipheron", "spiffe://prod.example.org/other"
	for name, tc := range map[string]struct {
		where string
		opts  []Option
		want  string // "" = accepted
	}{
		"two server uids":             {sock, []Option{WithServerUID(uid), WithServerUID(uid + 1)}, "WithServerUID"},
		"two server uids, reversed":   {sock, []Option{WithServerUID(uid + 1), WithServerUID(uid)}, "WithServerUID"},
		"the same server uid twice":   {sock, []Option{WithServerUID(uid), WithServerUID(uid)}, ""},
		"two request keys":            {sock, []Option{WithServerUID(uid), WithRequestKey(key), WithRequestKey(other)}, "WithRequestKey"},
		"the same request key twice":  {sock, []Option{WithServerUID(uid), WithRequestKey(key), WithRequestKey(append(ed25519.PrivateKey(nil), key...))}, ""},
		"two request key files":       {sock, []Option{WithServerUID(uid), WithRequestKeyFile(reqFile), WithRequestKeyFile(reqFile + "2")}, "WithRequestKeyFile"},
		"the same key file twice":     {sock, []Option{WithServerUID(uid), WithRequestKeyFile(reqFile), WithRequestKeyFile(filepath.Dir(reqFile) + "/./request.key")}, ""},
		"two server SPIFFE IDs":       {network, []Option{WithTLSFiles(cert, keyFile, caFile), WithRequestKey(key), WithServerSPIFFEID(idA), WithServerSPIFFEID(idB)}, "WithServerSPIFFEID"},
		"a SPIFFE ID, then none":      {network, []Option{WithTLSFiles(cert, keyFile, caFile), WithRequestKey(key), WithServerSPIFFEID(idA), WithServerSPIFFEID("")}, "WithServerSPIFFEID"},
		"the same SPIFFE ID twice":    {network, []Option{WithTLSFiles(cert, keyFile, caFile), WithRequestKey(key), WithServerSPIFFEID(idA), WithServerSPIFFEID(idA)}, ""},
		"two sets of TLS files":       {network, []Option{WithTLSFiles(cert, keyFile, caFile), WithTLSFiles(cert, keyFile, caFile+"2"), WithRequestKey(key)}, "WithTLSFiles"},
		"another certificate file":    {network, []Option{WithTLSFiles(cert, keyFile, caFile), WithTLSFiles(cert+"2", keyFile, caFile), WithRequestKey(key)}, "WithTLSFiles"},
		"the same TLS files twice":    {network, []Option{WithTLSFiles(cert, keyFile, caFile), WithTLSFiles(cert, keyFile, caFile), WithRequestKey(key)}, ""},
		"a wrong-sized key, and nil":  {sock, []Option{nil, WithServerUID(uid), WithRequestKey(key[:31])}, "not 31"},
		"two fingerprints (as ever)":  {sock, []Option{WithServerUID(uid), WithProfileFingerprint(profile, fpA), WithProfileFingerprint(profile, fpB)}, "two fingerprints"},
		"the same fingerprint twice":  {sock, []Option{WithServerUID(uid), WithProfileFingerprint(profile, fpA), WithProfileFingerprint(profile, fpA)}, ""},
		"a key and a key file":        {sock, []Option{WithServerUID(uid), WithRequestKey(key), WithRequestKeyFile(reqFile)}, "one question"},
		"WithAnyServer, no pin (dev)": {sock, []Option{WithAnyServer()}, ""},
	} {
		p, err := resolve(tc.where, tc.opts)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && err == nil:
			t.Errorf("%s: accepted (%+v)", name, p.endpoint)
		case tc.want != "" && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: %v; want an error naming %q", name, err, tc.want)
		}
	}
}

// TestThePinsDirectoryIsReadWholeOrNotAtAll (finding E): an error reading the pins directory — with no names, or
// after some of them — fails the client; it is never taken as "no more pins", which would leave the profiles of the
// unread files trusted on first use.
func TestThePinsDirectoryIsReadWholeOrNotAtAll(t *testing.T) {
	newSidecarEnv(t, map[string]string{"credentials" + PinFingerprintSuffix: fpA + "\n", "invoices" + PinFingerprintSuffix: fpB + "\n"})
	if p, err := resolve("", []Option{WithEnvironment()}); err != nil || len(p.pins) != 2 {
		t.Fatalf("the directory as it is: %v", err)
	}
	origRead := readDirNames
	defer func() { readDirNames = origRead }()
	boom := errors.New("input/output error")
	// A read error is refused whatever else pins what: with a pin by option and WithRequiredPins too.
	readDirNames = func(string, int) ([]string, error) { return nil, boom }
	if _, err := resolve("", []Option{WithEnvironment(), WithRequiredPins(), WithProfileFingerprint("credentials", fpA)}); !errors.Is(err, boom) {
		t.Fatalf("a read error beside a pin by option: %v; want the read's error", err)
	}
	for name, read := range map[string]func(string, int) ([]string, error){
		"an error and no names": func(string, int) ([]string, error) { return nil, boom },
		"an error after some names": func(dir string, n int) ([]string, error) {
			names, err := origRead(dir, n)
			if err != nil || len(names) < 2 {
				t.Fatalf("the real read: %v %v", names, err)
			}
			return names[:1], boom // what os.File.Readdirnames answers for a read that failed midway
		},
	} {
		readDirNames = read
		p, err := resolve("", []Option{WithEnvironment()})
		if !errors.Is(err, boom) {
			t.Fatalf("%s: %+v, %v; want the read's error", name, p, err)
		}
		if !strings.Contains(err.Error(), EnvPinsDir) {
			t.Errorf("%s: the error does not name %s: %v", name, EnvPinsDir, err)
		}
	}
	readDirNames = origRead

	// The reader itself: every entry of a directory, none of an empty one, and an error — not an empty list — for
	// one that cannot be opened or holds more than it was asked for is the caller's to count.
	dir := t.TempDir()
	if names, err := readDirNames(dir, 10); err != nil || names != nil {
		t.Fatalf("an empty directory: %v, %v; want none, nil", names, err)
	}
	for _, n := range []string{"a", "b", "c"} {
		writeFile(t, filepath.Join(dir, n), "x", 0o644)
	}
	if names, err := readDirNames(dir, 10); err != nil || len(names) != 3 {
		t.Fatalf("three entries: %v, %v", names, err)
	}
	if names, err := readDirNames(dir, 2); err != nil || len(names) != 2 {
		t.Fatalf("three entries, two asked for: %v, %v", names, err)
	}
	if names, err := readDirNames(filepath.Join(dir, "missing"), 10); err == nil || names != nil {
		t.Fatalf("a directory that does not exist: %v, %v", names, err)
	}
	file := filepath.Join(dir, "a")
	if names, err := readDirNames(file, 10); err == nil || errors.Is(err, io.EOF) || names != nil {
		t.Fatalf("a file read as a directory: %v, %v; want an error that is not io.EOF", names, err)
	}
}

// TestAnEmptyPinsDirectory (finding E): a pins directory that is set and holds no fingerprint pins nothing. Without
// WithRequiredPins that is accepted, as before (every profile trusted on first use). With it, the client is refused
// when it is made only when nothing pins any profile — then every call would fail, and New says so with the same
// ErrPinRequired; a pin given by an option makes the configuration valid, and the profiles it does not pin are refused
// at their first call, before anything is sent. A directory of context digests only is as empty.
func TestAnEmptyPinsDirectory(t *testing.T) {
	for name, pins := range map[string]map[string]string{
		"no file at all":       {},
		"context digests only": {"credentials" + PinContextDigestSuffix: fpA + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			newSidecarEnv(t, pins)
			// In production (CIPHERON_ENVIRONMENT unset) WithRequiredPins is implied: refused as below.
			if _, err := resolve("", []Option{WithEnvironment()}); !errors.Is(err, ErrPinRequired) {
				t.Fatalf("production, no WithRequiredPins, no pin at all: %v; want ErrPinRequired", err)
			}
			t.Setenv(EnvEnvironment, DevelopmentEnvironment)
			p, err := resolve("", []Option{WithEnvironment()})
			if err != nil || len(p.pins) != 0 || p.requirePins {
				t.Fatalf("development, without WithRequiredPins: %+v, %v; want a client with no pin", p, err)
			}
			_, err = resolve("", []Option{WithEnvironment(), WithRequiredPins()})
			if !errors.Is(err, ErrPinRequired) || !errors.Is(err, ErrServerIdentity) || !strings.Contains(err.Error(), EnvPinsDir) {
				t.Fatalf("with WithRequiredPins and no pin at all: %v; want ErrPinRequired naming %s", err, EnvPinsDir)
			}
			// A pin given by an option, before or after WithEnvironment: a valid configuration.
			for _, opts := range [][]Option{
				{WithEnvironment(), WithRequiredPins(), WithProfileFingerprint("credentials", fpA)},
				{WithProfileFingerprint("credentials", fpA), WithRequiredPins(), WithEnvironment()},
			} {
				p, err := resolve("", opts)
				if err != nil || p.pins["credentials"] != fpA || !p.requirePins {
					t.Fatalf("an empty pins directory, WithRequiredPins and a pin by option: %v", err)
				}
			}
		})
	}
	// One fingerprint is enough for the directory not to be empty; and no pins directory at all is not an empty one.
	newSidecarEnv(t, map[string]string{"credentials" + PinFingerprintSuffix: fpA + "\n"})
	if _, err := resolve("", []Option{WithEnvironment(), WithRequiredPins()}); err != nil {
		t.Fatalf("a directory with a fingerprint, WithRequiredPins: %v", err)
	}
	unsetenv(t, EnvPinsDir)
	if _, err := resolve("", []Option{WithEnvironment(), WithRequiredPins()}); !errors.Is(err, ErrPinRequired) {
		t.Fatalf("no pins directory in production: %v; want ErrPinRequired (D17: never a silent fallback)", err)
	}
	t.Setenv(EnvEnvironment, DevelopmentEnvironment)
	if _, err := resolve("", []Option{WithEnvironment(), WithRequiredPins()}); err != nil {
		t.Fatalf("development, no pins directory, WithRequiredPins (each profile's first call decides): %v", err)
	}
}

// TestAnEmptyPinsDirectoryBesideAPinByOption (finding E, the owner's rule): WithEnvironment with an empty pins
// directory, WithRequiredPins and WithProfileFingerprint for one profile is a valid client: the pinned profile is served,
// and a profile nothing pins fails at its first call with ErrPinRequired, before anything is asked of cipheron.
func TestAnEmptyPinsDirectoryBesideAPinByOption(t *testing.T) {
	const pinned, unpinned = "credentials", "other"
	fake := cipherontest.New(t, pinned, unpinned)
	sock := fake.ServeSocket(t)
	newSidecarEnv(t, map[string]string{})
	t.Setenv(EnvSocket, sock)
	t.Setenv(EnvServerUID, strconv.Itoa(os.Getuid()))
	unsetenv(t, EnvRequestKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := DialGRPC("", WithEnvironment(), WithRequiredPins(), WithProfileFingerprint(pinned, fake.Fingerprint(pinned)))
	if err != nil {
		t.Fatalf("an empty pins directory beside a pin by option: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Encrypt(ctx, pinned, []byte("x")); err != nil {
		t.Fatalf("the profile pinned by option: %v", err)
	}
	calls := fake.PublicKeyCalls()
	if _, err := c.Encrypt(ctx, unpinned, []byte("x")); !errors.Is(err, ErrPinRequired) || !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("a profile nothing pins: %v; want ErrPinRequired", err)
	}
	if fake.PublicKeyCalls() != calls {
		t.Fatal("the unpinned profile's call asked cipheron for its keys")
	}
}

// recorder is an HTTP server that counts what reaches it.
type recorder struct {
	hits   atomic.Int64
	bodies atomic.Int64 // bytes of request bodies
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.hits.Add(1)
	n, _ := io.Copy(io.Discard, req.Body)
	r.bodies.Add(n)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// TestHTTPNeverFollowsARedirect (finding F): a 3xx answer — every kind, 307 and 308 included, which net/http follows
// by sending the body again — is the call's error, FAILED_PRECONDITION; the place it names receives nothing, and the
// address the client was given receives the request once. Over mutual TLS the redirect names a plain-http server:
// followed, the request (its sealed payload and its signature) would have left the TLS configuration altogether.
func TestHTTPNeverFollowsARedirect(t *testing.T) {
	const serverID = "spiffe://prod.example.org/cipheron"
	elsewhere := &recorder{}
	plain := httptest.NewServer(elsewhere)
	defer plain.Close()

	ca := cipherontest.NewCA(t, "ca")
	leaf := ca.Server(t, serverID)
	pair, err := tls.X509KeyPair(leaf.ChainPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var code atomic.Int64
	var first atomic.Int64
	redirecting := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, plain.URL+r.URL.Path, int(code.Load()))
	}))
	redirecting.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: ca.Pool, MinVersion: tls.VersionTLS13}
	redirecting.StartTLS()
	defer redirecting.Close()
	addr := redirecting.Listener.Addr().String()
	_, key := keyPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Over a unix socket too: there the transport dials the socket whatever the URL says, so a followed redirect
	// would come back to the same server — ten times.
	sockDir := cipherontest.SocketDir(t)
	sock := filepath.Join(sockDir, "r.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var onSocket atomic.Int64
	local := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onSocket.Add(1)
		http.Redirect(w, r, plain.URL+r.URL.Path, int(code.Load()))
	})}
	go func() { _ = local.Serve(l) }()
	defer func() { _ = local.Close() }()

	for _, status3xx := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		code.Store(int64(status3xx))
		first.Store(0)
		onSocket.Store(0)
		overTLS, err := DialHTTP(addr, WithTLS(cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/app", ca.Pool)),
			WithRequestKey(key), WithServerSPIFFEID(serverID))
		if err != nil {
			t.Fatal(err)
		}
		overSocket, err := DialHTTP(sock, WithServerUID(uint32(os.Getuid())))
		if err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]*Client{"TLS": overTLS, "socket": overSocket} {
			_, err := c.Encrypt(ctx, "credentials", []byte("s3cr3t"))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), strconv.Itoa(status3xx)) ||
				!strings.Contains(err.Error(), "redirect") {
				t.Errorf("HTTP %d over %s: %v; want FAILED_PRECONDITION naming the redirect", status3xx, name, err)
			}
			_ = c.Close()
		}
		if n := first.Load(); n != 1 {
			t.Errorf("HTTP %d: the TLS server received %d requests, want 1 (the request is never sent again)", status3xx, n)
		}
		if n := onSocket.Load(); n != 1 {
			t.Errorf("HTTP %d: the socket's server received %d requests, want 1", status3xx, n)
		}
	}
	if elsewhere.hits.Load() != 0 || elsewhere.bodies.Load() != 0 {
		t.Fatalf("the redirect's target received %d requests (%d bytes of bodies): a redirect was followed",
			elsewhere.hits.Load(), elsewhere.bodies.Load())
	}
	// And a network client's transport has no way to plaintext TCP at all, whatever would ask for it.
	network, err := DialHTTP(addr, WithTLS(cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/app", ca.Pool)),
		WithRequestKey(key), WithServerSPIFFEID(serverID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = network.Close() }()
	h, ok := network.rpcs[0].(*httpRPC)
	if !ok {
		t.Fatalf("a network HTTP client's transport: got %T", network.rpcs[0])
	}
	if conn, err := h.tr.DialContext(ctx, "tcp", plain.Listener.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("a network client's transport opened a plaintext TCP connection")
	}
	if h.client.CheckRedirect == nil {
		t.Fatal("the HTTP client follows redirects")
	}
}

// TestTLSFloor (finding G): the configuration the library builds from files requires TLS 1.3; a caller's
// configuration that says nothing gets TLS 1.3, and one that says TLS 1.2 keeps it. A client at the default does not
// talk to a TLS 1.2 server at all.
func TestTLSFloor(t *testing.T) {
	dir := t.TempDir()
	ca := cipherontest.NewCA(t, "ca")
	leaf := ca.Client(t, "spiffe://prod.example.org/app")
	cert := cipherontest.Write(t, dir, "c.crt", leaf.ChainPEM, 0o644)
	keyFile := cipherontest.Write(t, dir, "c.key", leaf.KeyPEM, 0o600)
	caFile := cipherontest.Write(t, dir, "ca.pem", ca.PEM, 0o644)
	cfg, err := TLSFromFiles(cert, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLSFromFiles: MinVersion %#x, want TLS 1.3", cfg.MinVersion)
	}
	_, key := keyPair(t)
	p, err := resolve("cipheron.prod.svc:8443", []Option{WithTLSFiles(cert, keyFile, caFile), WithRequestKey(key)})
	if err != nil || p.tls.MinVersion != tls.VersionTLS13 {
		t.Fatalf("WithTLSFiles: %v", err)
	}
	for name, tc := range map[string]struct{ given, want uint16 }{
		"unset":   {0, tls.VersionTLS13},
		"TLS 1.2": {tls.VersionTLS12, tls.VersionTLS12},
		"TLS 1.3": {tls.VersionTLS13, tls.VersionTLS13},
	} {
		own := cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/app", ca.Pool)
		own.MinVersion = tc.given
		got, err := clientTLS(own, "")
		if err != nil {
			t.Fatal(err)
		}
		if got.MinVersion != tc.want {
			t.Errorf("a configuration with MinVersion %s: %#x, want %#x", name, got.MinVersion, tc.want)
		}
		if own.MinVersion != tc.given {
			t.Errorf("%s: the caller's configuration was changed", name)
		}
	}

	// End to end: a server that speaks TLS 1.2 at most. The default client never completes a handshake with it
	// (no request reaches it); a client whose configuration asks for TLS 1.2 is served.
	const serverID = "spiffe://prod.example.org/cipheron"
	fake := cipherontest.New(t, "credentials")
	fake.RequireRequestKey("credentials", publicOf(t, key))
	addr := fake.ServeTLSConfig(t, ca.Server(t, serverID), ca, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })
	unset := cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/app", ca.Pool)
	unset.MinVersion = 0
	strict, err := DialGRPC(addr, WithTLS(unset), WithRequestKey(key), WithServerSPIFFEID(serverID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = strict.Close() }()
	short, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	_, err = strict.Encrypt(short, "credentials", []byte("x"))
	cancel()
	if err == nil || fake.PublicKeyCalls() != 0 {
		t.Fatalf("a TLS 1.3 client and a TLS 1.2 server: %v, %d requests reached the server", err, fake.PublicKeyCalls())
	}
	lax, err := DialGRPC(addr, WithTLS(cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/app", ca.Pool)), // MinVersion: TLS 1.2
		WithRequestKey(key), WithServerSPIFFEID(serverID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lax.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := lax.Encrypt(ctx, "credentials", []byte("x")); err != nil {
		t.Fatalf("a client that asked for TLS 1.2, and a TLS 1.2 server: %v", err)
	}
}

// hurriedConn counts the backoff resets hurry asks of a connection that never becomes ready.
type hurriedConn struct {
	resets atomic.Int64
	ready  atomic.Bool
}

func (c *hurriedConn) GetState() connectivity.State {
	if c.ready.Load() {
		return connectivity.Ready
	}
	return connectivity.TransientFailure
}
func (c *hurriedConn) ResetConnectBackoff() { c.resets.Add(1) }

// TestTheReconnectHurryIsBounded (finding H): after a refusal a waiting call cuts gRPC's backoff short only until
// one connection attempt has had its outcome — not every 50 ms for as long as the call waits. An attempt that
// fails otherwise (the server is down), one whose handshake completes, and another refusal each end it; so do a
// ready connection and the end of the call.
func TestTheReconnectHurryIsBounded(t *testing.T) {
	refusal := &refusedError{err: &net.OpError{Op: "remote error", Err: tls.AlertError(42)}}
	settle := func(t *testing.T, resets *atomic.Int64) int64 {
		t.Helper()
		// No reset is asked for once the goroutine has returned: the count stays where it is.
		n := resets.Load()
		time.Sleep(4 * hurryInterval)
		if m := resets.Load(); m != n {
			t.Fatalf("the connection's backoff was still being reset (%d, then %d)", n, m)
		}
		return n
	}
	for name, outcome := range map[string]func(r *refusals, conn *hurriedConn, cancel context.CancelFunc){
		"an attempt that failed otherwise": func(r *refusals, _ *hurriedConn, _ context.CancelFunc) { r.clear() },
		"another refusal":                  func(r *refusals, _ *hurriedConn, _ context.CancelFunc) { r.refused(refusal) },
		"a ready connection":               func(_ *refusals, conn *hurriedConn, _ context.CancelFunc) { conn.ready.Store(true) },
		"the end of the call":              func(_ *refusals, _ *hurriedConn, cancel context.CancelFunc) { cancel() },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRefusals()
			r.refused(refusal) // the last attempt was refused
			conn := &hurriedConn{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cctx, last, since, done := r.beginAt(ctx)
			defer done()
			if !last {
				t.Fatal("the last attempt was refused")
			}
			returned := make(chan struct{})
			go func() { hurry(cctx, conn, r, since); close(returned) }()
			// While nothing has happened it keeps asking: once is not enough (a reset before the backoff began is lost).
			for deadline := time.Now().Add(5 * time.Second); conn.resets.Load() < 3; {
				if time.Now().After(deadline) {
					t.Fatalf("only %d resets while the attempt was pending", conn.resets.Load())
				}
				time.Sleep(hurryInterval / 5)
			}
			outcome(r, conn, cancel)
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("hurry kept running after the attempt had its outcome")
			}
			settle(t, &conn.resets)
		})
	}
	// An attempt that already had its outcome when the call began its hurry: nothing is reset at all.
	r := newRefusals()
	r.refused(refusal)
	conn := &hurriedConn{}
	cctx, _, since, done := r.beginAt(context.Background())
	defer done()
	r.clear()
	hurry(cctx, conn, r, since)
	if n := conn.resets.Load(); n != 0 {
		t.Fatalf("%d resets after the attempt had settled", n)
	}
}

// TestHTTPStatusFallbacks (finding J): when the body's details cannot be read, the HTTP status decides what a
// RESOURCE_EXHAUSTED is — 429 is busy (a RetryInfo: never a bare RESOURCE_EXHAUSTED, which reads as a size refusal),
// 413 is ErrTooLarge — and a body that is read keeps its details.
func TestHTTPStatusFallbacks(t *testing.T) {
	hasRetry := func(err error) bool {
		for _, d := range status.Convert(err).Details() {
			if _, ok := d.(*errdetails.RetryInfo); ok {
				return true
			}
		}
		return false
	}
	// A google.rpc.Status whose details are of a type this build does not know: protojson refuses the whole body.
	unknownDetail := `{"code":8,"message":"cipheron is busy","details":[{"@type":"type.googleapis.com/example.v9.Unknown","x":1}]}`
	for name, body := range map[string]string{
		"details of an unknown type": unknownDetail,
		"not json":                   "<html>Too Many Requests</html>",
		"empty":                      "",
	} {
		err := httpStatus(http.StatusTooManyRequests, []byte(body))
		if status.Code(err) != codes.ResourceExhausted || !hasRetry(err) || errors.Is(err, ErrTooLarge) {
			t.Errorf("HTTP 429 with %s: %v (RetryInfo %v); want RESOURCE_EXHAUSTED with a RetryInfo", name, err, hasRetry(err))
		}
	}
	if err := httpStatus(http.StatusTooManyRequests, []byte(unknownDetail)); !strings.Contains(err.Error(), "cipheron is busy") {
		t.Errorf("the body's message is lost with its details: %v", err)
	}
	// A status that was read whole is what it says, on both transports: one without details stays without.
	if err := httpStatus(http.StatusTooManyRequests, []byte(`{"code":8,"message":"upstream is overloaded","details":[]}`)); status.Code(err) != codes.ResourceExhausted || hasRetry(err) {
		t.Errorf("HTTP 429 with a status that has no details: %v", err)
	}
	// cipheron's own busy body is kept as it is: its reason, and its delay.
	own := `{"code":8,"message":"busy","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"` + transport.ReasonBusy +
		`","domain":"` + transport.ErrorDomain + `"},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"3s"}]}`
	st := status.Convert(httpStatus(http.StatusTooManyRequests, []byte(own)))
	if len(st.Details()) != 2 {
		t.Fatalf("cipheron's busy body: %v", st.Details())
	}
	if ri, ok := st.Details()[1].(*errdetails.RetryInfo); !ok || ri.GetRetryDelay().AsDuration() != 3*time.Second {
		t.Fatalf("cipheron's busy body lost its delay: %v", st.Details())
	}
	// 413: ErrTooLarge whatever the body, RESOURCE_EXHAUSTED by its code.
	for name, body := range map[string]string{
		"no body":                    "",
		"a status":                   `{"code":8,"message":"request body too large"}`,
		"a status of another code":   `{"code":3,"message":"http: request body too large"}`,
		"details of an unknown type": unknownDetail,
	} {
		err := httpStatus(http.StatusRequestEntityTooLarge, []byte(body))
		if !errors.Is(err, ErrTooLarge) || status.Code(err) != codes.ResourceExhausted || hasRetry(err) {
			t.Errorf("HTTP 413 with %s: %v; want ErrTooLarge", name, err)
		}
	}
	// Details of an unknown type on another status: the body's code and message, as before.
	if err := httpStatus(http.StatusBadRequest, []byte(`{"code":3,"message":"m","details":[{"@type":"type.googleapis.com/example.v9.Unknown"}]}`)); status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "m" {
		t.Errorf("details of an unknown type on HTTP 400: %v", err)
	}
	for httpCode, want := range map[int]codes.Code{
		http.StatusNotImplemented:   codes.Unimplemented,
		http.StatusMethodNotAllowed: codes.Unimplemented,
	} {
		if got := status.Code(httpStatus(httpCode, nil)); got != want {
			t.Errorf("HTTP %d without a body: %v, want %v", httpCode, got, want)
		}
	}
}

// TestHTTPStatusesEndToEnd (findings A, J): over a real HTTP round trip — a server on a unix socket answering what
// a gateway, or something in its place, answers — a 404 of an operation's route is UNIMPLEMENTED (a cipheron
// without the operation), a 429 without a readable body is busy, and a 413 is ErrTooLarge.
func TestHTTPStatusesEndToEnd(t *testing.T) {
	var answer atomic.Value // func(http.ResponseWriter)
	sock := filepath.Join(cipherontest.SocketDir(t), "s.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var paths sync.Map
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths.Store(r.URL.Path, true)
		write, ok := answer.Load().(func(http.ResponseWriter))
		if !ok {
			t.Errorf("a request before an answer was set: got %T", answer.Load())
			http.Error(w, "no answer set", http.StatusInternalServerError)
			return
		}
		write(w)
	})}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	call := func() error {
		c, err := DialHTTP(sock, WithServerUID(uint32(os.Getuid())))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_, err = c.Keys(ctx, "credentials")
		return err
	}
	answer.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":5,"message":"Not Found","details":[]}`)) // the gateway's answer for an unknown route
	})
	if err := call(); status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "public-key") {
		t.Errorf("HTTP 404 of the operation's route: %v; want UNIMPLEMENTED naming the operation", err)
	}
	if _, ok := paths.Load("/v1/cipher/credentials/public-key"); !ok {
		t.Error("the request did not go to the operation's route")
	}
	answer.Store(func(w http.ResponseWriter) { http.Error(w, "slow down", http.StatusTooManyRequests) })
	err = call()
	if status.Code(err) != codes.ResourceExhausted || len(status.Convert(err).Details()) != 1 {
		t.Errorf("HTTP 429 from something that is not the gateway: %v; want RESOURCE_EXHAUSTED with a RetryInfo", err)
	}
	answer.Store(func(w http.ResponseWriter) { http.Error(w, "too large", http.StatusRequestEntityTooLarge) })
	if err := call(); !errors.Is(err, ErrTooLarge) {
		t.Errorf("HTTP 413: %v; want ErrTooLarge", err)
	}
}

// TestTheHTTPPoolIsTheClients (finding N): the HTTP transport keeps WithConnections connections at most, idle ones
// included — a burst of calls waits for a connection instead of opening one each, which cipheron's cap of
// connections per caller would refuse — and drops an idle connection before cipheron's own idle timeout does.
func TestTheHTTPPoolIsTheClients(t *testing.T) {
	for _, n := range []int{1, DefaultConnections, MaxConnections} {
		tr := httpTransport(n)
		if tr.MaxConnsPerHost != n || tr.MaxIdleConnsPerHost != n || tr.MaxIdleConns != n {
			t.Errorf("%d connections: MaxConnsPerHost %d, MaxIdleConnsPerHost %d, MaxIdleConns %d", n, tr.MaxConnsPerHost,
				tr.MaxIdleConnsPerHost, tr.MaxIdleConns)
		}
		if tr.IdleConnTimeout <= 0 || tr.IdleConnTimeout >= 2*time.Minute {
			t.Errorf("IdleConnTimeout %v: under cipheron's two minutes", tr.IdleConnTimeout)
		}
		if tr.Proxy != nil || !tr.DisableCompression || tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
			t.Errorf("the transport uses a proxy, compresses, or may upgrade to HTTP/2: %+v", tr)
		}
	}
	if MaxConnections > 32 {
		t.Errorf("MaxConnections %d is over cipheron's default maxConnectionsPerCaller (32)", MaxConnections)
	}

	// End to end: sixteen calls at once over a client of two connections open two connections, not sixteen.
	const profile = "credentials"
	fake := cipherontest.New(t, profile)
	sock := filepath.Join(cipherontest.SocketDir(t), "p.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingListener{Listener: l}
	mux := fake.HTTPHandler(t)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(counted) }()
	defer func() { _ = srv.Close() }()
	c, err := DialHTTP(sock, WithServerUID(uint32(os.Getuid())), WithConnections(2))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Encrypt(ctx, profile, []byte("warm")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				if _, err := c.Encrypt(ctx, profile, []byte("x")); err != nil {
					t.Errorf("a call of the burst: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if n := counted.accepted.Load(); n < 1 || n > 2 {
		t.Fatalf("65 calls, sixteen at once, over a client of 2 connections opened %d connections", n)
	}
}

type countingListener struct {
	net.Listener

	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// TestTheGRPCDialParameters (finding O): the connect backoff is capped — two seconds on the socket, ten on the
// network, not gRPC's two minutes — an attempt is given time to complete, the network keepalive stays clear of the
// 20 seconds under which cipheron's listener sends GOAWAY, and the windows are the listener's.
func TestTheGRPCDialParameters(t *testing.T) {
	s, n := connectParams(socketMaxBackoff, socketConnectTimeout), connectParams(networkMaxBackoff, networkConnectTimeout)
	if s.Backoff.MaxDelay != 2*time.Second || n.Backoff.MaxDelay != 10*time.Second {
		t.Errorf("the backoff caps: socket %v, network %v", s.Backoff.MaxDelay, n.Backoff.MaxDelay)
	}
	for name, p := range map[string]struct {
		base, min time.Duration
		mult, jit float64
	}{
		"socket":  {s.Backoff.BaseDelay, s.MinConnectTimeout, s.Backoff.Multiplier, s.Backoff.Jitter},
		"network": {n.Backoff.BaseDelay, n.MinConnectTimeout, n.Backoff.Multiplier, n.Backoff.Jitter},
	} {
		if p.base != time.Second || p.mult != 1.6 || p.jit != 0.2 || p.min < time.Second {
			t.Errorf("%s: base %v, multiplier %v, jitter %v, at least %v an attempt", name, p.base, p.mult, p.jit, p.min)
		}
	}
	const serverMinPing = 20 * time.Second // the server's keepaliveMinTime
	if keepaliveTime < 30*time.Second || keepaliveTime <= serverMinPing || keepaliveTimeout != 15*time.Second {
		t.Errorf("keepalive every %v (cipheron refuses under %v), timeout %v", keepaliveTime, serverMinPing, keepaliveTimeout)
	}
	if grpcStreamWindow != 1<<20 || grpcConnWindow != 4<<20 {
		t.Errorf("the windows: stream %d, connection %d", grpcStreamWindow, grpcConnWindow)
	}
}
