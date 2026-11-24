//go:build linux || darwin

package cipheron_test

// trust_test.go — the library against a fake cipheron it does not control the honesty of
// (cipherontest): request auth, response verification, key pinning and trust on first use, the
// socket's and the network's server checks, sizes, the connection pool and the shared key fetch.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
)

const (
	profile  = "credentials"
	idApp    = "spiffe://prod.example.org/ns/pay/sa/api"
	idServer = "spiffe://prod.example.org/cipheron"
)

func myUID() uint32 { return uint32(os.Getuid()) }

// publicOf is key's public half.
func publicOf(t *testing.T, key ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("an Ed25519 private key's public half: got %T", key.Public())
	}
	return pub
}

func ctxFor(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// waitUntil waits for cond, checked every millisecond, for at most a minute: a synchronization on a state the
// test can observe, not a guess at how long it takes to arrive.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not reached within a minute: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitParkedInLoad waits until n goroutines are blocked in the client's shared key fetch (client.(*Client).load,
// waiting on the fetch they asked for or joined): the only way to see that a call has joined a fetch, which the
// client does not expose. A goroutine woken by the fetch's end is runnable, not blocked, so it is not counted.
func waitParkedInLoad(t *testing.T, n int) {
	t.Helper()
	const frame = "/internal/client.(*Client).load("
	waitUntil(t, fmt.Sprintf("%d calls waiting on a shared key fetch", n), func() bool {
		buf := make([]byte, 1<<20)
		for {
			m := runtime.Stack(buf, true)
			if m < len(buf) {
				buf = buf[:m]
				break
			}
			buf = make([]byte, 2*len(buf))
		}
		parked := 0
		for g := range strings.SplitSeq(string(buf), "\n\n") {
			if strings.Contains(g, " [select") && strings.Contains(g, frame) {
				parked++
			}
		}
		return parked == n
	})
}

func newClient(t *testing.T, address string, opts ...cipheron.Option) *cipheron.Client {
	t.Helper()
	c, err := cipheron.New(address, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// roundTrip runs Encrypt, Decrypt, Sign and Verify and checks each.
func roundTrip(t *testing.T, c *cipheron.Client, pt []byte) {
	t.Helper()
	ctx := ctxFor(t, 30*time.Second)
	ct, err := c.Encrypt(ctx, profile, pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(ctx, profile, ct)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("Decrypt: %v (equal %v)", err, bytes.Equal(got, pt))
	}
	sig, err := c.Sign(ctx, profile, pt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if ok, err := c.Verify(ctx, profile, pt, sig.Bytes, sig.KeyID); !ok || err != nil {
		t.Fatalf("Verify: %v %v", ok, err)
	}
}

// TestNewRefusesWhatCannotBeTrusted: New refuses, before connecting, a socket with no server check, a network
// address without a request key, and TLS configurations that would trust the system's roots or present no
// client certificate.
func TestNewRefusesWhatCannotBeTrusted(t *testing.T) {
	sock := cipherontest.New(t, profile).ServeSocket(t)
	ca := cipherontest.NewCA(t, "ca")
	good := cipherontest.ClientTLS(t, ca, idApp, ca.Pool)
	noRoots := good.Clone()
	noRoots.RootCAs = nil
	emptyCert := good.Clone()
	emptyCert.Certificates = []tls.Certificate{{}}
	noKey := good.Clone()
	noKey.Certificates = []tls.Certificate{{Certificate: good.Certificates[0].Certificate}}
	_, rk, _ := ed25519.GenerateKey(rand.Reader)
	key := cipheron.WithRequestKey(rk)
	for name, c := range map[string]struct {
		address string
		opts    []cipheron.Option
		want    string
	}{
		"a socket with no server check": {sock, nil, "WithServerUID"},
		"a socket with both checks":     {sock, []cipheron.Option{cipheron.WithServerUID(1), cipheron.WithAnyServer()}, "contradict"},
		"a network address without a request key": {"127.0.0.1:8443",
			[]cipheron.Option{cipheron.WithTLSConfig(good)}, "request key is required"},
		"a configuration without RootCAs": {"127.0.0.1:8443",
			[]cipheron.Option{cipheron.WithTLSConfig(noRoots), key}, "system's roots"},
		"an empty client certificate": {"127.0.0.1:8443",
			[]cipheron.Option{cipheron.WithTLSConfig(emptyCert), key}, "client certificate is empty"},
		"a client certificate without a key": {"127.0.0.1:8443",
			[]cipheron.Option{cipheron.WithTLSConfig(noKey), key}, "client certificate is empty"},
		"WithAnyServer on the network": {"127.0.0.1:8443",
			[]cipheron.Option{cipheron.WithTLSConfig(good), key, cipheron.WithAnyServer()}, "unix socket only"},
		"a bad fingerprint": {sock, []cipheron.Option{cipheron.WithAnyServer(),
			cipheron.WithProfileFingerprint(profile, "sha256:ABC")}, "not a fingerprint"},
		"a short request key":  {sock, []cipheron.Option{cipheron.WithAnyServer(), cipheron.WithRequestKey(rk[:32])}, "Ed25519 private key"},
		"too many connections": {sock, []cipheron.Option{cipheron.WithAnyServer(), cipheron.WithConnections(17)}, "WithConnections"},
		"a tiny message limit": {sock, []cipheron.Option{cipheron.WithAnyServer(), cipheron.WithMaxMessageBytes(10)}, "WithMaxMessageBytes"},
		"two request keys":     {sock, []cipheron.Option{cipheron.WithAnyServer(), key, cipheron.WithRequestKeyFile("/x")}, "two answers"},
		"a relative key file":  {sock, []cipheron.Option{cipheron.WithAnyServer(), cipheron.WithRequestKeyFile("k.pem")}, "absolute"},
		"a key file that is no file": {sock, []cipheron.Option{cipheron.WithAnyServer(),
			cipheron.WithRequestKeyFile("/nonexistent/cipheron/request.key")}, "request key"},
	} {
		cl, err := cipheron.New(c.address, c.opts...)
		if err == nil {
			_ = cl.Close()
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to say %q", name, err, c.want)
		}
	}
	// A configuration that verifies the server itself needs no RootCAs.
	own := good.Clone()
	own.RootCAs = nil
	own.InsecureSkipVerify = true
	own.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
	if c, err := cipheron.New("127.0.0.1:8443", cipheron.WithTLSConfig(own), key); err != nil {
		t.Errorf("a configuration with its own verification: %v", err)
	} else {
		_ = c.Close()
	}
}

// TestRequestKeyFileMustBeTheOwners: a request key file others can read is refused.
func TestRequestKeyFileMustBeTheOwners(t *testing.T) {
	dir := t.TempDir()
	_, path := cipherontest.RequestKey(t, dir, "request.key")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if c, err := cipheron.New("/run/cipheron/cipheron.sock", cipheron.WithAnyServer(), cipheron.WithRequestKeyFile(path)); err == nil {
		_ = c.Close()
		t.Fatal("a request key file others can read was accepted")
	}
}

// TestSocketRoundTripWithRequestKeyAndPin: every request carries auth the server verifies over the transcript,
// every answer verifies, and the keys match the pin.
func TestSocketRoundTripWithRequestKeyAndPin(t *testing.T) {
	fake := cipherontest.New(t, profile)
	priv, path := cipherontest.RequestKey(t, t.TempDir(), "request.key")
	fake.RequireRequestKey(profile, publicOf(t, priv))
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()), cipheron.WithRequestKeyFile(path),
		cipheron.WithProfileFingerprint(profile, fake.Fingerprint(profile)))
	roundTrip(t, c, []byte("a plaintext"))
	roundTrip(t, c, nil)
	if verified, absent, refused := fake.Auth(); verified != 6 || absent != 0 || refused != 0 {
		t.Fatalf("auth verified %d, absent %d, refused %d; want 6, 0, 0", verified, absent, refused)
	}
	ctx := ctxFor(t, 10*time.Second)
	ct, err := c.Encrypt(ctx, profile, []byte("moved"))
	if err != nil {
		t.Fatal(err)
	}
	if ct2, err := c.ReEncrypt(ctx, profile, ct); err != nil || bytes.Equal(ct, ct2) {
		t.Fatalf("ReEncrypt: %v", err)
	} else if pt, err := c.Decrypt(ctx, profile, ct2); err != nil || string(pt) != "moved" {
		t.Fatalf("Decrypt of the re-encrypted: %q %v", pt, err)
	}
	if verified, _, refused := fake.Auth(); verified != 9 || refused != 0 {
		t.Fatalf("ReEncrypt's auth: verified %d, refused %d", verified, refused)
	}
	keys, err := c.Keys(ctx, profile)
	if err != nil || keys.Fingerprint != fake.Fingerprint(profile) {
		t.Fatalf("Keys: %+v %v", keys, err)
	}
	want := fake.ProfileKeys(profile)
	active, ok := keys.Active()
	if !bytes.Equal(keys.HPKE, want.HPKE) || !keys.Response.Equal(want.Response) ||
		keys.Tenancy != cipheron.TenancyShared || keys.ContextDigest != want.ContextDigest || len(keys.SigningKeys) != 1 ||
		!ok || !bytes.Equal(active.KeyID, fake.ActiveKeyID(profile)) || !active.PublicKey.Equal(want.SigningKeys[0].PublicKey) {
		t.Fatalf("Keys are not the profile's: %+v", keys)
	}
	if digest, err := c.ContextDigest(ctx, profile); err != nil || digest != want.ContextDigest {
		t.Fatalf("ContextDigest: %q %v", digest, err)
	}
	keys.SigningKeys[0].PublicKey[0] ^= 1 // the caller's copy: the cache is untouched
	keys.Response[0] ^= 1
	if again, _ := c.Keys(ctx, profile); !again.SigningKeys[0].PublicKey.Equal(want.SigningKeys[0].PublicKey) || !again.Response.Equal(want.Response) {
		t.Fatal("a caller's change to Keys' answer reached the cache")
	}
	roundTrip(t, c, []byte("after Keys"))
}

// TestSocketWithoutRequestKey: on the socket a caller without a request key sends no auth, and a server that
// requires one refuses it as it refuses a wrong key.
func TestSocketWithoutRequestKey(t *testing.T) {
	fake := cipherontest.New(t, profile)
	sock := fake.ServeSocket(t)
	roundTrip(t, newClient(t, sock, cipheron.WithServerUID(myUID())), []byte("x"))
	if verified, absent, _ := fake.Auth(); verified != 0 || absent != 3 {
		t.Fatalf("auth verified %d, absent %d; want 0, 3", verified, absent)
	}
	theirs, _, _ := ed25519.GenerateKey(rand.Reader)
	fake.RequireRequestKey(profile, theirs)
	_, mine, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]*cipheron.Client{
		"no request key":    newClient(t, sock, cipheron.WithServerUID(myUID())),
		"another's request": newClient(t, sock, cipheron.WithServerUID(myUID()), cipheron.WithRequestKey(mine)),
	} {
		if _, err := c.Encrypt(ctxFor(t, 10*time.Second), profile, []byte("x")); !errors.Is(err, cipheron.ErrPermissionDenied) {
			t.Errorf("%s: %v, want ErrPermissionDenied", name, err)
		}
	}
}

// TestImpostorWithAPinIsRefused: a server with other keys than the pinned ones answers nothing the client
// accepts, and none of its keys is cached.
func TestImpostorWithAPinIsRefused(t *testing.T) {
	genuine := cipherontest.New(t, profile)
	impostor := cipherontest.New(t, profile)
	sock := impostor.ServeSocket(t)
	c := newClient(t, sock, cipheron.WithServerUID(myUID()), cipheron.WithProfileFingerprint(profile, genuine.Fingerprint(profile)))
	ctx := ctxFor(t, 10*time.Second)
	if _, err := c.Encrypt(ctx, profile, []byte("secret")); !errors.Is(err, cipheron.ErrServerIdentity) ||
		!strings.Contains(err.Error(), "not the pinned") {
		t.Fatalf("Encrypt to an impostor: %v", err)
	}
	if _, err := c.Sign(ctx, profile, []byte("x")); !errors.Is(err, cipheron.ErrServerIdentity) {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := c.Keys(ctx, profile); !errors.Is(err, cipheron.ErrServerIdentity) {
		t.Fatalf("Keys: %v", err)
	}
	if n := impostor.PublicKeyCalls(); n < 3 {
		t.Fatalf("a refused key set was cached: %d fetches", n)
	}
	// Without a pin the same impostor is trusted on first use: what the pin is for.
	roundTrip(t, newClient(t, sock, cipheron.WithServerUID(myUID())), []byte("x"))
}

// TestChangedKeysAreNeverAdopted: once a profile's keys are cached, a server answering other keys is
// ErrServerKeyChanged on every call, and the cache keeps the first keys.
func TestChangedKeysAreNeverAdopted(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 10*time.Second)
	roundTrip(t, c, []byte("x"))
	first := fake.Fingerprint(profile)
	fake.Rekey(profile)
	for range 2 {
		if _, err := c.Encrypt(ctx, profile, []byte("x")); !errors.Is(err, cipheron.ErrServerKeyChanged) ||
			!errors.Is(err, cipheron.ErrServerIdentity) {
			t.Fatalf("Encrypt after a key change: %v", err)
		}
		if _, err := c.Sign(ctx, profile, []byte("x")); !errors.Is(err, cipheron.ErrServerKeyChanged) {
			t.Fatalf("Sign after a key change: %v", err)
		}
	}
	// Keys asks cipheron again, and reports the change rather than the new identity: the cache keeps the first
	// (every call above still answered it as a change, never adopting the new keys).
	if keys, err := c.Keys(ctx, profile); !errors.Is(err, cipheron.ErrServerKeyChanged) || keys.Fingerprint != "" {
		t.Fatalf("Keys after a key change: %q %v", keys.Fingerprint, err)
	}
	if first == fake.Fingerprint(profile) {
		t.Fatal("the fake's identity did not change")
	}
	// Decrypt sends nothing sealed to the profile: the answer's signature, by the new response key, is what
	// shows the change. The fake's new storage key cannot open the old ciphertext, so give it a new one.
	fresh := newClient(t, fake.SocketPath(), cipheron.WithServerUID(myUID()))
	ct, err := fresh.Encrypt(ctx, profile, []byte("y"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(ctx, profile, ct); !errors.Is(err, cipheron.ErrServerKeyChanged) {
		t.Fatalf("Decrypt after a key change: %v", err)
	}
}

// TestBadAnswersAreRefused: no answer is returned unless it is signed by the profile's keys and well formed.
func TestBadAnswersAreRefused(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	ctx := ctxFor(t, 30*time.Second)
	ct, err := c.Encrypt(ctx, profile, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	type call func() error
	encrypt := func() error { _, err := c.Encrypt(ctx, profile, []byte("x")); return err }
	decrypt := func() error { _, err := c.Decrypt(ctx, profile, ct); return err }
	sign := func() error { _, err := c.Sign(ctx, profile, []byte("x")); return err }
	reencrypt := func() error { _, err := c.ReEncrypt(ctx, profile, ct); return err }
	for _, tc := range []struct {
		name string
		mode cipherontest.Mode
		call call
		want error
	}{
		{"junk ciphertext", cipherontest.JunkCiphertext, encrypt, cipheron.ErrBadResponse},
		{"garbled plaintext", cipherontest.GarbledPlaintext, decrypt, cipheron.ErrBadResponse},
		{"encrypt signed by another key", cipherontest.ForeignResponseSignature, encrypt, cipheron.ErrServerIdentity},
		{"decrypt signed by another key", cipherontest.ForeignResponseSignature, decrypt, cipheron.ErrServerIdentity},
		{"encrypt unsigned", cipherontest.NoResponseSignature, encrypt, cipheron.ErrServerIdentity},
		{"decrypt unsigned", cipherontest.NoResponseSignature, decrypt, cipheron.ErrServerIdentity},
		{"sign signed by another key", cipherontest.ForeignResponseSignature, sign, cipheron.ErrServerIdentity},
		{"sign unsigned", cipherontest.NoResponseSignature, sign, cipheron.ErrServerIdentity},
		{"a short signature", cipherontest.ShortSignature, sign, cipheron.ErrServerIdentity},
		{"another key's signature", cipherontest.ForeignSignature, sign, cipheron.ErrServerIdentity},
		{"a key id no listed key has", cipherontest.UnknownKeyID, sign, cipheron.ErrServerIdentity},
		{"a format-3 ciphertext in a shared profile", cipherontest.WrongFormatCiphertext, encrypt, cipheron.ErrBadResponse},
		{"reencrypt junk", cipherontest.JunkCiphertext, reencrypt, cipheron.ErrBadResponse},
		{"reencrypt of the wrong format", cipherontest.WrongFormatCiphertext, reencrypt, cipheron.ErrBadResponse},
		{"reencrypt signed by another key", cipherontest.ForeignResponseSignature, reencrypt, cipheron.ErrServerIdentity},
		{"reencrypt unsigned", cipherontest.NoResponseSignature, reencrypt, cipheron.ErrServerIdentity},
	} {
		fake.SetMode(tc.mode)
		err := tc.call()
		if !errors.Is(err, tc.want) || errors.Is(err, cipheron.ErrServerKeyChanged) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	fake.SetMode(cipherontest.Honest)
	roundTrip(t, c, []byte("x"))
}

// TestServerUIDMismatchIsIdentityNotATimeout: a socket server running as another uid fails the call at once
// with ErrServerIdentity carrying the reason — not after the call's deadline, not as a timeout.
func TestServerUIDMismatchIsIdentityNotATimeout(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()+1))
	for i := range 3 {
		start := time.Now()
		_, err := c.Encrypt(ctxFor(t, 20*time.Second), profile, []byte("secret"))
		if !errors.Is(err, cipheron.ErrServerIdentity) || errors.Is(err, context.DeadlineExceeded) ||
			!strings.Contains(err.Error(), "not the expected uid") {
			t.Fatalf("call %d: %v", i, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("call %d waited %v for a refused server", i, d)
		}
	}
	if fake.PublicKeyCalls() != 0 {
		t.Fatal("a request reached the refused server")
	}
}

// TestNetworkTrust: over mutual TLS a request key signs every request and the server is verified by its SPIFFE
// ID or its hostname; a server that fails either is ErrServerIdentity, at once.
func TestNetworkTrust(t *testing.T) {
	ca := cipherontest.NewCA(t, "ca")
	fake := cipherontest.New(t, profile)
	priv, keyFile := cipherontest.RequestKey(t, t.TempDir(), "request.key")
	fake.RequireRequestKey(profile, publicOf(t, priv))
	addr := fake.ServeTLS(t, ca.Server(t, idServer), ca)
	tc := cipherontest.ClientTLS(t, ca, idApp, ca.Pool)
	pin := cipheron.WithProfileFingerprint(profile, fake.Fingerprint(profile))
	rk := cipheron.WithRequestKeyFile(keyFile)

	roundTrip(t, newClient(t, addr, cipheron.WithTLSConfig(tc), cipheron.WithServerSPIFFEID(idServer), rk, pin), []byte("x"))
	roundTrip(t, newClient(t, addr, cipheron.WithTLSConfig(tc), rk, pin), []byte("x")) // by hostname (127.0.0.1)
	if verified, absent, refused := fake.Auth(); verified != 6 || absent != 0 || refused != 0 {
		t.Fatalf("auth verified %d, absent %d, refused %d", verified, absent, refused)
	}

	other := cipherontest.NewCA(t, "other")
	for name, c := range map[string]struct {
		addr string
		opts []cipheron.Option
		want string
	}{
		"another SPIFFE ID": {fake.ServeTLS(t, ca.Server(t, "spiffe://prod.example.org/impostor"), ca),
			[]cipheron.Option{cipheron.WithServerSPIFFEID(idServer)}, "not the expected"},
		"another host name":       {fake.ServeTLS(t, ca.ServerFor(t, "other.example"), ca), nil, "certificate"},
		"an untrusted CA":         {fake.ServeTLS(t, other.Server(t, idServer), ca), []cipheron.Option{cipheron.WithServerSPIFFEID(idServer)}, "certificate"},
		"an untrusted CA by name": {fake.ServeTLS(t, other.Server(t, idServer), ca), nil, "certificate"},
	} {
		cl := newClient(t, c.addr, append(c.opts, cipheron.WithTLSConfig(tc), rk)...)
		start := time.Now()
		_, err := cl.Encrypt(ctxFor(t, 20*time.Second), profile, []byte("secret"))
		if !errors.Is(err, cipheron.ErrServerIdentity) || errors.Is(err, context.DeadlineExceeded) ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: waited %v", name, d)
		}
	}
}

// TestLargeMessages: a client carries several MiB both ways (gRPC's own default would refuse an answer over
// 4 MiB), and refuses before sending anything what its WithMaxMessageBytes cannot carry.
func TestLargeMessages(t *testing.T) {
	fake := cipherontest.New(t, profile)
	sock := fake.ServeSocket(t)
	roundTrip(t, newClient(t, sock, cipheron.WithServerUID(myUID())), random(t, 8<<20))
	c := newClient(t, sock, cipheron.WithServerUID(myUID()), cipheron.WithMaxMessageBytes(6<<20))
	roundTrip(t, c, random(t, 4<<20+123))
	ctx := ctxFor(t, 10*time.Second)
	before := total(fake.EncryptsPerConnection())
	for name, call := range map[string]func() error{
		"encrypt": func() error { _, err := c.Encrypt(ctx, profile, make([]byte, 6<<20)); return err },
		"decrypt": func() error { _, err := c.Decrypt(ctx, profile, make([]byte, 6<<20)); return err },
		"sign":    func() error { _, err := c.Sign(ctx, profile, make([]byte, 6<<20)); return err },
	} {
		if err := call(); !errors.Is(err, cipheron.ErrTooLarge) || !strings.Contains(err.Error(), "WithMaxMessageBytes") {
			t.Errorf("%s over the limit: %v", name, err)
		}
	}
	if total(fake.EncryptsPerConnection()) != before {
		t.Error("an oversized request was sent")
	}
}

func total(m map[int64]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// TestConnectionPool: calls take the pool's connections in turn.
func TestConnectionPool(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()), cipheron.WithConnections(3))
	ctx := ctxFor(t, 10*time.Second)
	for range 9 {
		if _, err := c.Encrypt(ctx, profile, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	per := fake.EncryptsPerConnection()
	if len(per) != 3 {
		t.Fatalf("Encrypt used %d connections, want 3: %v", len(per), per)
	}
	for conn, n := range per {
		if n != 3 {
			t.Fatalf("connection %d carried %d of 9 calls: %v", conn, n, per)
		}
	}
}

// TestColdCallsShareOneKeyFetch: concurrent first calls in a profile make one PublicKey call, and a caller
// whose context ends does not fail the others that wait on the same fetch.
func TestColdCallsShareOneKeyFetch(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	release := fake.HoldPublicKey()
	defer release()

	// The first caller's fetch reaches cipheron and is held there before anyone else asks: it leads the fetch.
	short, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() { _, err := c.Encrypt(short, profile, []byte("x")); firstDone <- err }()
	waitUntil(t, "the first caller's fetch is held at cipheron", func() bool { return fake.PublicKeyCalls() == 1 })

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Bounded past the waits below (a minute each), so a slow machine is not a failed call.
			_, err := c.Encrypt(ctxFor(t, 5*time.Minute), profile, []byte("x"))
			errs <- err
		}()
	}
	// The 16 wait on the first caller's fetch; then the first caller gives up.
	waitParkedInLoad(t, n+1)
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("the short call: %v", err)
	}
	// The 16 retry, as one fetch, held at cipheron, which all 16 wait on before it is let go.
	waitUntil(t, "the waiters' own fetch is held at cipheron", func() bool { return fake.PublicKeyCalls() == 2 })
	waitParkedInLoad(t, n)
	release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a waiting call failed: %v", err)
		}
	}
	// One fetch for the short caller (ended), one shared by the 16.
	if got := fake.PublicKeyCalls(); got != 2 {
		t.Fatalf("%d PublicKey calls, want 2", got)
	}
}

// TestColdCallsShareOneKeyFetchExactly: N concurrent cold calls, one PublicKey call.
func TestColdCallsShareOneKeyFetchExactly(t *testing.T) {
	fake := cipherontest.New(t, profile)
	c := newClient(t, fake.ServeSocket(t), cipheron.WithServerUID(myUID()))
	release := fake.HoldPublicKey()
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Bounded past the waits below (a minute each), so a slow machine is not a failed call.
			_, err := c.Sign(ctxFor(t, 5*time.Minute), profile, []byte("x"))
			errs <- err
		}()
	}
	// Every call waits on the one fetch, held at cipheron, before it is let go.
	waitUntil(t, "the fetch is held at cipheron", func() bool { return fake.PublicKeyCalls() == 1 })
	waitParkedInLoad(t, n)
	release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := fake.PublicKeyCalls(); got != 1 {
		t.Fatalf("%d PublicKey calls for %d cold calls, want 1", got, n)
	}
}
