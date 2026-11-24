//go:build linux || darwin

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
)

// TestHTTPTransportSignsAndVerifies: the HTTP API carries the request nonce, the request auth and the response
// signature as gRPC does, and its refusals are the same.
func TestHTTPTransportSignsAndVerifies(t *testing.T) {
	const profile = "credentials"
	fake := cipherontest.New(t, profile)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fake.RequireRequestKey(profile, pub)
	sock := fake.ServeHTTPSocket(t)
	c, err := DialHTTP(sock, WithServerUID(uint32(os.Getuid())), WithRequestKey(priv),
		WithProfileFingerprint(profile, fake.Fingerprint(profile)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ct, err := c.Encrypt(ctx, profile, []byte("over HTTP"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.Decrypt(ctx, profile, ct); err != nil || string(pt) != "over HTTP" {
		t.Fatalf("Decrypt: %q %v", pt, err)
	}
	sig, err := c.Sign(ctx, profile, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Verify(ctx, profile, []byte("x"), sig.Bytes, sig.KeyID); !ok || err != nil {
		t.Fatalf("Verify: %v %v", ok, err)
	}
	ct2, err := c.ReEncrypt(ctx, profile, ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.Decrypt(ctx, profile, ct2); err != nil || string(pt) != "over HTTP" {
		t.Fatalf("Decrypt of the re-encrypted: %q %v", pt, err)
	}
	if verified, absent, refused := fake.Auth(); verified != 5 || absent != 0 || refused != 0 {
		t.Fatalf("auth verified %d, absent %d, refused %d", verified, absent, refused)
	}
	fake.SetMode(cipherontest.ForeignResponseSignature)
	if _, err := c.Encrypt(ctx, profile, []byte("x")); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("an answer signed by another key over HTTP: %v", err)
	}
	fake.SetMode(cipherontest.Honest)

	// A wrapped profile's provisioning over HTTP: CreateTenantKey, then RewrapTenantKey (its own path).
	const docs = "docs"
	wf := cipherontest.New(t, docs)
	wf.MakePerTenant(docs)
	wc, err := DialHTTP(wf.ServeHTTPSocket(t), WithAnyServer(), WithProfileFingerprint(docs, wf.Fingerprint(docs)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wc.Close() }()
	tk, err := wc.CreateTenantKey(ctx, docs, "t_1")
	if err != nil {
		t.Fatal(err)
	}
	wf.SetWriteVersion(docs, "v2")
	nk, err := wc.RewrapTenantKey(ctx, docs, "t_1", tk.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := ReadTenantKey(nk.Blob); err != nil || info.WrappingVersion != "v2" ||
		nk.Fingerprint != tk.Fingerprint {
		t.Fatalf("the rewrapped blob over HTTP: %+v %v", info, err)
	}

	impostor, err := DialHTTP(sock, WithServerUID(uint32(os.Getuid())+1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = impostor.Close() }()
	if _, err := impostor.Encrypt(ctx, profile, []byte("x")); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("a server of another uid over HTTP: %v", err)
	}
}

// TestHTTPOverTLSRefusesAnImpostor: over HTTPS a server whose certificate fails verification is
// ErrServerIdentity, as over gRPC.
func TestHTTPOverTLSRefusesAnImpostor(t *testing.T) {
	ca := cipherontest.NewCA(t, "ca")
	fake := cipherontest.New(t, "credentials")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tc := cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/a", ca.Pool)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for name, addr := range map[string]string{
		"another SPIFFE ID": fake.ServeTLS(t, ca.Server(t, "spiffe://prod.example.org/impostor"), ca),
		"another CA":        fake.ServeTLS(t, cipherontest.NewCA(t, "other").Server(t, "spiffe://prod.example.org/cipheron"), ca),
	} {
		c, err := DialHTTP(addr, WithTLS(tc), WithRequestKey(priv), WithServerSPIFFEID("spiffe://prod.example.org/cipheron"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Encrypt(ctx, "credentials", []byte("x")); !errors.Is(err, ErrServerIdentity) {
			t.Errorf("%s: %v", name, err)
		}
		_ = c.Close()
	}
}

// TestServerVerificationRefusalsAreIdentityErrors: whatever verifies the server — the configuration's own
// VerifyConnection or VerifyPeerCertificate, the SPIFFE ID check, crypto/tls's hostname check — its refusal
// is recognized as an identity refusal; a GetClientCertificate that answers nothing usable fails.
func TestServerVerificationRefusalsAreIdentityErrors(t *testing.T) {
	ca := cipherontest.NewCA(t, "ca")
	base := cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/a", ca.Pool)
	no := errors.New("no")

	vc := base.Clone()
	vc.VerifyConnection = func(tls.ConnectionState) error { return no }
	got, err := clientTLS(vc, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := got.VerifyConnection(tls.ConnectionState{}); !isIdentityError(err) || !errors.Is(err, no) {
		t.Errorf("VerifyConnection's refusal: %v", err)
	}
	vp := base.Clone()
	vp.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return no }
	if got, err = clientTLS(vp, ""); err != nil {
		t.Fatal(err)
	}
	if err := got.VerifyPeerCertificate(nil, nil); !isIdentityError(err) {
		t.Errorf("VerifyPeerCertificate's refusal: %v", err)
	}
	if got, err = clientTLS(base, "spiffe://prod.example.org/cipheron"); err != nil {
		t.Fatal(err)
	}
	if err := got.VerifyConnection(tls.ConnectionState{}); !isIdentityError(err) {
		t.Errorf("the SPIFFE check's refusal: %v", err)
	}
	if !isIdentityError(&tls.CertificateVerificationError{Err: no}) || isIdentityError(no) {
		t.Error("isIdentityError")
	}

	empty := base.Clone()
	empty.Certificates = nil
	empty.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	if got, err = clientTLS(empty, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := got.GetClientCertificate(nil); err == nil {
		t.Error("an empty certificate from GetClientCertificate was presented")
	}
}

func TestIsSocket(t *testing.T) {
	for addr, want := range map[string]bool{
		"/run/cipheron/cipheron.sock": true, "unix:///run/c.sock": true, "c.sock": true,
		"cipheron.prod.svc:8443": false, "127.0.0.1:8443": false,
	} {
		if got, err := IsSocket(addr); err != nil || got != want {
			t.Errorf("IsSocket(%q) = %v, %v", addr, got, err)
		}
	}
	if _, err := IsSocket("a:b:c"); err == nil {
		t.Error("IsSocket accepted a:b:c")
	}
}

// TestIdentityStateEndsWaitingCalls: a refusal ends every call waiting at that moment, with the refusal as
// its cause; a later attempt that is not refused clears it.
func TestIdentityStateEndsWaitingCalls(t *testing.T) {
	s := newIdentityState()
	ctx, opts, done := s.begin(context.Background())
	defer done()
	if len(opts) != 0 {
		t.Fatal("a call waits for readiness when nothing was refused")
	}
	refusal := &identityError{errors.New("uid 1, not 2")}
	s.failed(refusal)
	<-ctx.Done()
	if err := outcome(ctx, context.Canceled); !errors.Is(err, ErrServerIdentity) || !errors.Is(err, refusal) {
		t.Fatalf("outcome: %v", err)
	}
	_, opts2, done2 := s.begin(context.Background())
	done2()
	if len(opts2) != 1 {
		t.Fatal("a call after a refusal waits for readiness")
	}
	s.clear()
	if s.last() != nil {
		t.Fatal("clear")
	}
	if len(s.waiting) != 0 {
		t.Fatalf("%d calls still registered", len(s.waiting))
	}
}
