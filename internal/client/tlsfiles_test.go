//go:build linux || darwin

package client

import (
	"strings"
	"testing"

	testpki "github.com/nnicora/cipheron/cipherontest"
)

func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string]endpoint{
		"/run/cipheron/cipheron.sock":        {socket: "/run/cipheron/cipheron.sock"},
		"unix:///run/cipheron/cipheron.sock": {socket: "/run/cipheron/cipheron.sock"},
		"cipheron.prod.svc:8443":             {address: "cipheron.prod.svc:8443"},
		"127.0.0.1:8443":                     {address: "127.0.0.1:8443"},
		"[::1]:8443":                         {address: "[::1]:8443"},
	} {
		got, err := parseEndpoint(in)
		if err != nil || got != want {
			t.Errorf("parseEndpoint(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	// A bare name is a socket relative to the working directory.
	if got, err := parseEndpoint("c.sock"); err != nil || !strings.HasSuffix(got.socket, "/c.sock") || got.address != "" {
		t.Errorf("a bare name: %+v %v", got, err)
	}
	for _, bad := range []string{"", "unix://run/c.sock", ":8443", "host:0", "host:65536", "host:https", "a:b:c"} {
		if got, err := parseEndpoint(bad); err == nil {
			t.Errorf("parseEndpoint(%q) = %+v, accepted", bad, got)
		}
	}
}

// TestTheClientPairIsReadOnEveryHandshake: a rotated certificate is presented by the next handshake; a file
// caught mid-write falls back to the last pair read.
func TestTheClientPairIsReadOnEveryHandshake(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "ca")
	first := ca.Client(t, "spiffe://prod.example.org/a")
	cert := testpki.Write(t, dir, "c.crt", first.ChainPEM, 0o644)
	key := testpki.Write(t, dir, "c.key", first.KeyPEM, 0o600)
	caFile := testpki.Write(t, dir, "ca.pem", ca.PEM, 0o644)

	cfg, err := TLSFromFiles(cert, key, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil || cfg.GetClientCertificate == nil || cfg.InsecureSkipVerify {
		t.Fatalf("configuration %+v", cfg)
	}
	serial := func() string {
		t.Helper()
		c, err := cfg.GetClientCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.SerialNumber.String()
	}
	if serial() != first.Cert.SerialNumber.String() {
		t.Fatal("not the file's certificate")
	}
	next := ca.Client(t, "spiffe://prod.example.org/a")
	testpki.Write(t, dir, "c.key", next.KeyPEM, 0o600)
	testpki.Write(t, dir, "c.crt", next.ChainPEM, 0o644)
	if serial() != next.Cert.SerialNumber.String() {
		t.Fatal("the rotated certificate was not read")
	}
	testpki.Write(t, dir, "c.crt", next.ChainPEM[:len(next.ChainPEM)/2], 0o644)
	if serial() != next.Cert.SerialNumber.String() {
		t.Fatal("a file caught mid-write did not fall back to the last pair")
	}
}

func TestTLSFromFilesRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "ca")
	leaf := ca.Client(t, "spiffe://prod.example.org/a")
	cert := testpki.Write(t, dir, "c.crt", leaf.ChainPEM, 0o644)
	caFile := testpki.Write(t, dir, "ca.pem", ca.PEM, 0o644)
	for name, c := range map[string]struct {
		cert, key, ca string
	}{
		"a key others can read":         {cert, testpki.Write(t, dir, "k1", leaf.KeyPEM, 0o644), caFile},
		"a key its group can write":     {cert, testpki.Write(t, dir, "k2", leaf.KeyPEM, 0o620), caFile},
		"a CA file others can write":    {cert, testpki.Write(t, dir, "k3", leaf.KeyPEM, 0o600), testpki.Write(t, dir, "ca2", ca.PEM, 0o666)},
		"a key that is not the cert's":  {cert, testpki.Write(t, dir, "k4", ca.Client(t, "spiffe://prod.example.org/a").KeyPEM, 0o600), caFile},
		"a CA file that does not parse": {cert, testpki.Write(t, dir, "k5", leaf.KeyPEM, 0o600), testpki.Write(t, dir, "ca3", ca.PEM[:40], 0o644)},
		"a relative path":               {"c.crt", "c.key", "ca.pem"},
	} {
		if _, err := TLSFromFiles(c.cert, c.key, c.ca); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
