package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A complete bundle parses whole; every way a bundle can be caught half-written, or hold anything but
// certificates, refuses it — in particular a bundle cut after its first whole certificate, which a lenient
// reading would adopt as a smaller set.
func TestParseCertificateBundleAcceptsOnlyACompleteBundle(t *testing.T) {
	a, b := testCertPEM(t, "a"), testCertPEM(t, "b")
	certs, err := ParseCertificateBundle([]byte("\n" + a + "\n" + b + "\n\n"))
	if err != nil || len(certs) != 2 || certs[0].Subject.CommonName != "a" || certs[1].Subject.CommonName != "b" {
		t.Fatalf("a complete bundle: %d certificates, %v", len(certs), err)
	}
	for name, data := range map[string]string{
		"cut inside the second block": a + b[:len(b)/2],
		"cut after the second BEGIN":  a + "-----BEGIN CERTIFICATE-----\n",
		"trailing garbage":            a + b + "garbage",
		"leading garbage":             "garbage\n" + a,
		"text between blocks":         a + "# comment\n" + b,
		"a key block":                 a + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"a block that does not parse": a + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"empty":                       "",
		"whitespace only":             " \n\t",
		"a certificate with a header": strings.Replace(a, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n", 1),
	} {
		if certs, err := ParseCertificateBundle([]byte(data)); err == nil || !errors.Is(err, ErrMalformedBundle) {
			t.Errorf("%s: %d certificates, %v — want ErrMalformedBundle", name, len(certs), err)
		}
	}
}
