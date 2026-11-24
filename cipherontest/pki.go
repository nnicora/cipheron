package cipherontest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a throwaway root certificate authority, ECDSA P-256 (approved under fips140=only).
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// PEM is the CA's certificate.
	PEM []byte
	// Pool holds the CA's certificate.
	Pool *x509.CertPool
}

// NewCA is a self-signed root CA named name, valid from an hour ago for a day.
func NewCA(tb testing.TB, name string) *CA {
	tb.Helper()
	key := newKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, PEM: pemBlock("CERTIFICATE", der), Pool: pool}
}

// Leaf is an issued certificate with its key, as PEM files hold them.
type Leaf struct {
	Cert *x509.Certificate
	// ChainPEM is the leaf certificate.
	ChainPEM []byte
	// KeyPEM is the private key, PKCS #8.
	KeyPEM []byte
}

// Client is a client certificate (clientAuth) for the SPIFFE ID id.
func (ca *CA) Client(tb testing.TB, id string) *Leaf {
	tb.Helper()
	return ca.issue(tb, []string{id}, nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// Server is a server certificate (serverAuth) for localhost and the loopback addresses, carrying the SPIFFE ID
// id when it is not empty.
func (ca *CA) Server(tb testing.TB, id string) *Leaf {
	tb.Helper()
	var uris []string
	if id != "" {
		uris = []string{id}
	}
	return ca.issue(tb, uris, []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// ServerFor is a server certificate (serverAuth) for the DNS name dns only.
func (ca *CA) ServerFor(tb testing.TB, dns string) *Leaf {
	tb.Helper()
	return ca.issue(tb, nil, []string{dns}, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (ca *CA) issue(tb testing.TB, uris, dns []string, ips []net.IP, eku []x509.ExtKeyUsage) *Leaf {
	tb.Helper()
	key := newKey(tb)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              dns,
		IPAddresses:           ips,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			tb.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	return &Leaf{Cert: cert, ChainPEM: pemBlock("CERTIFICATE", der), KeyPEM: pemBlock("PRIVATE KEY", p8)}
}

// Write writes data to dir/name with mode, replacing what was there through a rename (as a rotation would),
// and returns the path.
func Write(tb testing.TB, dir, name string, data []byte, mode os.FileMode) string {
	tb.Helper()
	p := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, "."+name+"-")
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := tmp.Write(data); err != nil {
		tb.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		tb.Fatal(err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		tb.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		tb.Fatal(err)
	}
	return p
}

func newKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func serial(tb testing.TB) *big.Int {
	tb.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		tb.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
