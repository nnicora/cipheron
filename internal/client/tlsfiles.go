package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nnicora/cipheron/internal/certificate"
	"github.com/nnicora/cipheron/internal/secpath"
	"github.com/nnicora/cipheron/internal/zeroize"
)

const (
	// maxPEMFileBytes bounds a certificate chain or CA bundle file.
	maxPEMFileBytes = 1 << 20
	// maxPrivateKeyFileBytes bounds a private key file.
	maxPrivateKeyFileBytes = 64 << 10
)

// TLSFromFiles is a client TLS configuration for cipheron's network listener, read from PEM files:
//
//   - certFile and keyFile are this client's certificate chain (leaf first; the leaf carries the client's one identity
//     SAN, of the type its trust bundle at cipheron reads) and its private key. They are read again on EVERY handshake
//     (GetClientCertificate), so a certificate rotated on disk — by cert-manager, or a SPIRE helper writing files — is
//     used by the next connection without a restart. A read that fails (a file caught mid-write) falls back to the last
//     pair read, while that one has not expired.
//   - caFile is the CA bundle the server's certificate must verify against, read once, here.
//
// Every file goes through the checked reader (secpath.ReadFile): owned by root or this process's user, not
// writable by its group or others, in a directory chain no one else can write — whoever could replace the CA
// file could stand in for cipheron, and whoever could replace the key could be this client — and the private key
// readable by no one else (0400, 0440, 0600, 0640). The chain and the bundle must parse completely
// (certificate.ParseCertificateBundle), and the pair is read once here so a mistake fails now.
//
// The server is verified by hostname (the address's host) unless WithServerSPIFFEID asks for its SPIFFE ID.
//
// The configuration requires TLS 1.3 (MinVersion): cipheron's listener serves it — and requires it unless its
// network.tls.minVersion says "1.2" — and only under TLS 1.3 is cipheron's refusal of this client's certificate an
// authenticated alert, which fails a call at once (refusal.go). A caller that must reach a cipheron limited to TLS
// 1.2 lowers MinVersion on the configuration returned and passes it to WithTLS.
func TLSFromFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	caPEM, err := secpath.ReadFile(caFile, "cipheron CA file", secpath.Public, maxPEMFileBytes)
	if err != nil {
		return nil, err
	}
	cas, err := certificate.ParseCertificateBundle(caPEM)
	if err != nil {
		return nil, fmt.Errorf("cipheron CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	for _, ca := range cas {
		pool.AddCert(ca)
	}
	kp := &keyPairFiles{certFile: certFile, keyFile: keyFile, now: time.Now}
	first, err := kp.load()
	if err != nil {
		return nil, err
	}
	kp.last = first
	return &tls.Config{RootCAs: pool, GetClientCertificate: kp.get, MinVersion: tls.VersionTLS13}, nil
}

// keyPairFiles reads a certificate and key pair from its files on every handshake.
type keyPairFiles struct {
	certFile, keyFile string
	now               func() time.Time

	mu   sync.Mutex
	last *tls.Certificate
}

// get is the configuration's GetClientCertificate.
func (k *keyPairFiles) get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c, err := k.load()
	k.mu.Lock()
	defer k.mu.Unlock()
	if err == nil {
		k.last = c
		return c, nil
	}
	if k.last != nil && k.last.Leaf != nil && k.now().Before(k.last.Leaf.NotAfter) {
		return k.last, nil
	}
	return nil, err
}

func (k *keyPairFiles) load() (*tls.Certificate, error) {
	certPEM, err := secpath.ReadFile(k.certFile, "cipheron client certificate", secpath.Public, maxPEMFileBytes)
	if err != nil {
		return nil, err
	}
	if _, err := certificate.ParseCertificateBundle(certPEM); err != nil {
		return nil, fmt.Errorf("cipheron client certificate %s: %w", k.certFile, err)
	}
	keyPEM, err := secpath.ReadFile(k.keyFile, "cipheron client private key", secpath.Private, maxPrivateKeyFileBytes)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	zeroize.Bytes(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("cipheron client key %s is not the key of %s: %w", k.keyFile, k.certFile, err)
	}
	if pair.Leaf == nil {
		return nil, errors.New("cipheron client certificate: the leaf did not parse")
	}
	return &pair, nil
}
