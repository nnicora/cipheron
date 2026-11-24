package certificate

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrMalformedBundle is wrapped by every ParseCertificateBundle refusal.
var ErrMalformedBundle = errors.New("certificate bundle does not parse completely")

// ParseCertificateBundle parses a PEM bundle of certificates STRICTLY: every byte of it must belong to a
// complete "CERTIFICATE" block with no headers whose content parses as an X.509 certificate, with only
// whitespace between, before and after the blocks, and at least one certificate. Anything else — text
// outside a block, a block cut short (no END line), a block of another type, a block that does not parse —
// refuses the whole bundle (an error wrapping ErrMalformedBundle). The blocks are read by ReadPEMBlocks, so
// a broken block in the middle refuses the bundle rather than being skipped.
//
// It is for a bundle that REPLACES one in service, read from a file that may be caught mid-write: a file cut
// at a block boundary still holds whole certificates, and a lenient reading (x509.CertPool.AppendCertsFromPEM,
// which skips what it cannot read) would adopt it as a smaller set. Refusing it keeps the last good set until
// the file is complete.
func ParseCertificateBundle(data []byte) ([]*x509.Certificate, error) {
	blocks, err := ReadPEMBlocks(data, PEMLabelCertificate)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedBundle, err)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%w: no certificate", ErrMalformedBundle)
	}
	out := make([]*x509.Certificate, 0, len(blocks))
	for i, b := range blocks {
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %w", ErrMalformedBundle, i+1, err)
		}
		out = append(out, cert)
	}
	return out, nil
}
