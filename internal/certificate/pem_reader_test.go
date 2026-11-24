package certificate

import (
	"errors"
	"strings"
	"testing"
)

// corruptBase64 replaces one character of the first body line of block with one outside the alphabet.
func corruptBase64(block string) string {
	at := strings.Index(block, "\n") + 12
	return block[:at] + "!" + block[at+1:]
}

// The strict reader reads every byte or refuses the whole input: a broken block in the middle is never
// skipped (as pem.Decode skips it), and nothing but whitespace may surround the blocks.
func TestReadPEMBlocksRefusesAnythingItCannotReadWhole(t *testing.T) {
	a, b, c := testCertPEM(t, "a"), testCertPEM(t, "b"), testCertPEM(t, "c")
	blocks, err := ReadPEMBlocks([]byte("\n  "+a+"\n"+strings.ReplaceAll(b, "\n", "\r\n")+"\t\n"+c), PEMLabelCertificate)
	if err != nil || len(blocks) != 3 {
		t.Fatalf("three whole blocks (one with CRLF lines): %d, %v", len(blocks), err)
	}
	if none, err := ReadPEMBlocks([]byte(" \n\t"), PEMLabelCertificate); err != nil || len(none) != 0 {
		t.Fatalf("whitespace only: %d, %v — want no block and no error", len(none), err)
	}
	endB := "-----END CERTIFICATE-----\n"
	for name, data := range map[string]string{
		"cut in the middle, then another block":   a + b[:len(b)/2] + "\n" + c,
		"a corrupted base64 character":            a + corruptBase64(b) + c,
		"a missing END line":                      a + strings.TrimSuffix(b, endB) + c,
		"a missing END line at the end":           a + strings.TrimSuffix(b, endB),
		"a mismatched END label":                  a + strings.Replace(b, endB, "-----END X509 CRL-----\n", 1) + c,
		"leading text":                            "leading text\n" + a + b,
		"trailing text":                           a + b + "trailing text",
		"text between blocks":                     a + "# a comment\n" + b,
		"text after a BEGIN line":                 strings.Replace(a, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE----- x", 1),
		"a header":                                strings.Replace(a, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n", 1),
		"an empty block":                          "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
		"non-canonical base64 (padding bits set)": "-----BEGIN CERTIFICATE-----\nAQJ=\n-----END CERTIFICATE-----\n",
		"a space inside a base64 line":            a[:40] + " " + a[40:],
	} {
		if blocks, err := ReadPEMBlocks([]byte(data), PEMLabelCertificate); !errors.Is(err, ErrMalformedPEM) {
			t.Errorf("%s: %d blocks, %v — want ErrMalformedPEM", name, len(blocks), err)
		}
	}
	var label *PEMLabelError
	if _, err := ReadPEMBlocks([]byte(a+"-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n"), PEMLabelCertificate); !errors.As(err, &label) ||
		label.Label != "EC PRIVATE KEY" || label.Block != 2 || !errors.Is(err, ErrMalformedPEM) {
		t.Errorf("an unexpected label: %v, want a *PEMLabelError naming it", err)
	}
}

// The reviewer's case (OI-080): A + B (cut short, or with a corrupted character) + C is refused whole,
// never adopted as {A, C}.
func TestParseCertificateBundleRefusesABrokenBlockInTheMiddle(t *testing.T) {
	a, b, c := testCertPEM(t, "A"), testCertPEM(t, "B"), testCertPEM(t, "C")
	for name, bundle := range map[string]string{
		"B cut short":           a + b[:len(b)/2] + "\n" + c,
		"B with a corrupt char": a + corruptBase64(b) + c,
	} {
		if certs, err := ParseCertificateBundle([]byte(bundle)); !errors.Is(err, ErrMalformedBundle) {
			t.Errorf("%s: read as %d certificates, %v — want ErrMalformedBundle", name, len(certs), err)
		}
	}
}
