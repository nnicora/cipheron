package certificate

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// PEM labels (RFC 7468) the strict reader's callers accept.
const (
	// PEMLabelCertificate is the label of an X.509 certificate (RFC 7468 §5).
	PEMLabelCertificate = "CERTIFICATE"
	// PEMLabelCRL is the label of an X.509 certificate revocation list (RFC 7468 §6).
	PEMLabelCRL = "X509 CRL"
)

const (
	pemBegin    = "-----BEGIN "
	pemEnd      = "-----END "
	pemBoundary = "-----"
)

// ErrMalformedPEM is wrapped by every ReadPEMBlocks refusal.
var ErrMalformedPEM = errors.New("PEM does not read completely")

// PEMLabelError is the ReadPEMBlocks refusal of a block whose label the caller does not accept. It wraps
// ErrMalformedPEM; Label lets a caller say more (a private key, for instance).
type PEMLabelError struct {
	// Block is the 1-based position of the block.
	Block int
	// Label is the block's label, as its BEGIN line names it.
	Label string
}

func (e *PEMLabelError) Error() string {
	return fmt.Sprintf("%v: PEM block %d is a %q block", ErrMalformedPEM, e.Block, e.Label)
}

func (e *PEMLabelError) Unwrap() error { return ErrMalformedPEM }

// PEMBlock is one block ReadPEMBlocks read: its label and its decoded content.
type PEMBlock struct {
	Label string
	Bytes []byte
}

// ReadPEMBlocks reads data as PEM blocks (RFC 7468, strict) and nothing else. It walks the bytes itself,
// so nothing is skipped:
//   - every block starts with a line "-----BEGIN <label>-----" and ends with the matching
//     "-----END <label>-----", before any other BEGIN line; a block without its END line, or with
//     another label's, refuses the whole input;
//   - a block's body is base64 lines, decoded strictly (no character outside the alphabet, padding only
//     at the end), with only whitespace around each line; a header line ("Name: value") is refused;
//   - only whitespace may come before, between or after the blocks;
//   - the label must be one of accept (a *PEMLabelError otherwise), checked at the BEGIN line.
//
// Every refusal wraps ErrMalformedPEM. An input of whitespace only has no block, which is not an error
// here: each caller says whether it needs one.
func ReadPEMBlocks(data []byte, accept ...string) ([]PEMBlock, error) {
	var out []PEMBlock
	lines := splitLines(data)
	for i := 0; i < len(lines); i++ {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		n := len(out) + 1
		label, ok := boundaryLabel(line, pemBegin)
		if !ok {
			return nil, fmt.Errorf("%w: text outside a PEM block before block %d", ErrMalformedPEM, n)
		}
		if !acceptable(label, accept) {
			return nil, &PEMLabelError{Block: n, Label: label}
		}
		var body []byte
		ended := false
		for i++; i < len(lines); i++ {
			l := bytes.TrimSpace(lines[i])
			if bytes.HasPrefix(l, []byte(pemBoundary)) {
				if end, isEnd := boundaryLabel(l, pemEnd); isEnd && end == label {
					ended = true
					break
				}
				return nil, fmt.Errorf("%w: PEM block %d (%s) has no matching END line", ErrMalformedPEM, n, label)
			}
			if bytes.IndexByte(l, ':') >= 0 {
				return nil, fmt.Errorf("%w: PEM block %d (%s) carries a header", ErrMalformedPEM, n, label)
			}
			body = append(body, l...)
		}
		if !ended {
			return nil, fmt.Errorf("%w: PEM block %d (%s) is cut short: no END line", ErrMalformedPEM, n, label)
		}
		der, err := base64.StdEncoding.Strict().DecodeString(string(body))
		if err != nil {
			return nil, fmt.Errorf("%w: PEM block %d (%s) is not base64: %w", ErrMalformedPEM, n, label, err)
		}
		if len(der) == 0 {
			return nil, fmt.Errorf("%w: PEM block %d (%s) is empty", ErrMalformedPEM, n, label)
		}
		out = append(out, PEMBlock{Label: label, Bytes: der})
	}
	return out, nil
}

// splitLines splits data at "\n"; a "\r" before it is whitespace, trimmed with the rest.
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	return bytes.Split(data, []byte("\n"))
}

// boundaryLabel is the label of a whole boundary line "<prefix><label>-----", or false. A label is
// printable ASCII without a hyphen at either end, and not empty (RFC 7468 §3).
func boundaryLabel(line []byte, prefix string) (string, bool) {
	if !bytes.HasPrefix(line, []byte(prefix)) || !bytes.HasSuffix(line, []byte(pemBoundary)) ||
		len(line) < len(prefix)+len(pemBoundary)+1 {
		return "", false
	}
	label := line[len(prefix) : len(line)-len(pemBoundary)]
	if label[0] == '-' || label[len(label)-1] == '-' {
		return "", false
	}
	for _, c := range label {
		if c < ' ' || c > '~' {
			return "", false
		}
	}
	return string(label), true
}

func acceptable(label string, accept []string) bool {
	for _, a := range accept {
		if label == a {
			return true
		}
	}
	return false
}
