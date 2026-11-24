package format

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// The test kinds' codecs: a stored header of one fixed field, one behind a length byte and one behind a 4-byte
// length; and a codec of any other form (an int: what it is does not matter to the framework).
type testCodec interface {
	Codec[testHeader]
}

type testHeader struct{ a, b, c []byte }

type fieldsV1 struct{ extra int } // extra: bytes appended beyond Size (a codec at odds with its frame)

func (fieldsV1) Layout() Layout {
	return Layout{Fields: []Field{{Name: "a", Min: 2, Max: 2}, {Name: "b", Prefix: 1, Min: 1, Max: 8},
		{Name: "c", Prefix: 4, Min: 1, Max: 300}}}
}
func (fieldsV1) Size(h testHeader) int { return 2 + 1 + len(h.b) + 4 + len(h.c) }
func (f fieldsV1) Append(dst []byte, h testHeader) ([]byte, error) {
	if len(h.a) != 2 || len(h.b) < 1 || len(h.b) > 8 || len(h.c) < 1 || len(h.c) > 300 {
		return nil, errTestField
	}
	dst = append(append(append(dst, h.a...), byte(len(h.b))), h.b...)
	dst = append(binary.BigEndian.AppendUint32(dst, uint32(len(h.c))), h.c...)
	return append(dst, make([]byte, f.extra)...), nil
}
func (fieldsV1) Parse(b []byte) (testHeader, int, bool) {
	if len(b) < 3 {
		return testHeader{}, 0, false
	}
	h := testHeader{a: b[:2]}
	n := int(b[2])
	if n < 1 || n > 8 || len(b) < 3+n+4 {
		return testHeader{}, 0, false
	}
	h.b = b[3 : 3+n]
	m := int(binary.BigEndian.Uint32(b[3+n:]))
	if m < 1 || m > 300 || len(b) < 3+n+4+m {
		return testHeader{}, 0, false
	}
	h.c = b[3+n+4 : 3+n+4+m]
	return h, 3 + n + 4 + m, true
}

var (
	errTestField   = errors.New("a field")
	errTestRefuse  = errors.New("refused")
	errTestUnknown = errors.New("unknown")
)

func testUnknown(uint32, uint32) error { return errTestUnknown }

// newTestStored is a Stored kind of magic for the tests.
func newTestStored(name, magic string, sealing Sealing) *Kind[testCodec] {
	return NewStoredKind[testCodec](name, magic, sealing, errTestRefuse, testUnknown)
}

// newGCM is AES-GCM with the module's random nonce: a test suite's AEAD.
func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(b)
}

// testSuiteOf is a test suite of namespace name.
func testSuiteOf(name string) Suite {
	return TestSuite("test "+name, TestNamespace(name), 32, 32, 12, 16, sha256.New, newGCM)
}
