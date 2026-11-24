package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	mrand "math/rand/v2"
)

// copiedDigest is Digest as it was before it hashed its fields in place: the label and every field appended,
// length-prefixed, into one slice, and the SHA-256 of that. It is the definition the wire contract was signed
// under, kept here as the reference Digest must equal byte for byte.
func copiedDigest(fields ...[]byte) [sha256.Size]byte {
	t := transcript(nil).addString(digestLabel)
	for _, f := range fields {
		t = t.add(f)
	}
	return sha256.Sum256(t)
}

// TestDigestHashesInPlaceWhatItUsedToCopy: Digest writes each field's length and bytes into the hash instead of
// copying them into one buffer first, and the digest is the same — for no field, nil and empty fields (which are
// one thing: a zero length), fields of every size around the hash's block, and random field lists. A request
// signed by a release that copied verifies under one that streams, and the other way round.
func TestDigestHashesInPlaceWhatItUsedToCopy(t *testing.T) {
	random := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := [][][]byte{
		nil,
		{},
		{nil},
		{{}},
		{nil, nil},
		{{}, nil, {}},
		{[]byte("a")},
		{[]byte("a"), nil},
		{nil, []byte("a")},
		{[]byte("ab"), []byte("c")},
		{[]byte("a"), []byte("bc")},
		{random(55), random(56), random(63), random(64), random(65)},
		{random(1 << 20), nil, random(3), {}},
	}
	for range 200 {
		fields := make([][]byte, mrand.IntN(7))
		for i := range fields {
			switch mrand.IntN(5) {
			case 0: // nil
			case 1:
				fields[i] = []byte{}
			default:
				fields[i] = random(mrand.IntN(300))
			}
		}
		cases = append(cases, fields)
	}
	for i, fields := range cases {
		before := make([][]byte, len(fields))
		for j, f := range fields {
			before[j] = bytes.Clone(f)
		}
		got, want := Digest(fields...), copiedDigest(fields...)
		if got != want {
			t.Fatalf("case %d (%d fields): Digest %x, the copied digest %x", i, len(fields), got, want)
		}
		for j, f := range fields {
			if !bytes.Equal(f, before[j]) {
				t.Fatalf("case %d: Digest changed field %d", i, j)
			}
		}
	}
	// Two field lists that differ only in where a boundary falls, or in an empty field, digest differently.
	if Digest([]byte("ab"), []byte("c")) == Digest([]byte("a"), []byte("bc")) || Digest([]byte("a")) == Digest([]byte("a"), nil) {
		t.Fatal("the length prefixes do not separate the fields")
	}
}

// BenchmarkDigest shows what hashing in place saves: no allocation of the fields' total size.
func BenchmarkDigest(b *testing.B) {
	payload := make([]byte, 1<<20)
	enc := make([]byte, EncLen)
	b.Run("in place", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for b.Loop() {
			_ = Digest(enc, payload, nil, nil)
		}
	})
	b.Run("copied", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for b.Loop() {
			_ = copiedDigest(enc, payload, nil, nil)
		}
	})
}
