package transport

// layout_bench_test.go — what reading a stored layout's header costs: a ciphertext's key id (formats 3 and 4), a
// tenant key blob's header, a segmented object and its streamed header.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func benchRandom(b *testing.B, n int) []byte {
	b.Helper()
	x := make([]byte, n)
	if _, err := rand.Read(x); err != nil {
		b.Fatal(err)
	}
	return x
}

func BenchmarkParseKeyIDVersioned(b *testing.B) {
	h, err := AppendVersionedHeader(Release(), nil, "v1", benchRandom(b, CiphertextSaltLen))
	if err != nil {
		b.Fatal(err)
	}
	ct := append(h, benchRandom(b, CiphertextNonceLen+1024+CiphertextTagLen)...)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseKeyID(Release(), ct); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseKeyIDTenantKey(b *testing.B) {
	ct := append([]byte(CiphertextMagic), FormatTenantKey)
	ct = append(ct, benchRandom(b, TenantKeyIDLen+CiphertextSaltLen+CiphertextNonceLen+1024+CiphertextTagLen)...)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseKeyID(Release(), ct); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTenantKey(b *testing.B) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	h, err := AppendTenantKeyHeader(Release(), nil, &TenantKeyHeader{Version: TenantKeyVersion, KeyID: benchRandom(b, TenantKeyIDLen),
		Profile: "docs", Tenant: "t_1", SigningPublicKey: pub, WrappingVersion: "v1", Created: time.Unix(1_700_000_000, 0),
		Salt: benchRandom(b, TenantKeySaltLen)})
	if err != nil {
		b.Fatal(err)
	}
	blob := append(h, benchRandom(b, TenantSealedLen)...)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseTenantKey(Release(), blob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseSegmented(b *testing.B) {
	segs := make([][]byte, 16)
	for i := range segs {
		segs[i] = benchRandom(b, 200)
	}
	obj, err := MarshalSegmented(Release(), SegmentedHeader{ObjectID: benchRandom(b, ObjectIDLen), SegmentSize: MinSegmentSize,
		Count: uint32(len(segs))}, segs)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseSegmented(Release(), obj); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadSegmentedHeader(b *testing.B) {
	h, err := AppendSegmentedHeader(Release(), nil,
		SegmentedHeader{ObjectID: benchRandom(b, ObjectIDLen), SegmentSize: MinSegmentSize, Count: 3})
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(h)
	b.ReportAllocs()
	for b.Loop() {
		r.Reset(h)
		if _, err := ReadSegmentedHeader(Release(), r); err != nil {
			b.Fatal(err)
		}
	}
}
