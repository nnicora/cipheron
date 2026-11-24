package transport

// waved_bench_test.go — Wave D (deep review 2026-11-12, P13) micro-benchmarks: the per-request transcripts and seal
// info, a segment's associated data, an HTTP body read sized from Content-Length against io.ReadAll, and the HPKE
// parts behind the owner decisions D-F and D-G.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
)

func BenchmarkPerRequestTranscripts(b *testing.B) {
	nonce, sig := bytes.Repeat([]byte{1}, NonceLen), bytes.Repeat([]byte{2}, ed25519.SignatureSize)
	var d [sha256.Size]byte
	pub := ed25519.PublicKey(bytes.Repeat([]byte{3}, ed25519.PublicKeySize))
	id := bytes.Repeat([]byte{4}, ObjectIDLen)
	b.ReportAllocs()
	for b.Loop() {
		_ = RequestTranscript(Release(), "credentials", OpEncrypt, 1, nonce, d)
		_ = ResponseTranscript(Release(), "credentials", "sha256:"+strings.Repeat("0", 64), OpEncrypt, nonce, sig, d, d)
		_ = RequestSealInfo(Release(), "credentials", OpEncrypt, "t_acme", pub)
		_ = SegmentAssociatedData(id, 7, false, []byte("row 1"))
	}
}

func BenchmarkHTTPBody64KiB(b *testing.B) {
	body := bytes.Repeat([]byte{'j'}, 64<<10)
	b.Run("io.ReadAll", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = io.ReadAll(io.LimitReader(bytes.NewReader(body), 1<<20+1))
		}
	})
	b.Run("ReadHTTPBody", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = ReadHTTPBody(bytes.NewReader(body), int64(len(body)), 1<<20)
		}
	})
}

// BenchmarkHPKEPerItem breaks one batch item's HPKE work into its parts — what the owner decisions D-F and D-G
// would change (measured only; neither is implemented):
//
//   - parse: KEM().NewPrivateKey from the locked bytes, which cipheron does per request (D-F: an unwipeable
//     ecdh.PrivateKey copy on the heap each time; caching one parsed key would save this, at the cost of one
//     long-lived heap copy);
//   - open: NewRecipient (the KEM decapsulation: an ECDH) and the AEAD open — the server's per-item cost;
//   - seal: NewSender (an encapsulation: key generation and an ECDH) and the AEAD seal — the client's per-item cost;
//   - context seal/open: one more message under an EXISTING context — what an item would cost with one HPKE context
//     per batch (D-G: RFC 9180 multi-message, the item index in the AAD; a new transcript version).
func BenchmarkHPKEPerItem(b *testing.B) {
	sk, err := NewOneTimeKey()
	if err != nil {
		b.Fatal(err)
	}
	skb, err := sk.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.PublicKey()
	info, pt := []byte("cipheron/v1|request|credentials|encrypt"), bytes.Repeat([]byte{1}, 1024)
	enc, ct, err := Seal(pk, info, pt)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("parse", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = KEM().NewPrivateKey(skb)
		}
	})
	b.Run("open", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = Open(sk, info, enc, ct)
		}
	})
	b.Run("seal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _, _ = Seal(pk, info, pt)
		}
	})
	b.Run("context seal+open", func(b *testing.B) {
		e, s, err := hpke.NewSender(pk, KDF(), AEAD(), info)
		if err != nil {
			b.Fatal(err)
		}
		r, err := hpke.NewRecipient(e, sk, KDF(), AEAD(), info)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			c, _ := s.Seal(nil, pt)
			if _, err := r.Open(nil, c); err != nil {
				b.Fatal(err)
			}
		}
	})
}
