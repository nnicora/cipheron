package transport

// layout_fuzz_test.go — fuzz tests of every stored layout's header codec: the ciphertext formats' two headers (a
// tenant key id, a master version id), the tenant key blob's and the segmented object's. Whatever the bytes: no
// panic; a refusal is the family's (ErrCiphertext and ErrCiphertextFormat, ErrTenantKey, ErrSegmented); what parses
// is written back byte for byte by the layout's own append (the header is consumed exactly); and the ciphertexts'
// parser agrees with specParseKeyID, the formats' layout written out independently of the registry.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron/wire/format"
)

// fuzzKeyIDSeeds are a ciphertext of every format, at its overhead and longer, and near misses.
func fuzzKeyIDSeeds(f *testing.F) {
	f.Helper()
	salt := bytes.Repeat([]byte{0x5a}, CiphertextSaltLen)
	tail := make([]byte, CiphertextNonceLen+CiphertextTagLen)
	for _, format := range []byte{FormatVersioned, FormatVersionedAAD} {
		h, err := AppendVersionedHeaderFormat(Release(), nil, format, "v1", salt)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(append(bytes.Clone(h), tail...))
		f.Add(append(append(bytes.Clone(h), tail...), "plaintext"...))
		f.Add(h)
	}
	for _, format := range []byte{FormatTenantKey, FormatTenantKeyAAD} {
		ct := append(append(append([]byte(CiphertextMagic), format), bytes.Repeat([]byte{7}, TenantKeyIDLen)...), salt...)
		f.Add(append(ct, tail...))
		f.Add(ct)
	}
	f.Add([]byte("CPH1\x02"))
	f.Add([]byte("CPH1\x04\x20" + strings.Repeat("v", 32)))
	f.Add([]byte("CPT1\x01"))
	f.Add([]byte{})
}

// specKeyID is ParseKeyID's result written out from the formats' specification (ciphertext.go's table), without the
// registry: the magic, then format 3 or 6 (a 16-byte key id and the salt, at least 81 bytes in all) or format 4 or 5
// (a length byte of 1 to 32, that many bytes of [A-Za-z0-9._-], the salt, then at least the nonce and the tag).
// unknown reports the magic with another format byte.
func specParseKeyID(ct []byte) (k KeyID, ok, unknown bool) {
	if len(ct) < 5 || string(ct[:4]) != "CPH1" {
		return KeyID{}, false, false
	}
	switch f := ct[4]; f {
	case 3, 6:
		if len(ct) < 5+16+32+12+16 {
			return KeyID{}, false, false
		}
		return KeyID{Format: f, AssociatedData: f == 6, TenantKeyID: bytes.Clone(ct[5:21]), HeaderLen: 53}, true, false
	case 4, 5:
		if len(ct) < 6 {
			return KeyID{}, false, false
		}
		n := int(ct[5])
		if n < 1 || n > 32 || len(ct) < 6+n+32+12+16 {
			return KeyID{}, false, false
		}
		for _, c := range ct[6 : 6+n] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return KeyID{}, false, false
			}
		}
		return KeyID{Format: f, AssociatedData: f == 5, MasterVersion: string(ct[6 : 6+n]), HeaderLen: 6 + n + 32}, true, false
	}
	return KeyID{}, false, true
}

// FuzzParseKeyID: the formats 3 to 6 — both ciphertext header codecs — against the specification.
func FuzzParseKeyID(f *testing.F) {
	fuzzKeyIDSeeds(f)
	f.Fuzz(func(t *testing.T, ct []byte) {
		k, err := ParseKeyID(Release(), ct)
		want, ok, unknown := specParseKeyID(ct)
		switch {
		case !ok && err == nil:
			t.Fatalf("%x parsed as %+v; the specification refuses it", ct, k)
		case ok && err != nil:
			t.Fatalf("%x refused (%v); the specification reads %+v", ct, err, want)
		case err != nil:
			if !errors.Is(err, ErrCiphertext) || errors.Is(err, ErrCiphertextFormat) != unknown {
				t.Fatalf("%x: refused as %v (an unknown format: %v)", ct, err, unknown)
			}
			return
		}
		if k.Format != want.Format || k.AssociatedData != want.AssociatedData || k.MasterVersion != want.MasterVersion ||
			!bytes.Equal(k.TenantKeyID, want.TenantKeyID) || k.HeaderLen != want.HeaderLen {
			t.Fatalf("%x: %+v, the specification reads %+v", ct, k, want)
		}
		s, err := format.Marked(Release(), ciphertexts, ct)
		if err != nil || s.Version() != uint32(k.Format) || k.Overhead() != k.HeaderLen+CiphertextNonceLen+CiphertextTagLen ||
			k.Versioned() != (s.Codec().names() == NamesMasterVersion) || k.TenantKey() != (s.Codec().names() == NamesTenantKey) {
			t.Fatalf("%x: the scheme %v, %v", ct, s, err)
		}
		// Consumed exactly: the scheme writes the header it read, salt and all.
		back, err := format.AppendHeader(s, nil, k, ct[k.HeaderLen-CiphertextSaltLen:k.HeaderLen])
		if err != nil || !bytes.Equal(back, ct[:k.HeaderLen]) {
			t.Fatalf("%x: the header written back is %x, %v", ct, back, err)
		}
	})
}

// FuzzAppendCiphertextHeader: what a ciphertext layout writes, it reads back — any version id, key id and salt,
// accepted or refused alike by both sides.
func FuzzAppendCiphertextHeader(f *testing.F) {
	f.Add(FormatVersioned, "v1", []byte("0123456789abcdef"), bytes.Repeat([]byte{1}, 32))
	f.Add(FormatTenantKeyAAD, "", bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 32))
	f.Add(FormatVersionedAAD, strings.Repeat("Z", 33), []byte{}, []byte{1})
	f.Add(byte(9), "v|1", []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, f byte, version string, keyID, salt []byte) {
		s, err := format.Read(Release(), ciphertexts, uint32(f))
		if err != nil || len(salt) != CiphertextSaltLen {
			return
		}
		h, err := format.AppendHeader(s, nil, KeyID{MasterVersion: version, TenantKeyID: keyID}, salt)
		if err != nil {
			return
		}
		ct := append(bytes.Clone(h), make([]byte, CiphertextNonceLen+CiphertextTagLen)...)
		k, err := ParseKeyID(Release(), ct)
		if err != nil || k.Format != f || k.HeaderLen != len(h) || !bytes.Equal(ct[k.HeaderLen-CiphertextSaltLen:k.HeaderLen], salt) ||
			(s.Codec().names() == NamesMasterVersion && k.MasterVersion != version) ||
			(s.Codec().names() == NamesTenantKey && !bytes.Equal(k.TenantKeyID, keyID)) {
			t.Fatalf("format %d %q %x: wrote %x, read %+v, %v", f, version, keyID, h, k, err)
		}
	})
}

// fuzzBlob is a valid blob for the seeds: what AppendTenantKeyHeader writes, which ParseTenantKey reads back.
func fuzzBlob(f *testing.F) []byte {
	f.Helper()
	pub := ed25519.PublicKey(bytes.Repeat([]byte{4}, ed25519.PublicKeySize))
	h, err := AppendTenantKeyHeader(Release(), nil, &TenantKeyHeader{Version: TenantKeyVersion, KeyID: bytes.Repeat([]byte{1}, 16),
		Profile: "docs", Tenant: "t_1", SigningPublicKey: pub, WrappingVersion: "v1", Created: time.Unix(1_800_000_000, 0),
		Salt: bytes.Repeat([]byte{2}, TenantKeySaltLen)})
	if err != nil {
		f.Fatal(err)
	}
	blob := append(h, make([]byte, TenantSealedLen)...)
	if p, err := ParseTenantKey(Release(), blob); err != nil || p.Profile != "docs" || p.Tenant != "t_1" || p.WrappingVersion != "v1" {
		f.Fatalf("the blob AppendTenantKeyHeader wrote does not read back: %+v, %v", p, err)
	}
	return blob
}

// FuzzAppendTenantKeyHeader: what the tenant key blob's layout writes, it reads back — any key id, profile, tenant,
// public key, wrapping version, creation time and salt, accepted or refused alike by both sides.
func FuzzAppendTenantKeyHeader(f *testing.F) {
	f.Add(byte(TenantKeyVersion), bytes.Repeat([]byte{1}, 16), "docs", "t_1", bytes.Repeat([]byte{4}, 32), "v1",
		int64(1_800_000_000), bytes.Repeat([]byte{2}, 32))
	f.Add(byte(2), []byte{}, "Docs", "a b", []byte{}, "v|1", int64(0), []byte{})
	f.Fuzz(func(t *testing.T, v byte, keyID []byte, profile, tenant string, pub []byte, wrapping string, created int64,
		salt []byte,
	) {
		in := &TenantKeyHeader{Version: v, KeyID: keyID, Profile: profile, Tenant: tenant, SigningPublicKey: pub,
			WrappingVersion: wrapping, Created: time.Unix(created, 0), Salt: salt}
		h, err := AppendTenantKeyHeader(Release(), nil, in)
		if err != nil {
			return
		}
		got, err := ParseTenantKey(Release(), append(bytes.Clone(h), make([]byte, TenantSealedLen)...))
		if err != nil || got.Version != v || !bytes.Equal(got.KeyID, keyID) || got.Profile != profile || got.Tenant != tenant ||
			!bytes.Equal(got.SigningPublicKey, pub) || got.WrappingVersion != wrapping || got.Created.Unix() != created ||
			!bytes.Equal(got.Salt, salt) || !bytes.Equal(got.AAD, h) {
			t.Fatalf("%+v: wrote %x, read %+v, %v", in, h, got, err)
		}
	})
}

// FuzzParseTenantKey: the tenant key blob's codec. What parses is the header it holds written back byte for byte,
// then exactly the sealed part; anything else is ErrTenantKey.
func FuzzParseTenantKey(f *testing.F) {
	blob := fuzzBlob(f)
	f.Add(blob)
	f.Add(blob[:len(blob)-1])
	f.Add(append(bytes.Clone(blob), 0))
	f.Add([]byte("CPT1\x02"))
	f.Add([]byte("CPH1\x01"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseTenantKey(Release(), b)
		if err != nil {
			if !errors.Is(err, ErrTenantKey) {
				t.Fatalf("%x: refused as %v", b, err)
			}
			return
		}
		if len(h.Sealed) != TenantSealedLen || len(h.AAD)+len(h.Sealed) != len(b) || !bytes.Equal(h.AAD, b[:len(h.AAD)]) ||
			h.Version != b[4] || h.Version != TenantKeyVersion {
			t.Fatalf("%x: %+v", b, h)
		}
		back, err := AppendTenantKeyHeader(Release(), nil, h)
		if err != nil || !bytes.Equal(back, h.AAD) {
			t.Fatalf("%x: the header written back is %x, %v", b, back, err)
		}
	})
}

// FuzzParseSegmented: the segmented object's codec and its framing. What parses is written back byte for byte, and
// its header is what ReadSegmentedHeader reads from the same bytes; anything else is ErrSegmented.
func FuzzParseSegmented(f *testing.F) {
	obj, err := MarshalSegmented(Release(), SegmentedHeader{ObjectID: bytes.Repeat([]byte{9}, ObjectIDLen), SegmentSize: MinSegmentSize,
		Count: 2}, [][]byte{[]byte("one"), {}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(obj)
	f.Add(obj[:SegmentedHeaderLen])
	f.Add(append(bytes.Clone(obj), 0))
	f.Add([]byte("CPS1\x02"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, segs, err := ParseSegmented(Release(), b)
		r := bytes.NewReader(b)
		rh, rerr := ReadSegmentedHeader(Release(), r)
		if err != nil {
			if !errors.Is(err, ErrSegmented) {
				t.Fatalf("%x: refused as %v", b, err)
			}
			if rerr != nil && !errors.Is(rerr, ErrSegmented) {
				t.Fatalf("%x: the streamed header refused as %v", b, rerr)
			}
			return
		}
		back, err := MarshalSegmented(Release(), h, segs)
		if err != nil || !bytes.Equal(back, b) || !IsSegmented(Release(), b) {
			t.Fatalf("%x: written back as %x, %v", b, back, err)
		}
		if rerr != nil || !bytes.Equal(rh.ObjectID, h.ObjectID) || rh.SegmentSize != h.SegmentSize || rh.Count != h.Count ||
			r.Len() != len(b)-SegmentedHeaderLen {
			t.Fatalf("%x: the streamed header %+v (%v), %d bytes left", b, rh, rerr, r.Len())
		}
	})
}

// FuzzReadSegmentedHeader: the segmented object's header read from a stream: exactly the header's bytes are read;
// what is read is the header AppendHeader writes; anything else is ErrSegmented.
func FuzzReadSegmentedHeader(f *testing.F) {
	h, err := AppendSegmentedHeader(Release(), nil, SegmentedHeader{ObjectID: bytes.Repeat([]byte{3}, ObjectIDLen),
		SegmentSize: DefaultSegmentSize, Count: 7})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(h)
	f.Add(append(bytes.Clone(h), "segments"...))
	f.Add(h[:len(h)-1])
	f.Add([]byte("CPS1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		got, err := ReadSegmentedHeader(Release(), r)
		if err != nil {
			if !errors.Is(err, ErrSegmented) {
				t.Fatalf("%x: refused as %v", b, err)
			}
			return
		}
		back, err := AppendSegmentedHeader(Release(), nil, got)
		if err != nil || len(b) < SegmentedHeaderLen || !bytes.Equal(back, b[:SegmentedHeaderLen]) ||
			r.Len() != len(b)-SegmentedHeaderLen {
			t.Fatalf("%x: read %+v, written back %x (%v), %d bytes left", b, got, back, err, r.Len())
		}
	})
}
