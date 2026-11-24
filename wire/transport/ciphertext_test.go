package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func salt(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, CiphertextSaltLen)
	if _, err := rand.Read(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// versioned is a format-4 ciphertext of a plaintext of n bytes (random bytes for nonce, ciphertext and tag).
func versioned(t *testing.T, id string, n int) []byte {
	t.Helper()
	h, err := AppendVersionedHeader(Release(), nil, id, salt(t))
	if err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, CiphertextNonceLen+n+CiphertextTagLen)
	_, _ = rand.Read(tail)
	return append(h, tail...)
}

func TestCiphertextConstants(t *testing.T) {
	if TenantKeyHeaderLen != 53 || TenantKeyOverhead != 81 ||
		VersionedMinOverhead != 67 || VersionedMaxOverhead != 98 || VersionedHeaderLen("v2") != 40 ||
		VersionedOverhead("v2") != 68 || VersionedOverhead(strings.Repeat("v", 32)) != VersionedMaxOverhead {
		t.Fatal("the formats' lengths are not the specified ones")
	}
}

// TestFormat4Layout: the header is "CPH1" | 4 | len | id | salt — the salt right after the id, nothing between
// them — and parses back.
func TestFormat4Layout(t *testing.T) {
	s := salt(t)
	h, err := AppendVersionedHeader(Release(), nil, "v2", s)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("CPH1\x04\x02v2"), s...)
	if !bytes.Equal(h, want) || len(h) != VersionedHeaderLen("v2") {
		t.Fatalf("header %x", h)
	}
	for _, id := range []string{"v2", "legacy", "2026-12", strings.Repeat("Z", 32), "a"} {
		ct := versioned(t, id, 5)
		k, err := ParseKeyID(Release(), ct)
		if err != nil || k.Format != FormatVersioned || k.MasterVersion != id || k.TenantKeyID != nil ||
			k.HeaderLen != VersionedHeaderLen(id) || len(ct) != VersionedOverhead(id)+5 {
			t.Fatalf("%q: %+v, %v", id, k, err)
		}
		// The key's name is the master version id alone.
		if k.String() != id {
			t.Fatalf("String %q, not %q", k.String(), id)
		}
	}
	for name, err := range map[string]error{
		"no id":        func() error { _, err := AppendVersionedHeader(Release(), nil, "", s); return err }(),
		"a long id":    func() error { _, err := AppendVersionedHeader(Release(), nil, strings.Repeat("v", 33), s); return err }(),
		"a bad id":     func() error { _, err := AppendVersionedHeader(Release(), nil, "v|2", s); return err }(),
		"a slash":      func() error { _, err := AppendVersionedHeader(Release(), nil, "v/2", s); return err }(),
		"a short salt": func() error { _, err := AppendVersionedHeader(Release(), nil, "v2", s[:31]); return err }(),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestFormat4IsUnambiguous: no two version ids share a header under one salt, however the bytes could be split —
// an id that is a prefix of another included.
func TestFormat4IsUnambiguous(t *testing.T) {
	s := salt(t)
	seen := map[string]string{}
	for _, id := range []string{"a", "ab", "abc", "b", "v1", "v12", "v2", "legacy", strings.Repeat("a", 32)} {
		h, err := AppendVersionedHeader(Release(), nil, id, s)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[string(h)]; dup {
			t.Fatalf("%s and %s share a header", id, prev)
		}
		seen[string(h)] = id
	}
}

// TestParseKeyIDRefuses: every truncation below a format's overhead, every other magic or format, and every
// malformed version id is ErrCiphertext; the overhead itself (an empty plaintext) is accepted.
func TestParseKeyIDRefuses(t *testing.T) {
	// Format 2 (a header of magic, format and salt, no key named) is not a format: refused as an unknown one.
	format2 := append(append([]byte("CPH1\x02"), salt(t)...), make([]byte, CiphertextNonceLen+CiphertextTagLen)...)
	tenant := append(append(append([]byte("CPH1\x03"), bytes.Repeat([]byte{9}, 16)...), salt(t)...),
		make([]byte, CiphertextNonceLen+CiphertextTagLen)...)
	v4 := versioned(t, "v2", 0)
	for name, ct := range map[string][]byte{"format 3": tenant, "format 4": v4} {
		if _, err := ParseKeyID(Release(), ct); err != nil {
			t.Fatalf("%s at its overhead: %v", name, err)
		}
		for n := 0; n < len(ct); n++ {
			if _, err := ParseKeyID(Release(), ct[:n]); !errors.Is(err, ErrCiphertext) {
				t.Fatalf("%s truncated to %d bytes: %v", name, n, err)
			}
		}
	}
	if k, _ := ParseKeyID(Release(), tenant); !bytes.Equal(k.TenantKeyID, bytes.Repeat([]byte{9}, 16)) || k.String() != "tenant-key:"+strings.Repeat("09", 16) {
		t.Fatalf("%+v", k)
	}
	// The key id is a copy: the caller may keep it without the row.
	k, _ := ParseKeyID(Release(), tenant)
	k.TenantKeyID[0] ^= 1
	if tenant[5] != 9 {
		t.Fatal("TenantKeyID aliases the ciphertext")
	}
	mod := func(b []byte, f func(b []byte)) []byte { c := bytes.Clone(b); f(c); return c }
	long := make([]byte, 200)
	for name, ct := range map[string][]byte{
		"nothing":            nil,
		"another magic":      mod(v4, func(b []byte) { b[3] = '2' }),
		"format 0":           mod(v4, func(b []byte) { b[4] = 0 }),
		"format 1":           mod(v4, func(b []byte) { b[4] = 1 }),
		"format 2":           format2,
		"format 2, longer":   append(bytes.Clone(format2), long...),
		"format 7":           mod(v4, func(b []byte) { b[4] = 7 }),
		"format 255":         mod(v4, func(b []byte) { b[4] = 255 }),
		"a zero-length id":   mod(v4, func(b []byte) { b[5] = 0 }),
		"a 33-byte id":       append(append([]byte("CPH1\x04\x21"), strings.Repeat("v", 33)...), long...),
		"a 255-byte id":      append([]byte("CPH1\x04\xff"), long...),
		"a bad id char":      mod(v4, func(b []byte) { b[7] = '|' }),
		"a NUL in the id":    mod(v4, func(b []byte) { b[6] = 0 }),
		"an id over the end": []byte("CPH1\x04\x09v2"),
		"zeros":              make([]byte, 100),
		"a CPT1 blob":        append([]byte("CPT1\x02"), long...),
	} {
		if _, err := ParseKeyID(Release(), ct); !errors.Is(err, ErrCiphertext) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The right magic and a format this protocol does not have is ErrCiphertextFormat, still ErrCiphertext; a wrong
	// magic, a known format's malformed header or a truncation is not.
	if !errors.Is(ErrCiphertextFormat, ErrCiphertext) {
		t.Fatal("ErrCiphertextFormat does not wrap ErrCiphertext")
	}
	for _, f := range []byte{0, 1, 2, 7, 8, 255} {
		if _, err := ParseKeyID(Release(), mod(v4, func(b []byte) { b[4] = f })); !errors.Is(err, ErrCiphertextFormat) || !errors.Is(err, ErrCiphertext) {
			t.Errorf("format %d: %v", f, err)
		}
	}
	for name, ct := range map[string][]byte{
		"nothing":            nil,
		"the magic alone":    []byte("CPH1"),
		"another magic":      mod(v4, func(b []byte) { b[3] = '2' }),
		"a zero-length id":   mod(v4, func(b []byte) { b[5] = 0 }),
		"format 4 truncated": v4[:len(v4)-1],
		"a CPT1 blob":        append([]byte("CPT1\x05"), long...),
	} {
		if _, err := ParseKeyID(Release(), ct); !errors.Is(err, ErrCiphertext) || errors.Is(err, ErrCiphertextFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Random garbage never panics, and is refused unless it happens to carry the magic.
	for i := 0; i < 2000; i++ {
		g := make([]byte, i%150)
		_, _ = rand.Read(g)
		if i%3 == 0 && len(g) > 5 {
			copy(g, "CPH1")
			g[4] = byte(2 + i%3)
		}
		k, err := ParseKeyID(Release(), g)
		if err == nil && (string(g[:4]) != CiphertextMagic || k.HeaderLen > len(g)) {
			t.Fatalf("garbage %x parsed as %+v", g, k)
		}
	}
}
