package format

import (
	"bytes"
	"errors"
	"testing"
)

// frameOf is a policy of one sealed stored kind of fieldsV1, its suite's salt and overhead, and a fixed plaintext.
func frameOf(tb testing.TB, plaintext int, extra int) (*Policy, *Kind[testCodec]) {
	tb.Helper()
	k := newTestStored("frame", "FRM1", Sealed)
	c, err := NewCatalog(k.Scheme(3, "v3", codecWith{fieldsV1{extra: extra}, plaintext}, SealedBy(testSuiteOf("frame"), "key")))
	if err != nil {
		tb.Fatal(err)
	}
	p, err := NewPolicy(c, k.Reads(3).Writes(0, 3))
	if err != nil {
		tb.Fatal(err)
	}
	return p, k
}

// codecWith is fieldsV1 with a fixed plaintext length.
type codecWith struct {
	fieldsV1

	plaintext int
}

func (c codecWith) Layout() Layout { l := c.fieldsV1.Layout(); l.Plaintext = c.plaintext; return l }

// TestTheFrame: the header is marker || fields || salt; the bounds are computed from the Layout and the suite; every
// truncation, a tail one byte short of the overhead, a fixed plaintext one byte long or short and an item over the
// longest are refused; a codec that appends more than its Size is refused as a programming error; a refusal leaves the
// caller's buffer and its spare capacity as they were.
func TestTheFrame(t *testing.T) {
	t.Parallel()
	p, k := frameOf(t, 5, 0)
	s := Write(p, k, 0)
	h := testHeader{a: []byte("AB"), b: []byte("bee"), c: []byte("sea")}
	salt := bytes.Repeat([]byte{0x5A}, 32)
	head, err := AppendHeader(s, []byte("x"), h, salt)
	want := append([]byte("xFRM1\x03AB\x03bee\x00\x00\x00\x03sea"), salt...)
	if err != nil || !bytes.Equal(head, want) {
		t.Fatalf("the header %q, %v", head, err)
	}
	zero, err := AppendHeader(s, nil, h, nil)
	if err != nil || !bytes.Equal(zero, append(want[1:len(want)-32:len(want)-32], make([]byte, 32)...)) {
		t.Fatalf("the header with a zero salt %q, %v", zero, err)
	}
	if lo, hi, item := s.Bounds(); lo != 5+2+2+5+32 || hi != 5+2+9+304+32 || item != hi+28+5 {
		t.Fatalf("the bounds %d, %d, %d", lo, hi, item)
	}
	if lo, over, item := Bounds(p, k); lo != 46 || over != 352+28 || item != 352+28+5 {
		t.Fatalf("the policy's bounds %d, %d, %d", lo, over, item)
	}
	item := append(bytes.Clone(head[1:]), make([]byte, 28+5)...)
	var got testHeader
	n, ok := ParseHeader(s, item, &got)
	if !ok || n != len(head)-1 || !bytes.Equal(got.c, []byte("sea")) {
		t.Fatalf("parse: %d, %v, %+v", n, ok, got)
	}
	for cut := 0; cut < len(item); cut++ {
		if _, ok := ParseHeader(s, item[:cut], &got); ok {
			t.Fatalf("an item cut at %d parses", cut)
		}
	}
	if _, ok := ParseHeader(s, append(bytes.Clone(item), 0), &got); ok {
		t.Fatal("a plaintext one byte long parses")
	}
	other := bytes.Clone(item)
	other[4] = 4
	if _, ok := ParseHeader(s, other, &got); ok {
		t.Fatal("another version's marker parses as this scheme")
	}
	// A refused field writes nothing, into the buffer or its spare capacity.
	buf := bytes.Repeat([]byte{0xAA}, 64)
	if out, err := AppendHeader(s, buf[:2], testHeader{a: []byte("A")}, salt); out != nil || !errors.Is(err, errTestField) ||
		!bytes.Equal(buf, bytes.Repeat([]byte{0xAA}, 64)) {
		t.Fatalf("a refused field: %x, %v", buf, err)
	}
	if _, err := AppendHeader(s, nil, h, salt[:31]); !errors.Is(err, errRegistry) {
		t.Fatalf("a short salt: %v", err)
	}
	pl, kl := frameOf(t, 5, 1)
	if _, err := AppendHeader(Write(pl, kl, 0), nil, h, nil); !errors.Is(err, errRegistry) {
		t.Fatalf("a codec appending a byte more than its Size: %v", err)
	}
	// An unsealed kind's tail is its owner's: no salt, no tail rule.
	u := newTestStored("open", "OPN1", Unsealed)
	cu, _ := NewCatalog(u.Scheme(1, "v1", fieldsV1{}))
	pu, err := NewPolicy(cu, u.Reads(1).Writes(0, 1))
	if err != nil {
		t.Fatal(err)
	}
	uh, err := AppendHeader(Write(pu, u, 0), nil, h, nil)
	if err != nil || !bytes.Equal(uh, []byte("OPN1\x01AB\x03bee\x00\x00\x00\x03sea")) {
		t.Fatalf("an unsealed header %q, %v", uh, err)
	}
	if n, ok := ParseHeader(Write(pu, u, 0), uh, &got); !ok || n != len(uh) {
		t.Fatalf("an unsealed header parses: %d, %v", n, ok)
	}
}

// FuzzParseHeader: ParseHeader against the plain reading of the frame: a header parses exactly when the bytes open
// with the marker, the codec parses the fields, the salt fits, and the tail is the overhead and the plaintext.
func FuzzParseHeader(f *testing.F) {
	p, k := frameOf(f, 5, 0)
	s := Write(p, k, 0)
	head, _ := AppendHeader(s, nil, testHeader{a: []byte("AB"), b: []byte("b"), c: []byte("c")}, nil)
	f.Add(append(bytes.Clone(head), make([]byte, 33)...))
	f.Add(head)
	f.Add([]byte("FRM1\x03"))
	f.Fuzz(func(t *testing.T, item []byte) {
		var got testHeader
		n, ok := ParseHeader(s, item, &got)
		want := len(item) >= 5 && string(item[:5]) == "FRM1\x03"
		if want {
			_, fields, fok := fieldsV1{}.Parse(item[5:])
			want = fok && len(item) == 5+fields+32+28+5
		}
		if ok != want || ok && n != len(item)-33 {
			t.Fatalf("%x: %d, %v; want %v", item, n, ok, want)
		}
	})
}

// FuzzNewCatalog: no declaration panics NewCatalog; each is accepted or refused.
func FuzzNewCatalog(f *testing.F) {
	f.Add("CPH1", uint32(3), "f", 1, 1, 2, 4, true)
	f.Add("", uint32(300), "", 2, 0, 0, -1, false)
	f.Fuzz(func(t *testing.T, magic string, v uint32, field string, prefix, lo, hi, plaintext int, sealed bool) {
		sealing := Unsealed
		var opts []Option
		if sealed {
			sealing, opts = Sealed, []Option{SealedBy(HKDFSHA256AESGCM(), "key")}
		}
		k := NewStoredKind[layoutCodec]("fuzz", magic, sealing, errTestRefuse, testUnknown)
		_, _ = NewCatalog(k.Scheme(v, "v", layoutCodec{Layout{Fields: []Field{{Name: field, Prefix: prefix, Min: lo,
			Max: hi}}, Plaintext: plaintext}}, opts...))
	})
}
