package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/nnicora/cipheron/wire/transport"
)

// TestJSONPointers: RFC 6901's escapes, the whole document refused, array indices without leading zeros, and the
// pointers of one call neither repeated nor nested.
func TestJSONPointers(t *testing.T) {
	for p, want := range map[string][]string{"/a": {"a"}, "/a~1b/~0c": {"a/b", "~c"}, "/": {""}, "/x/0": {"x", "0"}} {
		if got, err := parsePointer(p); err != nil || !slices.Equal(got, want) {
			t.Errorf("parsePointer(%q) = %q, %v", p, got, err)
		}
	}
	for _, p := range []string{"", "a", "/a~", "/a~2"} {
		if _, err := parsePointer(p); !errors.Is(err, transport.ErrJSONField) {
			t.Errorf("parsePointer(%q): %v", p, err)
		}
	}
	doc := map[string]any{"a": []any{"x", "y"}}
	for _, tok := range []string{"01", "-", "2", "-1", ""} {
		if _, _, ok := locate(doc, []string{"a", tok}); ok {
			t.Errorf("array index %q accepted", tok)
		}
	}
	if v, _, ok := locate(doc, []string{"a", "1"}); !ok || v != "y" {
		t.Fatalf("/a/1 = %v %v", v, ok)
	}
	for _, ps := range [][]string{{"/a", "/a"}, {"/a", "/a/b"}, {"/a/b", "/a"}, {}} {
		if _, err := checkPointers(ps); !errors.Is(err, transport.ErrJSONField) {
			t.Errorf("checkPointers(%q): %v", ps, err)
		}
	}
	if _, err := checkPointers([]string{"/a", "/ab"}); err != nil {
		t.Fatalf("siblings sharing a prefix: %v", err)
	}
}

// TestStreamReading: a streaming reader allocates nothing for a segment longer than the header allows, and an object
// that ends early is ErrSegmented.
func TestStreamReading(t *testing.T) {
	h := transport.SegmentedHeader{ObjectID: make([]byte, transport.ObjectIDLen), SegmentSize: transport.MinSegmentSize, Count: 2}
	b, err := transport.AppendSegmentedHeader(transport.Release(), nil, h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := transport.ReadSegmentedHeader(transport.Release(), bytes.NewReader(b))
	if err != nil || got.Count != 2 || got.SegmentSize != transport.MinSegmentSize {
		t.Fatalf("header: %+v %v", got, err)
	}
	if _, err := transport.ReadSegmentedHeader(transport.Release(), bytes.NewReader(b[:10])); !errors.Is(err, transport.ErrSegmented) {
		t.Fatalf("a short header: %v", err)
	}
	huge := binary.BigEndian.AppendUint32(nil, transport.MinSegmentSize+transport.MaxSegmentOverhead+1)
	if _, err := transport.ReadSegment(bytes.NewReader(huge), h); !errors.Is(err, transport.ErrSegmented) {
		t.Fatalf("an oversized segment length: %v", err)
	}
	short := transport.AppendSegment(nil, []byte("abc"))
	if _, err := transport.ReadSegment(bytes.NewReader(short[:5]), h); !errors.Is(err, transport.ErrSegmented) {
		t.Fatalf("a segment cut short: %v", err)
	}
	if s, err := transport.ReadSegment(bytes.NewReader(short), h); err != nil || string(s) != "abc" {
		t.Fatalf("a segment: %q %v", s, err)
	}
}
