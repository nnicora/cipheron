package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestJSONFieldAssociatedData pins a field's associated data byte for byte (a reader in another language makes the
// same) and the value encoding.
func TestJSONFieldAssociatedData(t *testing.T) {
	lp := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	var want []byte
	for _, f := range [][]byte{[]byte("cipheron/v1|json-field"), []byte("r-1"), []byte("/card/number"), []byte("aad")} {
		want = append(want, lp(f)...)
	}
	if got := JSONFieldAssociatedData("r-1", "/card/number", []byte("aad")); !bytes.Equal(got, want) {
		t.Fatalf("associated data %x, want %x", got, want)
	}
	if bytes.Equal(JSONFieldAssociatedData("r-1", "/a", nil), JSONFieldAssociatedData("r-1/", "a", nil)) {
		t.Fatal("record id and pointer are not separated")
	}
	v := EncodeJSONField(Release(), []byte{1, 2, 3})
	if v != "cipheron:v1:AQID" {
		t.Fatalf("encoded %q", v)
	}
	if ct, err := DecodeJSONField(Release(), v); err != nil || !bytes.Equal(ct, []byte{1, 2, 3}) {
		t.Fatalf("decoded %x %v", ct, err)
	}
	for _, bad := range []string{"AQID", "cipheron:v1:", "cipheron:v1:AQI", "cipheron:v1:!!!!", "cipheron:v2:AQID"} {
		if _, err := DecodeJSONField(Release(), bad); !errors.Is(err, ErrJSONField) {
			t.Errorf("DecodeJSONField(%q): %v", bad, err)
		}
	}
}
