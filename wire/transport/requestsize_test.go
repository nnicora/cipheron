package transport

import (
	"strings"
	"testing"
)

// TestADeclarationIsOneDecimalNumberOfBytes: ParseRequestBytes reads decimal digits with no sign, no space and no
// leading zero, 1 or more, at most an int64; anything else is no declaration cipheron admits.
func TestADeclarationIsOneDecimalNumberOfBytes(t *testing.T) {
	for v, want := range map[string]int64{"1": 1, "9": 9, "1048576": 1 << 20, "16918211": 16918211,
		"9223372036854775807": 1<<63 - 1} {
		if n, ok := ParseRequestBytes(v); !ok || n != want {
			t.Errorf("%q: %d %v, want %d", v, n, ok, want)
		}
	}
	for _, v := range []string{"", "0", "00", "01", "-1", "+1", " 1", "1 ", "1e3", "0x10", "1.0", "1,000", "\xd9\xa1",
		"9223372036854775808", strings.Repeat("9", 20)} {
		if n, ok := ParseRequestBytes(v); ok {
			t.Errorf("%q was read as %d", v, n)
		}
	}
}

// TestHTTPMessageBytesIsTheBodyLimitsInverse: the size an HTTP body declares is the smallest message bound whose body
// limit admits it, so a body is within a listener's bound exactly when its declared size is within maxRequestBytes.
func TestHTTPMessageBytesIsTheBodyLimitsInverse(t *testing.T) {
	check := func(l int64) {
		m := HTTPMessageBytes(l)
		if HTTPBodyLimit(m) < l || (m > 0 && HTTPBodyLimit(m-1) >= l) {
			t.Fatalf("HTTPMessageBytes(%d) = %d: HTTPBodyLimit(%d) = %d, HTTPBodyLimit(%d) = %d", l, m, m,
				HTTPBodyLimit(m), m-1, HTTPBodyLimit(m-1))
		}
	}
	for l := range int64(3 * HTTPJSONHeadroom) {
		check(l)
	}
	for _, l := range []int64{1 << 20, 1<<20 + 1, HTTPBodyLimit(1 << 20), HTTPBodyLimit(1<<20) + 1,
		HTTPBodyLimit(SegmentRequestBytes), 1 << 40} {
		check(l)
	}
	for _, maxRequest := range []int64{1, 1000, 64 << 10, 1 << 20, SegmentRequestBytes, 64 << 20} {
		limit := HTTPBodyLimit(maxRequest)
		for _, l := range []int64{limit - 1, limit, limit + 1} {
			if within := HTTPMessageBytes(l) <= maxRequest; within != (l <= limit) {
				t.Errorf("maxRequest %d: a body of %d declares %d (within: %v)", maxRequest, l, HTTPMessageBytes(l), within)
			}
		}
	}
	if HTTPMessageBytes(0) != 0 || HTTPMessageBytes(HTTPJSONHeadroom) != 0 {
		t.Error("a body within the JSON headroom declares more than 0")
	}
}

// TestTheSegmentRequestSizeIsComputedFromTheFormat: the largest request one segment of MaxSegmentSize travels in — the
// default of cipheron's maxRequestBytes and batch.maxBytes — is the batch's fixed fields, the largest item a segment
// makes (EncryptBatch's is SealedItemBytes) and the framing: 16 MiB and 140 995 bytes.
func TestTheSegmentRequestSizeIsComputedFromTheFormat(t *testing.T) {
	if MaxSegmentSize != 16<<20 {
		t.Fatalf("MaxSegmentSize is %d", MaxSegmentSize)
	}
	enc := SealedItemBytes(MaxSegmentSize, MaxAssociatedDataLen)
	dec := int64(MaxSegmentSize + MaxSegmentOverhead + MaxAssociatedDataLen)
	reenc := int64(MaxSegmentSize + MaxSegmentOverhead + 2*MaxAssociatedDataLen)
	if int64(MaxSegmentItemBytes) != max(enc, dec, reenc) {
		t.Fatalf("MaxSegmentItemBytes %d, want the largest of %d, %d, %d", MaxSegmentItemBytes, enc, dec, reenc)
	}
	if MaxBatchFixedBytes != 2*MaxTenantKeyLen+EncLen {
		t.Fatalf("MaxBatchFixedBytes %d", MaxBatchFixedBytes)
	}
	got, sum := SegmentRequestBytes, int64(MaxBatchFixedBytes+MaxSegmentItemBytes+MaxBatchFraming)
	if got != sum || got != 16918211 {
		t.Fatalf("SegmentRequestBytes %d, want %d and 16918211", got, sum)
	}
	if DefaultBatchMaxBytes != SegmentRequestBytes || DefaultBatchMaxBytes > MaxBatchMaxBytes {
		t.Fatalf("DefaultBatchMaxBytes %d", DefaultBatchMaxBytes)
	}
}
