package transport

// readbody_test.go — Wave D (deep review 2026-11-12, P13): an HTTP body read with its buffer sized once from
// Content-Length reads what io.ReadAll(io.LimitReader(r, limit+1)) reads, whatever the announcement says.

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadHTTPBodyReadsWhatReadAllReads(t *testing.T) {
	const limit = 1000
	for _, n := range []int{0, 1, 511, 999, 1000, 1001, 5000} {
		body := bytes.Repeat([]byte{'j'}, n)
		want, _ := io.ReadAll(io.LimitReader(bytes.NewReader(body), limit+1))
		for _, announced := range []int64{-1, 0, int64(n) - 1, int64(n), int64(n) + 7, limit, limit + 1, 1 << 40} {
			for name, r := range map[string]io.Reader{"whole": bytes.NewReader(body),
				"a byte at a time": iotest.OneByteReader(bytes.NewReader(body))} {
				got, err := ReadHTTPBody(r, announced, limit)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%d bytes announced as %d, %s: %d bytes, %v; want %d", n, announced, name, len(got), err, len(want))
				}
			}
		}
	}
	// An error of the reader is returned, with what was read.
	if _, err := ReadHTTPBody(iotest.ErrReader(io.ErrUnexpectedEOF), 10, limit); err != io.ErrUnexpectedEOF { //nolint:errorlint // identity is the assertion: the reader's error, as ReadAll returns it
		t.Fatalf("a failing reader: %v", err)
	}
	// Sized once: an announced body is read into one buffer.
	body := bytes.Repeat([]byte{'k'}, 64<<10)
	allocs := testing.AllocsPerRun(20, func() {
		if _, err := ReadHTTPBody(bytes.NewReader(body), int64(len(body)), 1<<20); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 3 {
		t.Fatalf("%v allocations reading an announced 64 KiB body; want the buffer once", allocs)
	}
}
