package cipherontest

// grant_test.go — Grant holds a test to cipheron's configuration rule for caller entries: retenant without export
// fails the test, as cipheron refuses such an entry at load (retenant only widens a cross-profile ReEncrypt out of the
// profile, which export allows, so alone it grants nothing).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/wire/transport"
)

// fatalRecorder is a testing.TB whose Fatalf records its message and returns, so a test can see what the fake refused.
type fatalRecorder struct {
	testing.TB

	fatal []string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatal = append(r.fatal, fmt.Sprintf(format, args...))
}

func TestGrantRefusesRetenantWithoutExport(t *testing.T) {
	s := New(t, "a")
	rec := &fatalRecorder{TB: t}
	s.tb = rec
	for _, ops := range [][]transport.Operation{{transport.OpRetenant}, {transport.OpRetenant, transport.OpImport,
		transport.OpReEncrypt}} {
		rec.fatal = nil
		s.Grant("a", ops...)
		if len(rec.fatal) != 1 || !strings.Contains(rec.fatal[0], "lists retenant but not export") {
			t.Errorf("Grant(%v): %q; want one refusal of retenant without export", ops, rec.fatal)
		}
	}
	for _, ops := range [][]transport.Operation{{transport.OpExport, transport.OpRetenant}, {transport.OpExport},
		{transport.OpImport}, nil} {
		rec.fatal = nil
		s.Grant("a", ops...)
		if len(rec.fatal) != 0 {
			t.Errorf("Grant(%v): %q; want it accepted", ops, rec.fatal)
		}
	}
}
