package transport_test

// release_test.go — the protocol's lifecycle run against the record of the previous release (testdata/release.txt,
// one line per kind: the versions read and the version written for each slot). This release must follow it
// (format.Check: readers first, the writer last, readers removed last), and the record is this release's: a change to
// what the protocol reads or writes is a change to the record, reviewed with it. `go test ./wire/transport -run Release
// -update-release` rewrites it, only once Check passes. That a version's bytes never change is the frozen set's
// (spec/frozen and its readers). cipheron's server keeps its own record, the protocol's kinds and its keyset file.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

var updateRelease = flag.Bool("update-release", false, "rewrite testdata/release.txt from this release, once it follows it")

// recordOf renders p's record: per kind, in catalog order, "<kind> read <v>,<v> write <slot>:<v> ...".
func recordOf(p *format.Policy) string {
	type rule struct {
		reads  []string
		writes []string
	}
	var order []string
	rules := map[string]*rule{}
	for i := range p.Schemes() {
		r := rules[i.Kind]
		if r == nil {
			r = &rule{}
			rules[i.Kind] = r
			order = append(order, i.Kind)
		}
		r.reads = append(r.reads, strconv.FormatUint(uint64(i.Version), 10))
		if i.Written {
			r.writes = append(r.writes, fmt.Sprintf("%d:%d", i.Slot, i.Version))
		}
	}
	var b strings.Builder
	for _, k := range order {
		slices.Sort(rules[k].writes)
		fmt.Fprintf(&b, "%s read %s write %s\n", k, strings.Join(rules[k].reads, ","), strings.Join(rules[k].writes, " "))
	}
	return b.String()
}

// policyOfRecord is the policy a record names: a stub kind of each recorded name (Check reads names, slots and versions
// only), a stub scheme of each version read, written for its slot.
func policyOfRecord(t *testing.T, record string) *format.Policy {
	t.Helper()
	var entries []format.Entry
	var rules []format.Rule
	for _, line := range strings.Split(strings.TrimSpace(record), "\n") {
		name, rest, ok := strings.Cut(line, " read ")
		reads, writes, ok2 := strings.Cut(rest, " write ")
		if !ok || !ok2 {
			t.Fatalf("a record line %q", line)
		}
		k := format.NewKind[int](name, format.Numbered, format.Unsealed, nil,
			func(uint32, uint32) error { return errors.New("not read") })
		slot := map[uint32]format.Slot{}
		var ws [][2]uint32
		for _, w := range strings.Fields(writes) {
			s, v, _ := strings.Cut(w, ":")
			sn, err1 := strconv.ParseUint(s, 10, 8)
			vn, err2 := strconv.ParseUint(v, 10, 32)
			if err1 != nil || err2 != nil {
				t.Fatalf("a record line %q", line)
			}
			slot[uint32(vn)] = format.Slot(sn)
			ws = append(ws, [2]uint32{uint32(sn), uint32(vn)})
		}
		var rs []uint32
		for _, v := range strings.Split(reads, ",") {
			vn, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				t.Fatalf("a record line %q", line)
			}
			rs = append(rs, uint32(vn))
			entries = append(entries, k.Scheme(uint32(vn), v, 0, format.ForSlot(slot[uint32(vn)])))
		}
		r := k.Reads(rs...)
		for _, w := range ws {
			r = r.Writes(format.Slot(w[0]), w[1])
		}
		rules = append(rules, r)
	}
	c, err := format.NewCatalog(entries...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := format.NewPolicy(c, rules...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheReleaseFollowsTheRecordedOne(t *testing.T) {
	const path = "testdata/release.txt"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := format.Check(policyOfRecord(t, string(raw)), transport.Release()); err != nil {
		t.Fatalf("this release may not follow the recorded one: %v", err)
	}
	got := recordOf(transport.Release())
	if *updateRelease {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if got != string(raw) {
		t.Fatalf("this release is not the recorded one (-update-release once it is reviewed):\n%s\nrecorded:\n%s", got, raw)
	}
	// The record's own rendering round-trips: the record names exactly the policy it is read as.
	if recordOf(policyOfRecord(t, string(raw))) != string(raw) {
		t.Fatal("the record does not read back as itself")
	}
}
