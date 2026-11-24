package format

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"strings"
	"testing"
)

// TestNewCatalogRefuses: one row per refusal of a malformed declaration, each wrapping errRegistry with its words.
func TestNewCatalogRefuses(t *testing.T) {
	t.Parallel()
	s1, s2 := testSuiteOf("a"), testSuiteOf("a") // two suites of one namespace
	sealed := newTestStored("sealed", "SEA1", Sealed)
	open := newTestStored("open", "OPN1", Unsealed)
	pre := NewKind[int]("prefixed", Prefixed, Unsealed, errTestRefuse, nil)
	tok := NewKind[int]("tokened", Tokened, Unsealed, errTestRefuse, nil)
	num := NewKind[int]("numbered", Numbered, Unsealed, nil, testUnknown)
	ok := sealed.Scheme(1, "v1", fieldsV1{}, SealedBy(s1, "a key"))
	for _, c := range []struct {
		name    string
		entries []Entry
		want    string
	}{
		{"a kind with no name", []Entry{NewKind[int]("", Numbered, Unsealed, nil, testUnknown).Scheme(1, "v1", 1)}, "a kind is a name"},
		{"a magic of 9 bytes", []Entry{newTestStored("x", "123456789", Unsealed).Scheme(1, "v1", fieldsV1{})}, "a kind is a name"},
		{"a magic with a space", []Entry{newTestStored("x", "A B", Unsealed).Scheme(1, "v1", fieldsV1{})}, "a kind is a name"},
		{"a stored kind with no refusal", []Entry{NewStoredKind[testCodec]("x", "X", Unsealed, nil, testUnknown).Scheme(1, "v1", fieldsV1{})}, "a kind is a name"},
		{"a numbered kind with no unknown", []Entry{NewKind[int]("x", Numbered, Unsealed, nil, nil).Scheme(1, "v1", 1)}, "a kind is a name"},
		{"a form outside Form", []Entry{NewKind[int]("x", Form(9), Unsealed, errTestRefuse, testUnknown).Scheme(1, "v1", 1)}, "a kind is a name"},
		{"two kinds of one name", []Entry{ok, newTestStored("sealed", "OTH1", Unsealed).Scheme(1, "v1", fieldsV1{})}, `two kinds are named "sealed"`},
		{"a magic begun by another", []Entry{ok, newTestStored("y", "SEA", Unsealed).Scheme(1, "v1", fieldsV1{})}, `the magic "SEA" is the sealed kind's "SEA1"`},
		{"a magic beginning another", []Entry{ok, newTestStored("y", "SEA12", Unsealed).Scheme(1, "v1", fieldsV1{})}, `the magic "SEA12" is the sealed kind's "SEA1"`},
		{"a nil codec", []Entry{sealed.Scheme(1, "v1", nil, SealedBy(s1, "k"))}, "a scheme has a name and a codec"},
		{"no name", []Entry{sealed.Scheme(1, "", fieldsV1{}, SealedBy(s1, "k"))}, "a scheme has a name and a codec"},
		{"two schemes of one version", []Entry{ok, sealed.Scheme(1, "again", fieldsV1{}, SealedBy(s1, "k"))}, "has a scheme of version 1 already: v1"},
		{"a stored version above 255", []Entry{sealed.Scheme(256, "v256", fieldsV1{}, SealedBy(s1, "k"))}, "a stored scheme's version is a byte"},
		{"a sealed scheme without a suite", []Entry{sealed.Scheme(1, "v1", fieldsV1{})}, "is sealed and has no suite"},
		{"a sealed scheme with the zero suite", []Entry{sealed.Scheme(1, "v1", fieldsV1{}, SealedBy(Suite{}, "k"))}, "is sealed and has no suite"},
		{"a sealed scheme without a key name", []Entry{sealed.Scheme(1, "v1", fieldsV1{}, SealedBy(s1, ""))}, "has a suite and no name for its key"},
		{"an unsealed scheme with a suite", []Entry{open.Scheme(1, "v1", fieldsV1{}, SealedBy(s1, "k"))}, "is not sealed and has a suite"},
		{"an unsealed scheme with the zero suite", []Entry{open.Scheme(1, "v1", fieldsV1{}, SealedBy(Suite{}, "k"))}, "is not sealed and has a suite"},
		{"a prefixed scheme without a marker", []Entry{pre.Scheme(1, "v1", 1)}, "has no marker"},
		{"a marker on a numbered scheme", []Entry{num.Scheme(1, "v1", 1, Marker("x"))}, "it declares no marker"},
		{"a marker on a stored scheme", []Entry{open.Scheme(1, "v1", fieldsV1{}, Marker("x"))}, "it declares no marker"},
		{"a prefix that begins another", []Entry{pre.Scheme(1, "v1", 1, Marker("p:v1:")), pre.Scheme(2, "v2", 1, Marker("p:v1:x"))}, "begins v1's"},
		{"two equal tokens", []Entry{tok.Scheme(1, "v1", 1, Marker("t/1")), tok.Scheme(2, "v2", 1, Marker("t/1"))}, `the token "t/1" is v1's`},
		{"a shared namespace", []Entry{ok, sealed.Scheme(2, "v2", fieldsV1{}, SealedBy(s2, "k"))}, `the label namespace "cipheron-test/a/v1|" is suite test a's`},
		{"a stored codec without a Layout", []Entry{NewStoredKind[int]("x", "X", Unsealed, errTestRefuse, testUnknown).Scheme(1, "v1", 1)}, "declares its Layout"},
		{"no field", []Entry{NewStoredKind[layoutCodec]("x", "X", Unsealed, errTestRefuse, testUnknown).Scheme(1, "v1", layoutCodec{})}, "a stored scheme has a field"},
		{"a field without a name", []Entry{layoutOf(Field{Min: 1, Max: 1})}, "is a name and 1 <= Min <= Max"},
		{"Min 0", []Entry{layoutOf(Field{Name: "f", Min: 0, Max: 1})}, "is a name and 1 <= Min <= Max"},
		{"Min above Max", []Entry{layoutOf(Field{Name: "f", Min: 2, Max: 1})}, "is a name and 1 <= Min <= Max"},
		{"Max above 255 behind 1", []Entry{layoutOf(Field{Name: "f", Prefix: 1, Min: 1, Max: 256})}, "<= 255 bytes"},
		{"a prefix of 2", []Entry{layoutOf(Field{Name: "f", Prefix: 2, Min: 1, Max: 2})}, "0, 1 or 4"},
		{"a plaintext on an unsealed kind", []Entry{NewStoredKind[layoutCodec]("x", "X", Unsealed, errTestRefuse, testUnknown).Scheme(1, "v1", layoutCodec{Layout{Fields: []Field{{Name: "f", Min: 1, Max: 1}}, Plaintext: 4}})}, "a fixed plaintext length is a sealed kind's"},
		{"a nil entry", []Entry{nil}, "a nil entry"},
	} {
		if _, err := NewCatalog(c.entries...); err == nil || !errors.Is(err, errRegistry) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want %q", c.name, err, c.want)
		}
	}
	if _, err := NewCatalog(ok, open.Scheme(1, "v1", fieldsV1{}), pre.Scheme(1, "v1", 1, Marker("p:v1:")),
		pre.Scheme(2, "v2", 1, Marker("p:v2:")), tok.Scheme(1, "v1", 1, Marker("t/1")), num.Scheme(7, "v7", 7)); err != nil {
		t.Fatalf("a valid catalog: %v", err)
	}
}

// layoutCodec is a stored codec of any Layout, for the Layout refusals.
type layoutCodec struct{ l Layout }

func (c layoutCodec) Layout() Layout                         { return c.l }
func (layoutCodec) Size(int) int                             { return 0 }
func (layoutCodec) Append(dst []byte, _ int) ([]byte, error) { return dst, nil }
func (layoutCodec) Parse([]byte) (int, int, bool)            { return 0, 0, false }

func layoutOf(f Field) Entry {
	return NewStoredKind[layoutCodec]("x", "X", Unsealed, errTestRefuse, testUnknown).Scheme(1, "v1",
		layoutCodec{Layout{Fields: []Field{f}}})
}

// TestACatalogIsACopy: changing a codec's variable or an option after Kind.Scheme, or a SchemeInfo's Layout, changes
// nothing a Catalog or Policy answers.
func TestACatalogIsACopy(t *testing.T) {
	t.Parallel()
	k := NewStoredKind[*fieldsV1]("k", "CPY1", Sealed, errTestRefuse, testUnknown)
	codec, suite := &fieldsV1{}, testSuiteOf("copy")
	opts := []Option{SealedBy(suite, "a key")}
	e := k.Scheme(1, "v1", codec, opts...)
	opts[0] = SealedBy(testSuiteOf("other"), "another key")
	c, err := NewCatalog(e)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(c, k.Reads(1).Writes(0, 1))
	if err != nil {
		t.Fatal(err)
	}
	codec.extra = 9
	w := Write(p, k, 0)
	if w.Suite() != suite || w.Codec().extra != 9 { // the pointer is the caller's: a value codec is the copy
		t.Fatalf("the scheme's suite changed: %s", w.Suite().Name())
	}
	for i := range p.Schemes() {
		i.Layout.Fields[0].Name = "changed"
		i.Layout.Fields = nil
	}
	for i := range p.Schemes() {
		if len(i.Layout.Fields) != 3 || i.Layout.Fields[0].Name != "a" || i.KeyName != "a key" || !i.Written {
			t.Fatalf("a SchemeInfo is not a copy: %+v", i)
		}
	}
}

// TestNewPolicyRefuses: one row per rule of a policy.
func TestNewPolicyRefuses(t *testing.T) {
	t.Parallel()
	s := testSuiteOf("policy")
	k := newTestStored("k", "POL1", Sealed)
	two := newTestStored("two", "POL2", Unsealed)
	c, err := NewCatalog(k.Scheme(1, "v1", fieldsV1{}, SealedBy(s, "key")), k.Scheme(2, "v2", fieldsV1{}, SealedBy(s, "key")),
		k.Scheme(3, "v3", fieldsV1{}, SealedBy(s, "key"), ForSlot(1)), two.Scheme(1, "v1", fieldsV1{}))
	if err != nil {
		t.Fatal(err)
	}
	other := newTestStored("other", "OTH1", Unsealed)
	twoRule := two.Reads(1).Writes(0, 1)
	for _, c2 := range []struct {
		name  string
		rules []Rule
		want  string
	}{
		{"no rule for a kind", []Rule{k.Reads(1, 3).Writes(0, 1).Writes(1, 3)}, "no rule for the two kind"},
		{"a rule of no kind", []Rule{{}, twoRule}, "a rule of no kind"},
		{"two rules for a kind", []Rule{twoRule, twoRule}, "two rules for the two kind"},
		{"a rule for a kind the catalog lacks", []Rule{other.Reads(1).Writes(0, 1)}, "which the catalog does not have"},
		{"a version read twice", []Rule{k.Reads(1, 1, 3).Writes(0, 1).Writes(1, 3), twoRule}, "reads version 1 twice"},
		{"a version read of no scheme", []Rule{k.Reads(1, 3, 4).Writes(0, 1).Writes(1, 3), twoRule}, "reads version 4, which is no scheme"},
		{"a slot written twice", []Rule{k.Reads(1, 2, 3).Writes(0, 1).Writes(0, 2).Writes(1, 3), twoRule}, "writes v1 for slot 0 already"},
		{"a slot not written", []Rule{k.Reads(1, 3).Writes(0, 1), twoRule}, "writes nothing for slot 1"},
		{"a slot the kind lacks", []Rule{k.Reads(1, 3).Writes(0, 1).Writes(1, 3).Writes(2, 1), twoRule}, "has no slot 2"},
		{"a version written for another slot", []Rule{k.Reads(1, 3).Writes(0, 3).Writes(1, 3), twoRule}, "is written for slot 1, not 0"},
		{"a version written not read", []Rule{k.Reads(1, 3).Writes(0, 2).Writes(1, 3), twoRule}, "writes version 2, which it does not read"},
		{"a version written of no scheme", []Rule{k.Reads(1, 3).Writes(0, 9).Writes(1, 3), twoRule}, "writes version 9, which is no scheme"},
	} {
		if _, err := NewPolicy(c, c2.rules...); err == nil || !errors.Is(err, errRegistry) || !strings.Contains(err.Error(), c2.want) {
			t.Errorf("%s: %v; want %q", c2.name, err, c2.want)
		}
	}
	p, err := NewPolicy(c, k.Reads(3, 1, 2).Writes(1, 3).Writes(0, 2), twoRule)
	if err != nil {
		t.Fatal(err)
	}
	// Each: the slot-0 writer first, then the others ascending.
	var order []uint32
	for s := range Each(p, k) {
		order = append(order, s.Version())
	}
	if len(order) != 3 || order[0] != 2 || order[1] != 1 || order[2] != 3 {
		t.Fatalf("Each's order: %v", order)
	}
	// With replaces a kind's rule (never appends a second) and adds a kind.
	q, err := p.With(nil, k.Reads(1, 3).Writes(0, 1).Writes(1, 3))
	if err != nil || Write(q, k, 0).Version() != 1 {
		t.Fatalf("With: %v", err)
	}
	if _, err := Read(q, k, 2); !errors.Is(err, errTestUnknown) {
		t.Fatalf("version 2 after With dropped it: %v", err)
	}
}

// TestCheck: the lifecycle's order as a pure function of two policies, over every combination of two releases of a
// kind with up to three versions and two slots: readers first, the writer last, readers removed last.
func TestCheck(t *testing.T) {
	t.Parallel()
	s := testSuiteOf("check")
	k := newTestStored("k", "CHK1", Sealed)
	var entries []Entry
	for v := uint32(1); v <= 3; v++ {
		entries = append(entries, k.Scheme(v, "v", fieldsV1{}, SealedBy(s, "key")), k.Scheme(v+10, "w", fieldsV1{},
			SealedBy(s, "key"), ForSlot(1)))
	}
	c, err := NewCatalog(entries...)
	if err != nil {
		t.Fatal(err)
	}
	type rel struct {
		reads  []uint32
		w0, w1 uint32
	}
	var rels []rel
	for mask := 1; mask < 8; mask++ {
		var reads []uint32
		for v := uint32(1); v <= 3; v++ {
			if mask&(1<<(v-1)) != 0 {
				reads = append(reads, v, v+10)
			}
		}
		for _, w := range reads {
			if w <= 3 {
				rels = append(rels, rel{reads, w, w + 10})
			}
		}
	}
	policy := func(r rel) *Policy {
		p, err := NewPolicy(c, k.Reads(r.reads...).Writes(0, r.w0).Writes(1, r.w1))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	in := func(v uint32, vs []uint32) bool {
		for _, x := range vs {
			if x == v {
				return true
			}
		}
		return false
	}
	n := 0
	for _, a := range rels {
		for _, b := range rels {
			n++
			want := in(b.w0, a.reads) && in(b.w1, a.reads) && in(a.w0, b.reads) && in(a.w1, b.reads)
			err := Check(policy(a), policy(b))
			if (err == nil) != want || err != nil && !errors.Is(err, errLifecycle) {
				t.Fatalf("%+v -> %+v: %v; allowed %v", a, b, err, want)
			}
		}
	}
	if n < 100 {
		t.Fatalf("%d combinations", n)
	}
	// A kind removed is refused; a kind added is allowed.
	two := newTestStored("two", "CHK2", Unsealed)
	c2, _ := NewCatalog(append(entries, two.Scheme(1, "v1", fieldsV1{}))...)
	both, err := NewPolicy(c2, k.Reads(1, 11).Writes(0, 1).Writes(1, 11), two.Reads(1).Writes(0, 1))
	if err != nil {
		t.Fatal(err)
	}
	one := policy(rel{[]uint32{1, 11}, 1, 11})
	if err := Check(one, both); err != nil {
		t.Fatalf("a kind added: %v", err)
	}
	if err := Check(both, one); err == nil || !strings.Contains(err.Error(), "the two kind is not in the next release") {
		t.Fatalf("a kind removed: %v", err)
	}
}

// TestMarked: a stored kind's scheme by its magic — of any length from 1 to 8 bytes, compared with one load when the
// item holds 8 bytes or more — and the byte after it, and nothing after that byte; every item shorter than the magic
// and a byte, or differing from the magic in any one byte, is the kind's refusal, and its magic with a byte no scheme
// read has its unknown refusal. Each answer is checked against the plain comparison. Prefixes and tokens likewise.
func TestMarked(t *testing.T) {
	const v = 0x5A
	for n := 1; n <= 8; n++ {
		magic := string(rune('j'+n)) + "!#%&*+-"[:n-1]
		k := newTestStored("k", magic, Unsealed)
		c, err := NewCatalog(k.Scheme(v, "v", fieldsV1{}), k.Scheme(v+1, "w", fieldsV1{}))
		if err != nil {
			t.Fatal(err)
		}
		p, err := NewPolicy(c, k.Reads(v).Writes(0, v))
		if err != nil {
			t.Fatal(err)
		}
		want := func(item []byte) error {
			switch {
			case len(item) <= n || string(item[:n]) != magic:
				return errTestRefuse
			case item[n] != v:
				return errTestUnknown
			}
			return nil
		}
		for tail := 0; tail <= 12; tail++ {
			item := append(append([]byte(magic), v), bytes.Repeat([]byte{0xC3}, tail)...)
			items := [][]byte{}
			for cut := 0; cut <= len(item); cut++ {
				items = append(items, item[:cut])
			}
			for i := 0; i <= n; i++ {
				bad := bytes.Clone(item)
				bad[i] ^= 0x20
				items = append(items, bad)
			}
			for _, it := range items {
				s, err := Marked(p, k, it)
				if w := want(it); err != w || (w == nil) != (s != nil) { //nolint:errorlint // the very value
					t.Fatalf("magic %q, item %q: %v, %v; want %v", magic, it, s, err, w)
				}
			}
		}
		if allocs := testing.AllocsPerRun(50, func() { _, _ = Marked(p, k, []byte(magic+"Z0123456")) }); allocs != 0 {
			t.Fatalf("Marked allocates %v times", allocs)
		}
	}
	pre := NewKind[int]("prefixed", Prefixed, Unsealed, errTestRefuse, nil)
	tok := NewKind[int]("tokened", Tokened, Unsealed, errTestRefuse, nil)
	c, err := NewCatalog(pre.Scheme(1, "v1", 1, Marker("p:v1:")), tok.Scheme(1, "v1", 1, Marker("t/1")))
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(c, pre.Reads(1).Writes(0, 1), tok.Reads(1).Writes(0, 1))
	if err != nil {
		t.Fatal(err)
	}
	for item, ok := range map[string]bool{"p:v1:": true, "p:v1:x": true, "p:v1": false, "p:v01:x": false, "": false} {
		if s, err := Marked(p, pre, []byte(item)); ok != (s != nil) || !ok && err != errTestRefuse { //nolint:errorlint // the very value
			t.Errorf("prefix %q: %v", item, err)
		}
	}
	for item, ok := range map[string]bool{"t/1": true, "t/10": false, "t/": false, "t/1 ": false} {
		if s, err := Marked(p, tok, []byte(item)); ok != (s != nil) || !ok && err != errTestRefuse { //nolint:errorlint // the very value
			t.Errorf("token %q: %v", item, err)
		}
	}
	if _, err := Read(p, tok, 2); err != errTestRefuse { //nolint:errorlint // the very value
		t.Errorf("a token version not read: %v", err)
	}
}

// TestItemKeyOpenZeroes: an in-place open that fails leaves no unauthenticated plaintext — of an AEAD that writes its
// plaintext before it checks the tag — and an open into a buffer of its own zeroes what it wrote.
func TestItemKeyOpenZeroes(t *testing.T) {
	t.Parallel()
	k := ItemKey{aead: leaky{}}
	body := bytes.Repeat([]byte{0x42}, 40)
	if _, ok := k.Open(body[:0], body, nil); ok || !bytes.Equal(body, make([]byte, 40)) {
		t.Fatalf("in place: %x", body)
	}
	dst := make([]byte, 3, 64)
	if _, ok := k.Open(dst, bytes.Repeat([]byte{0x42}, 40), nil); ok || !bytes.Equal(dst[:3+40], make([]byte, 43)) {
		t.Fatalf("into a buffer: %x", dst[:43])
	}
}

// leaky is an AEAD that writes the body as its plaintext, then fails.
type leaky struct{}

func (leaky) NonceSize() int                  { return 0 }
func (leaky) Overhead() int                   { return 0 }
func (leaky) Seal(dst, _, p, _ []byte) []byte { return append(dst, p...) }
func (leaky) Open(dst, _, c, _ []byte) ([]byte, error) {
	_ = append(dst, bytes.Repeat([]byte{0x99}, len(c))...)
	return nil, errors.New("tag")
}

var _ cipher.AEAD = leaky{}
