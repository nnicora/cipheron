package format

import (
	"encoding/binary"
	"fmt"
	"iter"
	"slices"
)

// Rule is one kind's rule of a Policy: the versions read (Kind.Reads) and one writer per slot (Rule.Writes).
type Rule struct {
	kind   *kindBase
	reads  []uint32
	writes []slotWrite
}

type slotWrite struct {
	slot    Slot
	version uint32
}

// Writes is r with version v written for slot s.
func (r Rule) Writes(s Slot, v uint32) Rule {
	r.reads = slices.Clone(r.reads)
	r.writes = append(slices.Clone(r.writes), slotWrite{s, v})
	return r
}

// Policy is what a release reads and writes of every Kind of its Catalog: per kind, the scheme written for each slot
// and the schemes read (Tink's primary and enabled keys). NewPolicy validates it once; it never changes. Every reader
// and writer takes one.
//
// It holds its kinds in catalog order, each with the table its own codec type's code built: Write, Marked, Read, Each
// and Bounds find a kind by a linear scan comparing one pointer per kind, then make one type assertion that cannot
// fail (the table of a kind was built by that kind's code).
type Policy struct {
	catalog *Catalog
	rules   []Rule
	kinds   []policyKind
}

type policyKind struct {
	kind  *kindBase
	table table
}

// table is a *kindTable[C].
type table interface {
	add(s anyScheme, read bool)
	setWriter(slot Slot, s anyScheme)
	finish()
	infos(yield func(SchemeInfo) bool) bool
}

// kindTable is one kind's schemes under a Policy.
type kindTable[C any] struct {
	// byByte are a Stored kind's schemes read, by version byte.
	byByte [256]*Scheme[C]
	// read are the schemes read in ascending order; each in Each's order: slot 0's writer first.
	read, each []*Scheme[C]
	// writers are the schemes written, by slot.
	writers []*Scheme[C]
	// the bounds over the schemes read (Bounds).
	minHeader, maxOverhead, maxItem int
}

func (t *kindTable[C]) add(s anyScheme, read bool) {
	if !read {
		return
	}
	sc, ok := s.(*Scheme[C])
	if !ok {
		panic(fmt.Sprintf("format: a %T in a kind table of %T", s, sc))
	}
	t.read = append(t.read, sc)
	if sc.d.kind.form == Stored {
		t.byByte[sc.d.version] = sc
	}
}

func (t *kindTable[C]) setWriter(slot Slot, s anyScheme) {
	sc, ok := s.(*Scheme[C])
	if !ok {
		panic(fmt.Sprintf("format: a %T in a kind table of %T", s, sc))
	}
	for int(slot) >= len(t.writers) {
		t.writers = append(t.writers, nil)
	}
	t.writers[slot] = sc
}

func (t *kindTable[C]) finish() {
	slices.SortFunc(t.read, func(a, b *Scheme[C]) int { return compare(a.d.version, b.d.version) })
	w := t.writers[0]
	t.each = append(t.each, w)
	for _, s := range t.read {
		if s != w {
			t.each = append(t.each, s)
		}
	}
	for _, s := range t.read {
		if t.minHeader == 0 || s.d.minHeader < t.minHeader {
			t.minHeader = s.d.minHeader
		}
		t.maxOverhead = max(t.maxOverhead, s.d.maxHeader+s.d.suite.Overhead())
		t.maxItem = max(t.maxItem, s.d.maxItem)
	}
}

func (t *kindTable[C]) infos(yield func(SchemeInfo) bool) bool {
	for _, s := range t.read {
		d := &s.d
		written := int(d.slot) < len(t.writers) && t.writers[d.slot] == s
		info := SchemeInfo{Kind: d.kind.name, Form: d.kind.form, Version: d.version, Name: d.name, Slot: d.slot,
			Written: written, Marker: d.marker, Suite: d.suite, KeyName: d.keyName,
			Layout: Layout{Fields: slices.Clone(d.layout.Fields), Plaintext: d.layout.Plaintext}}
		if !yield(info) {
			return false
		}
	}
	return true
}

// NewPolicy validates rules against c: exactly one rule per kind c has and none for a kind it lacks; every version read
// is a scheme of c and none is read twice; for each slot of the kind (the slots its schemes in c are declared for)
// exactly one version written, of a scheme declared for that slot; every version written is read. A refusal names the
// first fault.
func NewPolicy(c *Catalog, rules ...Rule) (*Policy, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: a policy of no catalog", errRegistry)
	}
	byKind := map[*kindBase]Rule{}
	for _, r := range rules {
		if r.kind == nil {
			return nil, fmt.Errorf("%w: a rule of no kind", errRegistry)
		}
		if _, dup := byKind[r.kind]; dup {
			return nil, fmt.Errorf("%w: two rules for the %s kind", errRegistry, r.kind.name)
		}
		if c.kind(r.kind) == nil {
			return nil, fmt.Errorf("%w: a rule for the %s kind, which the catalog does not have", errRegistry, r.kind.name)
		}
		byKind[r.kind] = r
	}
	p := &Policy{catalog: c}
	for i := range c.kinds {
		ck := &c.kinds[i]
		k := ck.kind
		r, ok := byKind[k]
		if !ok {
			return nil, fmt.Errorf("%w: the policy has no rule for the %s kind", errRegistry, k.name)
		}
		read := map[uint32]bool{}
		for _, v := range r.reads {
			if read[v] {
				return nil, fmt.Errorf("%w: the %s kind reads version %d twice", errRegistry, k.name, v)
			}
			if ck.scheme(v) == nil {
				return nil, fmt.Errorf("%w: the %s kind reads version %d, which is no scheme of the catalog", errRegistry,
					k.name, v)
			}
			read[v] = true
		}
		slots := map[Slot]bool{}
		for _, s := range ck.schemes {
			slots[s.decl().slot] = true
		}
		written := map[Slot]anyScheme{}
		for _, w := range r.writes {
			s := ck.scheme(w.version)
			switch {
			case !slots[w.slot]:
				return nil, fmt.Errorf("%w: the %s kind has no slot %d", errRegistry, k.name, w.slot)
			case written[w.slot] != nil:
				return nil, fmt.Errorf("%w: %s: the %s kind writes %s for slot %d already", errRegistry,
					versionName(s, w.version), k.name, written[w.slot].decl().name, w.slot)
			case s == nil:
				return nil, fmt.Errorf("%w: the %s kind writes version %d, which is no scheme of the catalog", errRegistry,
					k.name, w.version)
			case s.decl().slot != w.slot:
				return nil, fmt.Errorf("%w: %s of the %s kind is written for slot %d, not %d", errRegistry, s.decl().name,
					k.name, s.decl().slot, w.slot)
			case !read[w.version]:
				return nil, fmt.Errorf("%w: the %s kind writes version %d, which it does not read", errRegistry, k.name,
					w.version)
			}
			written[w.slot] = s
		}
		for s := range slots {
			if written[s] == nil {
				return nil, fmt.Errorf("%w: the %s kind writes nothing for slot %d", errRegistry, k.name, s)
			}
		}
		t := k.newTable()
		for _, s := range ck.schemes {
			t.add(s, read[s.decl().version])
		}
		for slot, s := range written {
			t.setWriter(slot, s)
		}
		t.finish()
		p.kinds = append(p.kinds, policyKind{kind: k, table: t})
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func versionName(s anyScheme, v uint32) string {
	if s == nil {
		return fmt.Sprintf("version %d", v)
	}
	return s.decl().name
}

// kind is c's kind k; nil when c lacks it.
func (c *Catalog) kind(k *kindBase) *catalogKind {
	for i := range c.kinds {
		if c.kinds[i].kind == k {
			return &c.kinds[i]
		}
	}
	return nil
}

// scheme is the kind's scheme of version v; nil when it has none.
func (ck *catalogKind) scheme(v uint32) anyScheme {
	for _, s := range ck.schemes {
		if s.decl().version == v {
			return s
		}
	}
	return nil
}

// With is p over its catalog and schemes, validated as one Catalog, with rules in place of p's rules of their kinds and
// added for kinds p has none of; validated as NewPolicy validates. cipheron's release is the protocol's with the keyset
// file this way; a test adds its version this way.
func (p *Policy) With(schemes []Entry, rules ...Rule) (*Policy, error) {
	c, err := NewCatalog(append(slices.Clone(p.catalog.entries), schemes...)...)
	if err != nil {
		return nil, err
	}
	rs := slices.Clone(p.rules)
	for _, r := range rules {
		i := slices.IndexFunc(rs, func(o Rule) bool { return o.kind == r.kind })
		if i >= 0 {
			rs[i] = r
		} else {
			rs = append(rs, r)
		}
	}
	return NewPolicy(c, rs...)
}

// tableOf is p's table of k. A kind p does not have is a programming error: it panics, naming the kind.
func tableOf[C any](p *Policy, k *Kind[C]) *kindTable[C] {
	for i := range p.kinds {
		if p.kinds[i].kind == &k.b {
			t, _ := p.kinds[i].table.(*kindTable[C]) // built by k's own code: the assertion cannot fail
			return t
		}
	}
	panic(fmt.Sprintf("format: the policy has no %s kind", k.b.name))
}

// Write is the scheme p writes for slot s of k. A kind p does not have, or a slot k does not have, is a programming
// error: it panics, naming the kind and the slot.
func Write[C any](p *Policy, k *Kind[C], s Slot) *Scheme[C] {
	t := tableOf(p, k)
	if int(s) >= len(t.writers) || t.writers[s] == nil {
		panic(fmt.Sprintf("format: the %s kind has no slot %d", k.b.name, s))
	}
	return t.writers[s]
}

// Marked is the scheme p reads for item, a Stored, Prefixed or Tokened kind's, by its marker: k's refuse for an item no
// scheme read marks, k's unknown for a Stored kind's magic and a byte p reads no scheme of. It allocates nothing but a
// refusal's error. A kind of another form, or one p does not have, panics.
func Marked[C any](p *Policy, k *Kind[C], item []byte) (*Scheme[C], error) {
	t := tableOf(p, k)
	b := &k.b
	switch b.form {
	case Stored:
		// Every stored item is read here, so the magic is compared with one load when item has 8 bytes or more, and
		// byte for byte when it is shorter.
		m := len(b.magic)
		if len(item) >= 8 && binary.LittleEndian.Uint64(item)&b.mask == b.word ||
			len(item) < 8 && len(item) >= m && string(item[:m]) == b.magic {
			if len(item) > m {
				if s := t.byByte[item[m]]; s != nil {
					return s, nil
				}
				return nil, b.unknown(uint32(item[m]), t.writers[0].d.version)
			}
		}
		return nil, b.refuse
	case Prefixed:
		for _, s := range t.read {
			if len(item) >= len(s.d.marker) && string(item[:len(s.d.marker)]) == s.d.marker {
				return s, nil
			}
		}
		return nil, b.refuse
	case Tokened:
		for _, s := range t.read {
			if string(item) == s.d.marker {
				return s, nil
			}
		}
		return nil, b.refuse
	}
	panic(fmt.Sprintf("format: Marked serves no %s kind (%s)", b.form, b.name))
}

// Read is the scheme of k at version v that p reads; k's unknown otherwise (a Prefixed or Tokened kind: its refuse).
func Read[C any](p *Policy, k *Kind[C], v uint32) (*Scheme[C], error) {
	t := tableOf(p, k)
	if k.b.form == Stored {
		if v < 256 && t.byByte[v] != nil {
			return t.byByte[v], nil
		}
	} else {
		for _, s := range t.read {
			if s.d.version == v {
				return s, nil
			}
		}
	}
	if k.b.form == Prefixed || k.b.form == Tokened {
		return nil, k.b.refuse
	}
	return nil, k.b.unknown(v, t.writers[0].d.version)
}

// Each yields every scheme of k that p reads: the one written for slot 0 first, then the others in ascending order. It
// is how an Unmarked kind is read: a verifier rebuilds a transcript under each until one verifies.
func Each[C any](p *Policy, k *Kind[C]) iter.Seq[*Scheme[C]] {
	t := tableOf(p, k)
	return func(yield func(*Scheme[C]) bool) {
		for _, s := range t.each {
			if !yield(s) {
				return
			}
		}
	}
}

// Bounds are what a reader of a Stored kind needs before it knows an item's scheme, over the schemes p reads: the
// shortest header, the most an item adds to its plaintext (header and suite overhead) and the longest item any scheme
// bounds (0: none). Computed once by NewPolicy.
func Bounds[C any](p *Policy, k *Kind[C]) (minHeader, maxOverhead, maxItem int) {
	t := tableOf(p, k)
	return t.minHeader, t.maxOverhead, t.maxItem
}

// Schemes yields what p reads, kind by kind in catalog order, each kind's versions ascending: a read-only copy for the
// docs, the conformance kit and the release record, which do not hold the kinds.
func (p *Policy) Schemes() iter.Seq[SchemeInfo] {
	return func(yield func(SchemeInfo) bool) {
		for _, k := range p.kinds {
			if !k.table.infos(yield) {
				return
			}
		}
	}
}

// SchemeInfo is one scheme p reads, as Policy.Schemes describes it. A copy: changing it changes nothing.
type SchemeInfo struct {
	Kind    string // the kind's name ("ciphertext")
	Form    Form
	Version uint32
	Name    string // the scheme's name ("format 4")
	Slot    Slot
	Written bool   // p writes this scheme for Slot
	Marker  string // as Scheme.Marker
	Suite   Suite  // the zero Suite for an Unsealed kind
	KeyName string // as SealedBy named it; "" for an Unsealed kind
	Layout  Layout // a Stored scheme's; the zero Layout otherwise (Fields a copy)
}
