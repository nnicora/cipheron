package format

import "fmt"

// Entry is one scheme declaration as NewCatalog takes it. Only Kind.Scheme makes one.
type Entry interface {
	// newScheme is the scheme the entry declares, a new copy each call.
	newScheme() anyScheme
}

// Option is what a scheme declares beside its version, name and codec. Only SealedBy, Marker and ForSlot make one.
type Option struct {
	what  optKind
	suite Suite
	text  string
	slot  Slot
}

type optKind uint8

const (
	optSuite optKind = iota + 1
	optMarker
	optSlot
)

// SealedBy is the suite a scheme of a Sealed kind seals its items under, and the name of the key an item is made under
// in a refusal of a key of another length ("data key", "storage key", "tenant-wrapping key", "master key").
func SealedBy(s Suite, keyName string) Option { return Option{what: optSuite, suite: s, text: keyName} }

// Marker is the bytes every item of a Prefixed scheme opens with ("cipheron:v1:"), or a Tokened scheme's token
// ("cipheron-key-statement/1"). A Stored scheme's marker is its kind's magic and its version byte: never declared.
func Marker(m string) Option { return Option{what: optMarker, text: m} }

// ForSlot is the slot a scheme is written for, when it is written (a Policy decides that). The default is 0.
func ForSlot(s Slot) Option { return Option{what: optSlot, slot: s} }

// declaration is a scheme's declaration, whatever its codec type.
type declaration struct {
	kind      *kindBase
	version   uint32
	name      string
	slot      Slot
	suite     Suite
	keyName   string
	sealedBy  bool
	marker    string
	hasMarker bool
	// codecNil reports the nil interface value as the codec (refused); layoutOK a codec that declares its Layout.
	codecNil, layoutOK bool
	// layout and the bounds are a Stored scheme's, computed by NewCatalog.
	layout               Layout
	minHeader, maxHeader int
	maxItem              int
	fieldsMin, fieldsMax int
}

// entry is Kind.Scheme's Entry: a copy of the declaration and the codec.
type entry[C any] struct {
	d     declaration
	codec C
}

func (e entry[C]) newScheme() anyScheme {
	s := &Scheme[C]{d: e.d, codec: e.codec}
	s.d.codecNil = any(e.codec) == nil
	if !s.d.codecNil {
		if lc, ok := any(e.codec).(interface{ Layout() Layout }); ok {
			l := lc.Layout()
			s.d.layout = Layout{Fields: append([]Field(nil), l.Fields...), Plaintext: l.Plaintext}
			s.d.layoutOK = true
		}
	}
	return s
}

// anyScheme is a *Scheme[C] of any codec type.
type anyScheme interface {
	decl() *declaration
}

// Scheme is one scheme of a Catalog: a read-only view of its declaration. Nothing changes it.
type Scheme[C any] struct {
	d     declaration
	codec C
}

func (s *Scheme[C]) decl() *declaration { return &s.d }

// Version is the scheme's version.
func (s *Scheme[C]) Version() uint32 { return s.d.version }

// Name is the scheme's name.
func (s *Scheme[C]) Name() string { return s.d.name }

// Slot is the slot the scheme is written for.
func (s *Scheme[C]) Slot() Slot { return s.d.slot }

// Suite is the scheme's suite; the zero Suite for an Unsealed kind.
func (s *Scheme[C]) Suite() Suite { return s.d.suite }

// Codec is the scheme's codec.
func (s *Scheme[C]) Codec() C { return s.codec }

// Marker is the bytes every item of the scheme opens with (a Stored scheme's magic and version byte, a Prefixed
// scheme's prefix), or a Tokened scheme's token; "" for a Numbered or Unmarked scheme.
func (s *Scheme[C]) Marker() string { return s.d.marker }

// Bounds are a Stored scheme's shortest and longest header (marker, fields and salt) and its longest whole item (0:
// none), computed from its codec's Layout and its suite; all 0 for any other form.
func (s *Scheme[C]) Bounds() (minHeader, maxHeader, maxItem int) {
	return s.d.minHeader, s.d.maxHeader, s.d.maxItem
}

// ItemKey derives the own key of one item of the scheme from key, the key the item is made under, over info. It
// refuses a scheme without a suite, a key that is not the suite's length ("cipheron: the <key name> is <n> bytes, not
// <m>") and an info outside the suite's namespace ("cipheron: a label outside the namespace %q of the suite <name>")
// before anything is derived. key is only read.
func (s *Scheme[C]) ItemKey(key []byte, info string) (ItemKey, error) {
	if s.d.suite.s == nil {
		return ItemKey{}, fmt.Errorf("%w: %s of the %s kind has no suite", errRegistry, s.d.name, s.d.kind.name)
	}
	return s.d.suite.itemKey(key, s.d.keyName, info)
}

// Codec is a Stored scheme's fields: what follows the marker and precedes the salt. The framework writes and checks
// the marker, the salt (the suite's SaltLen) and the sealed tail (the suite's Overhead, and the Layout's Plaintext); a
// codec sees and writes its fields only.
type Codec[H any] interface {
	// Layout declares the fields, in order, and the sealed plaintext's length when it is fixed. Bounds, the docs and
	// the conformance cases are computed from it.
	Layout() Layout
	// Size is the length of the fields holding h.
	Size(h H) int
	// Append appends the fields holding h to dst. It checks every field before it writes anything, and refuses a
	// field Parse would refuse.
	Append(dst []byte, h H) ([]byte, error)
	// Parse reads the fields at the start of b (b begins after the marker): what they hold and their length. It
	// refuses (false) fields that do not fit in b or are not valid; what it returns may hold sub-slices of b.
	Parse(b []byte) (h H, n int, ok bool)
}

// Layout is a Stored scheme's fields and, for a kind whose plaintext has one fixed length, that length.
type Layout struct {
	// Fields are the fields after the marker, in order; the salt is not one of them.
	Fields []Field
	// Plaintext is the exact length of the sealed plaintext (a tenant key blob: 96); 0: any length.
	Plaintext int
}

// Field is one header field: Name (as the docs name it), and its length: Min to Max bytes, behind a length of Prefix
// bytes (0: none; 1: one length byte; 4: a 4-byte big-endian length). A fixed field has Min == Max and Prefix 0.
type Field struct {
	Name     string
	Prefix   int
	Min, Max int
}

// validateLayout checks a Stored scheme's Layout and computes its bounds and its marker.
func (d *declaration) validateLayout() error {
	switch {
	case !d.layoutOK:
		return fmt.Errorf("%w: %s: a stored scheme's codec declares its Layout", errRegistry, d.name)
	case len(d.layout.Fields) == 0:
		return fmt.Errorf("%w: %s: a stored scheme has a field", errRegistry, d.name)
	case d.layout.Plaintext < 0 || d.layout.Plaintext > 0 && d.kind.sealing != Sealed:
		return fmt.Errorf("%w: %s: a fixed plaintext length is a sealed kind's, and not negative", errRegistry, d.name)
	}
	for _, f := range d.layout.Fields {
		limit := 1 << 24
		switch f.Prefix {
		case 0:
		case 1:
			limit = 255
		case 4:
		default:
			return fmt.Errorf("%w: %s: the field %q has a length of %d bytes: 0, 1 or 4", errRegistry, d.name, f.Name,
				f.Prefix)
		}
		if f.Name == "" || f.Min < 1 || f.Min > f.Max || f.Max > limit {
			return fmt.Errorf("%w: %s: the field %q is a name and 1 <= Min <= Max <= %d bytes", errRegistry, d.name,
				f.Name, limit)
		}
		d.fieldsMin += f.Prefix + f.Min
		d.fieldsMax += f.Prefix + f.Max
	}
	d.marker = d.kind.magic + string([]byte{byte(d.version)})
	salt := d.suite.SaltLen()
	d.minHeader = len(d.marker) + d.fieldsMin + salt
	d.maxHeader = len(d.marker) + d.fieldsMax + salt
	if d.layout.Plaintext > 0 {
		d.maxItem = d.maxHeader + d.suite.Overhead() + d.layout.Plaintext
	}
	return nil
}

// AppendHeader appends the header of an item of s holding h to dst: the marker, the fields (s's codec), then salt (nil:
// the salt's length in zero bytes, for the writer to fill). It refuses what the codec refuses, writing nothing to dst
// or to its spare capacity; and it refuses, as a programming error, a codec whose appended fields are not Size(h)
// bytes or fall outside its Layout's bounds, and a salt that is not the suite's length. One allocation at most: it
// grows dst once to the header's length.
func AppendHeader[H any, C Codec[H]](s *Scheme[C], dst []byte, h H, salt []byte) ([]byte, error) {
	if s.d.kind.form != Stored {
		return nil, fmt.Errorf("%w: %s: AppendHeader serves a stored kind", errRegistry, s.d.name)
	}
	saltLen := s.d.suite.SaltLen()
	if salt != nil && len(salt) != saltLen {
		return nil, fmt.Errorf("%w: %s: a salt of %d bytes, not %d", errRegistry, s.d.name, len(salt), saltLen)
	}
	m := len(s.d.marker)
	size := s.codec.Size(h)
	start := len(dst)
	if need := m + size + saltLen; cap(dst)-start < need {
		grown := make([]byte, start, start+need)
		copy(grown, dst)
		dst = grown
	}
	out, err := s.codec.Append(dst[:start+m], h)
	if err != nil {
		return nil, err
	}
	n := len(out) - start - m
	if n != size || n < s.d.fieldsMin || n > s.d.fieldsMax || &out[0] != &dst[:1][0] {
		return nil, fmt.Errorf("%w: %s: the codec appended %d bytes of fields, not Size %d within %d to %d", errRegistry,
			s.d.name, n, size, s.d.fieldsMin, s.d.fieldsMax)
	}
	copy(out[start:], s.d.marker)
	if salt == nil {
		clear(out[len(out):][:saltLen])
		return out[:len(out)+saltLen], nil
	}
	return append(out, salt...), nil
}

// ParseHeader reads the header of an item of s at the start of item into *h and returns its length (marker, fields
// and salt). It refuses (false) an item longer than s's longest item, one that does not open with s's marker, fields
// the codec refuses, and a tail the frame does not allow: shorter than the suite's Overhead (a Sealed kind), or other
// than Overhead + Plaintext bytes (a fixed plaintext). An Unsealed kind's tail is its owner's.
func ParseHeader[H any, C Codec[H]](s *Scheme[C], item []byte, h *H) (n int, ok bool) {
	d := &s.d
	m := len(d.marker)
	if d.kind.form != Stored || d.maxItem > 0 && len(item) > d.maxItem || len(item) < m || string(item[:m]) != d.marker {
		return 0, false
	}
	got, fields, ok := s.codec.Parse(item[m:])
	if !ok || fields < 0 || fields > len(item)-m {
		return 0, false
	}
	n = m + fields + d.suite.SaltLen()
	if n > len(item) {
		return 0, false
	}
	if d.kind.sealing == Sealed {
		tail := len(item) - n
		if tail < d.suite.Overhead() || d.layout.Plaintext > 0 && tail != d.suite.Overhead()+d.layout.Plaintext {
			return 0, false
		}
	}
	*h = got
	return n, true
}
