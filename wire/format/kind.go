package format

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// Slot is one writer of a Kind: a Policy writes exactly one scheme per slot. A kind with one writer has slot 0; a kind
// with several numbers them from 0 and names them (the ciphertext's four, in transport).
type Slot uint8

// Form is how an item of a kind names its scheme.
type Form uint8

const (
	// Stored: every item opens with the kind's magic and one byte, its scheme's version; a scheme's codec is a header
	// Codec (ciphertexts, tenant key blobs, segmented objects). Read by Marked.
	Stored Form = iota + 1
	// Prefixed: every item opens with its scheme's marker (an encrypted JSON field's value). Read by Marked.
	Prefixed
	// Tokened: an item names its scheme by a token equal to the scheme's marker (an exported key statement's
	// "format"). Read by Marked, on the token alone.
	Tokened
	// Numbered: the version is a number in one of the item's fields (a key statement, a keyset file). Read by Read.
	Numbered
	// Unmarked: the version travels in no message; a reader rebuilds the item under each version read (transcripts
	// and seal infos). Read by Each.
	Unmarked
)

// String names the form.
func (f Form) String() string {
	switch f {
	case Stored:
		return "stored"
	case Prefixed:
		return "prefixed"
	case Tokened:
		return "tokened"
	case Numbered:
		return "numbered"
	case Unmarked:
		return "unmarked"
	}
	return fmt.Sprintf("form(%d)", uint8(f))
}

// Sealing is whether a kind's items are sealed under a Suite.
type Sealing uint8

const (
	// Unsealed: no scheme of the kind has a suite (a container, a transcript, a statement).
	Unsealed Sealing = iota
	// Sealed: every scheme of the kind has exactly one suite (SealedBy).
	Sealed
)

// Kind is one kind of versioned item, declared once by the package that owns its bytes. C is the type of its schemes'
// codecs: an interface of the owner's, implemented by one type per version. A Kind is an identity, compared by
// pointer; it holds its declaration and nothing else, and never changes.
type Kind[C any] struct{ b kindBase }

// kindBase is a kind's declaration, whatever its codec type.
type kindBase struct {
	name    string
	form    Form
	sealing Sealing
	magic   string
	// word and mask are the magic as the first 8 bytes of an item read little-endian hold it (a magic is at most 8
	// bytes): Marked compares it with one load.
	word, mask uint64
	refuse     error
	unknown    func(got, written uint32) error
	// newTable makes the kind's lookup table of a Policy: code of the kind's own codec type.
	newTable func() table
}

// NewStoredKind declares a Stored kind: name (its part name in compatibility.md), magic (1 to 8 printable ASCII bytes,
// before the version byte), sealing, refuse (the refusal of an item that is not one of the kind's: shorter than the
// magic and a byte, another magic, a header that does not parse) and unknown (the refusal of the magic with a byte no
// scheme read has; written is the version written for slot 0). The declaration is checked by NewCatalog.
func NewStoredKind[C any](name, magic string, sealing Sealing, refuse error,
	unknown func(got, written uint32) error,
) *Kind[C] {
	k := newKind[C](name, Stored, sealing, refuse, unknown)
	k.b.magic = magic
	if len(magic) >= 1 && len(magic) <= 8 {
		var word [8]byte
		copy(word[:], magic)
		k.b.word, k.b.mask = binary.LittleEndian.Uint64(word[:]), ^uint64(0)>>(64-8*len(magic))
	}
	return k
}

// NewKind declares a kind of any other form. refuse is required for Prefixed and Tokened (an item no scheme read
// marks); unknown for Numbered and Unmarked (a version no scheme read has: Read). The other is nil.
func NewKind[C any](name string, form Form, sealing Sealing, refuse error,
	unknown func(got, written uint32) error,
) *Kind[C] {
	return newKind[C](name, form, sealing, refuse, unknown)
}

func newKind[C any](name string, form Form, sealing Sealing, refuse error,
	unknown func(got, written uint32) error,
) *Kind[C] {
	return &Kind[C]{b: kindBase{name: name, form: form, sealing: sealing, refuse: refuse, unknown: unknown,
		newTable: func() table { return &kindTable[C]{} }}}
}

// Reads is the rule of a Policy for k that reads versions vs and writes nothing yet: add each slot's writer with
// Rule.Writes.
func (k *Kind[C]) Reads(vs ...uint32) Rule { return Rule{kind: &k.b, reads: slices.Clone(vs)} }

// Scheme declares version v of k, named name in refusals, in the release record and in the docs ("format 4",
// "version 1"), read and written by codec (a nil codec is refused). opts are what the kind's form and sealing need:
// SealedBy for a Sealed kind, Marker for a Prefixed or Tokened kind, ForSlot for a scheme written for a slot other than
// 0. The Entry is a copy: nothing done to codec's variable or to opts afterwards changes a Catalog made of it.
func (k *Kind[C]) Scheme(v uint32, name string, codec C, opts ...Option) Entry {
	d := declaration{kind: &k.b, version: v, name: name}
	for _, o := range opts {
		switch o.what {
		case optSuite:
			d.suite, d.keyName, d.sealedBy = o.suite, o.text, true
		case optMarker:
			d.marker, d.hasMarker = o.text, true
		case optSlot:
			d.slot = o.slot
		}
	}
	return entry[C]{d: d, codec: codec}
}

// validate checks a kind's declaration.
func (b *kindBase) validate() error {
	ok := b.name != "" && b.form >= Stored && b.form <= Unmarked && (b.sealing == Unsealed || b.sealing == Sealed)
	switch b.form {
	case Stored:
		ok = ok && validMagic(b.magic) && b.refuse != nil && b.unknown != nil
	case Prefixed, Tokened:
		ok = ok && b.magic == "" && b.refuse != nil
	case Numbered, Unmarked:
		ok = ok && b.magic == "" && b.unknown != nil
	}
	if !ok {
		return fmt.Errorf("%w: a kind is a name, a form, a magic of 1 to 8 printable ASCII bytes when it is stored, and "+
			"its refusals", errRegistry)
	}
	return nil
}

// validMagic reports whether m can be a magic: 1 to 8 printable ASCII bytes.
func validMagic(m string) bool {
	if len(m) == 0 || len(m) > 8 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if m[i] < '!' || m[i] > '~' {
			return false
		}
	}
	return true
}
