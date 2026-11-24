package format

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// errRegistry wraps every refusal of a malformed declaration (NewCatalog, NewPolicy, Policy.With, TestSuite,
// TestNamespace and the frame's programming errors): refused while a package is initialised or in a test.
var errRegistry = errors.New("cipheron: layout registry")

// Catalog is the schemes a program has: declared as data, validated once by NewCatalog, never changed. It refuses
//   - a kind declaration that is not valid: no name; a Stored kind whose magic is not 1 to 8 printable ASCII bytes;
//     a form outside Form; refuse or unknown missing where its form needs it; two kinds of one name;
//   - a magic that is another kind's, begins one or is begun by one;
//   - a scheme without a name or with a nil codec; two schemes of one kind and version; a version above 255 of a
//     Stored kind;
//   - a scheme of a Sealed kind without a suite (the zero Suite, the only Suite format did not make) or a key name;
//     a scheme of an Unsealed kind with a suite;
//   - a Marker on a scheme whose form has none; a Prefixed or Tokened scheme without one; within a Prefixed kind, a
//     marker that begins another's; within a Tokened kind, two equal tokens;
//   - a Stored scheme whose Layout has no field, a field without a name, Min above Max, Min below 1, or a Prefix other
//     than 0, 1 or 4 (Max at most 255 behind 1, 2^24 behind 4); a Plaintext on an Unsealed kind;
//   - two different suites owning one namespace.
//
// A kind's schemes may come in several Entry lists (a test adds its version beside the release's: Policy.With).
type Catalog struct {
	// kinds are the catalog's kinds in declaration order (each kind's first scheme), each with its schemes by version.
	kinds []catalogKind
	// entries are the declarations, kept for Policy.With.
	entries []Entry
}

type catalogKind struct {
	kind    *kindBase
	schemes []anyScheme
}

// NewCatalog validates entries and returns their Catalog; a refusal names the first fault.
func NewCatalog(entries ...Entry) (*Catalog, error) {
	c := &Catalog{entries: slices.Clone(entries)}
	byKind := map[*kindBase]int{}
	names := map[string]*kindBase{}
	suites := map[string]Suite{}
	for _, e := range entries {
		if e == nil {
			return nil, fmt.Errorf("%w: a nil entry", errRegistry)
		}
		s := e.newScheme()
		d := s.decl()
		k := d.kind
		i, seen := byKind[k]
		if !seen {
			if err := k.validate(); err != nil {
				return nil, err
			}
			if other := names[k.name]; other != nil {
				return nil, fmt.Errorf("%w: two kinds are named %q", errRegistry, k.name)
			}
			for _, o := range c.kinds {
				m := o.kind.magic
				if k.magic != "" && m != "" && (strings.HasPrefix(k.magic, m) || strings.HasPrefix(m, k.magic)) {
					return nil, fmt.Errorf("%w: the magic %q is the %s kind's %q, or begins it, or is begun by it",
						errRegistry, k.magic, o.kind.name, m)
				}
			}
			names[k.name] = k
			i = len(c.kinds)
			byKind[k] = i
			c.kinds = append(c.kinds, catalogKind{kind: k})
		}
		if err := validateScheme(d); err != nil {
			return nil, err
		}
		ck := &c.kinds[i]
		for _, o := range ck.schemes {
			od := o.decl()
			if od.version == d.version {
				return nil, fmt.Errorf("%w: %s: the %s kind has a scheme of version %d already: %s", errRegistry, d.name,
					k.name, d.version, od.name)
			}
			switch {
			case k.form == Prefixed && (strings.HasPrefix(d.marker, od.marker) || strings.HasPrefix(od.marker, d.marker)):
				return nil, fmt.Errorf("%w: %s: the marker %q begins %s's %q, or is begun by it", errRegistry, d.name,
					d.marker, od.name, od.marker)
			case k.form == Tokened && d.marker == od.marker:
				return nil, fmt.Errorf("%w: %s: the token %q is %s's", errRegistry, d.name, d.marker, od.name)
			}
		}
		if d.suite.s != nil {
			ns := d.suite.s.ns.s
			if o, ok := suites[ns]; ok && o != d.suite {
				return nil, fmt.Errorf("%w: suite %s: the label namespace %q is suite %s's", errRegistry, d.suite.s.name,
					ns, o.s.name)
			}
			suites[ns] = d.suite
		}
		ck.schemes = append(ck.schemes, s)
	}
	for i := range c.kinds {
		slices.SortFunc(c.kinds[i].schemes, func(a, b anyScheme) int {
			return compare(a.decl().version, b.decl().version)
		})
	}
	return c, nil
}

func compare(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// validateScheme checks one scheme's declaration against its kind's form and sealing.
func validateScheme(d *declaration) error {
	k := d.kind
	switch {
	case d.name == "" || d.codecNil:
		return fmt.Errorf("%w: %q: a scheme has a name and a codec", errRegistry, d.name)
	case k.form == Stored && d.version > 255:
		return fmt.Errorf("%w: %s: a stored scheme's version is a byte, not %d", errRegistry, d.name, d.version)
	case k.sealing == Sealed && d.suite.s == nil:
		return fmt.Errorf("%w: %s of the %s kind is sealed and has no suite", errRegistry, d.name, k.name)
	case k.sealing == Sealed && d.keyName == "":
		return fmt.Errorf("%w: %s has a suite and no name for its key", errRegistry, d.name)
	case k.sealing == Unsealed && (d.sealedBy || d.suite.s != nil):
		return fmt.Errorf("%w: %s of the %s kind is not sealed and has a suite", errRegistry, d.name, k.name)
	case (k.form == Prefixed || k.form == Tokened) && (!d.hasMarker || d.marker == ""):
		return fmt.Errorf("%w: %s of the %s kind has no marker", errRegistry, d.name, k.name)
	case k.form != Prefixed && k.form != Tokened && d.hasMarker:
		return fmt.Errorf("%w: %s of the %s kind is %s: it declares no marker", errRegistry, d.name, k.name, k.form)
	}
	if k.form == Stored {
		return d.validateLayout()
	}
	return nil
}
