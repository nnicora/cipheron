package format

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// errLifecycle wraps every refusal of Check: a next release whose policy may not follow the previous one's.
var errLifecycle = errors.New("cipheron: version lifecycle")

// Check refuses a next release whose policy may not follow prev's (the compatibility policy's order), naming every
// fault: a slot that switches to a version prev does not read (the writer last); a version next stops reading that
// prev writes (readers removed last); a kind prev has and next lacks. Adding a version to the read set, or a kind, is
// always allowed (readers first). Kinds are matched by name, slots and versions by number.
func Check(prev, next *Policy) error {
	var faults []string
	for _, pr := range prev.rules {
		name := pr.kind.name
		i := slices.IndexFunc(next.rules, func(r Rule) bool { return r.kind.name == name })
		if i < 0 {
			faults = append(faults, fmt.Sprintf("the %s kind is not in the next release: it is read until nothing "+
				"writes it", name))
			continue
		}
		nr := next.rules[i]
		for _, w := range nr.writes {
			if !slices.Contains(pr.reads, w.version) {
				faults = append(faults, fmt.Sprintf("the %s kind does not read version %d: it cannot write it", name,
					w.version))
			}
		}
		for _, w := range pr.writes {
			if !slices.Contains(nr.reads, w.version) {
				faults = append(faults, fmt.Sprintf("the %s kind writes version %d: it is read until nothing writes it",
					name, w.version))
			}
		}
	}
	if len(faults) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", errLifecycle, strings.Join(faults, "; "))
}
