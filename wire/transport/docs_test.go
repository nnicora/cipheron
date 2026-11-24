package transport_test

// docs_test.go — the catalog is the source of truth of the layout specification. From the protocol's release
// (transport.Release().Schemes(): the scheme names, markers, fields, bounds and suites) and from each format's own
// label (its codec's info) it renders, in spec/:
//
//   - api.md: the ciphertext layout table, the ciphertext key table, the tenant key blob's layout and the segmented
//     object's header;
//   - compatibility.md: the byte offsets of formats 4 and 5 and of formats 3 and 6;
//
// and it checks that compatibility.md's table of every format names exactly the versions each kind reads, and that
// the named format sections list the ciphertext's formats as the release reads them. A block sits between
// `<!-- format:<name> -->` and `<!-- /format -->`; a column the catalog does not know (prose) is read from the document
// by its row's key and written back as it is. A difference fails, and so does a block or a named section the document
// no longer has (a renamed or deleted heading). `go test ./wire/transport -run Docs -update-docs`
// rewrites the blocks.

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/wire/format"
	"github.com/nnicora/cipheron/wire/transport"
)

var updateDocs = flag.Bool("update-docs", false, "rewrite the generated blocks of spec/ from the catalog")

const docsDir = "../../spec/"

// problems collects what a docs check finds, so the checks run on any document (TestTheDocsChecksRefuse).
type problems []string

func (p *problems) add(f string, args ...any) { *p = append(*p, fmt.Sprintf(f, args...)) }

// schemesOf are the schemes of kind the release reads, ascending.
func schemesOf(kind string) []format.SchemeInfo {
	var out []format.SchemeInfo
	for i := range transport.Release().Schemes() {
		if i.Kind == kind {
			out = append(out, i)
		}
	}
	return out
}

// md escapes a table cell's "|".
func md(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// markerParts are a stored scheme's marker as the docs spell it: the magic quoted, then the version byte.
func markerParts(i format.SchemeInfo) []string {
	magic, b := i.Marker[:len(i.Marker)-1], i.Marker[len(i.Marker)-1]
	return []string{fmt.Sprintf("%q", magic), fmt.Sprintf("0x%02x", b)}
}

// fieldParts are a stored scheme's fields as the docs spell them: a fixed field `name (n)`, a field behind one length
// byte `len (1) | name (len)`, a field behind a 4-byte length `lp(name)`.
func fieldParts(fields []format.Field) []string {
	var parts []string
	for _, f := range fields {
		switch f.Prefix {
		case 0:
			parts = append(parts, fmt.Sprintf("%s (%d)", f.Name, f.Max))
		case 1:
			parts = append(parts, "len (1) | "+f.Name+" (len)")
		default:
			parts = append(parts, "lp("+f.Name+")")
		}
	}
	return parts
}

// layoutCell renders a ciphertext scheme's layout: the marker, the fields, the salt and the sealed tail.
func layoutCell(i format.SchemeInfo) string {
	parts := append(markerParts(i), fieldParts(i.Layout.Fields)...)
	if s := i.Suite.SaltLen(); s > 0 {
		parts = append(parts, fmt.Sprintf("salt (%d)", s))
	}
	if i.Suite.Overhead() > 0 {
		parts = append(parts, "nonce", "ct", "tag")
	}
	return "`" + md(strings.Join(parts, " | ")) + "`"
}

// bounds are a stored scheme's overhead bounds: its header and its suite's tail.
func bounds(i format.SchemeInfo) (lo, hi int) {
	lo, hi = len(i.Marker)+i.Suite.SaltLen()+i.Suite.Overhead(), len(i.Marker)+i.Suite.SaltLen()+i.Suite.Overhead()
	for _, f := range i.Layout.Fields {
		lo, hi = lo+f.Prefix+f.Min, hi+f.Prefix+f.Max
	}
	return lo, hi
}

// labelCell renders format f's key derivation: the suite's expand, the key the scheme names, its label — the codec's
// info built with placeholders, every length-prefixed placeholder as lp(...) — the salt and the key length.
func labelCell(i format.SchemeInfo) string {
	const profile, tenant, version = "<profile>", "<tenant>", "<version id>"
	info := transport.CiphertextInfoForTest(transport.Release(), byte(i.Version), profile, tenant, version)
	var parts []string
	lit := ""
	for len(info) > 0 {
		matched := false
		for _, p := range []string{version, tenant, profile} {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(p)))
			if strings.HasPrefix(info, string(n[:])+p) {
				if lit != "" {
					parts = append(parts, fmt.Sprintf("%q", lit))
					lit = ""
				}
				parts = append(parts, "lp("+strings.Trim(p, "<>")+")")
				info, matched = info[4+len(p):], true
				break
			}
		}
		if !matched {
			lit, info = lit+info[:1], info[1:]
		}
	}
	if lit != "" {
		parts = append(parts, fmt.Sprintf("%q", lit))
	}
	expand, _, _ := strings.Cut(i.Suite.Name(), "/")
	return "`" + md(fmt.Sprintf("%s(%s, %s || salt, %d)", expand, i.KeyName, strings.Join(parts, " || "),
		i.Suite.KeyLen())) + "`"
}

// tableRows splits a markdown table's rows into cells (the separator row kept as is).
func tableRows(block string) [][]string {
	var out [][]string
	for _, line := range strings.Split(strings.TrimSpace(block), "\n") {
		line = strings.TrimSpace(line)
		cells := regexp.MustCompile(`\s\|\s`).Split(strings.Trim(line, "|"), -1)
		for k := range cells {
			cells[k] = strings.TrimSpace(cells[k])
		}
		out = append(out, cells)
	}
	return out
}

// renderTable renders a table of header, and rows of cells.
func renderTable(header []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString("| " + strings.Join(header, " | ") + " |\n|")
	for range header {
		b.WriteString(" --- |")
	}
	b.WriteString("\n")
	for _, r := range rows {
		b.WriteString("| " + strings.Join(r, " | ") + " |\n")
	}
	return b.String()
}

// prose is the cell col of the row keyed key (its cell keyCol) in the current block; "" when there is none.
func prose(old [][]string, keyCol int, key string, col int) string {
	for _, r := range old {
		if len(r) > col && len(r) > keyCol && r[keyCol] == key {
			return r[col]
		}
	}
	return ""
}

// layoutsBlock renders api.md's ciphertext-layouts block from the catalog, prose from old.
func layoutsBlock(ps *problems, old [][]string) string {
	var rows [][]string
	schemes := schemesOf("ciphertext")
	for n, i := range schemes {
		v := strconv.FormatUint(uint64(i.Version), 10)
		layout := layoutCell(i)
		lo, hi := bounds(i)
		overhead := strconv.Itoa(lo)
		for _, e := range schemes[:n] {
			if slices.Equal(e.Layout.Fields, i.Layout.Fields) && e.Suite == i.Suite {
				layout = fmt.Sprintf("format %d's layout with format byte `0x%02x`", e.Version, i.Version)
				if elo, ehi := bounds(e); lo != hi && elo == lo && ehi == hi {
					overhead = fmt.Sprintf("as %d", e.Version)
				}
				break
			}
		}
		if lo != hi && !strings.HasPrefix(overhead, "as ") {
			overhead = fmt.Sprintf("%d to %d", lo, hi)
			if paren := strings.TrimSpace(strings.TrimPrefix(prose(old, 0, v, 3), overhead)); paren != "" {
				var vf format.Field
				for _, f := range i.Layout.Fields {
					if f.Min != f.Max {
						vf = f
					}
				}
				if !strings.Contains(paren, fmt.Sprintf("%d to %d", vf.Min, vf.Max)) {
					ps.add("format %s: the overhead's parenthetical %q does not name the field's %d to %d bytes", v,
						paren, vf.Min, vf.Max)
				}
				overhead += " " + paren
			}
		}
		rows = append(rows, []string{v, layout, prose(old, 0, v, 2), overhead})
	}
	return renderTable([]string{"format", "layout", "written by", "overhead"}, rows)
}

// keysBlock renders api.md's ciphertext-keys block from the catalog, prose from old.
func keysBlock(old [][]string) string {
	var rows [][]string
	seen := map[string]uint32{}
	for _, i := range schemesOf("ciphertext") {
		v := strconv.FormatUint(uint64(i.Version), 10)
		cell := labelCell(i)
		if e, ok := seen[cell]; ok {
			cell = fmt.Sprintf("as format %d", e)
		} else {
			seen[cell] = i.Version
		}
		rows = append(rows, []string{v, cell, prose(old, 0, v, 2)})
	}
	return renderTable([]string{"format", "AES-256 key", "AAD"}, rows)
}

// codeLayout renders a stored scheme's layout as a code block's lines: the marker and the fields, wrapped at 100
// columns behind a continuation bar; then, for a sealed kind, the salt and the sealed tail on lines of their own.
func codeLayout(i format.SchemeInfo) string {
	const indent = "       | "
	parts := append(markerParts(i), fieldParts(i.Layout.Fields)...)
	var lines []string
	line := ""
	for _, p := range parts {
		switch {
		case line == "":
			line = p
		case len(line)+3+len(p) > 100:
			lines = append(lines, line)
			line = indent + p
		default:
			line += " | " + p
		}
	}
	lines = append(lines, line)
	if s := i.Suite.SaltLen(); s > 0 {
		lines = append(lines, indent+fmt.Sprintf("salt (%d)", s))
	}
	if o := i.Suite.Overhead(); o > 0 {
		_, aead, _ := strings.Cut(i.Suite.Name(), "/")
		tail := fmt.Sprintf("nonce | ct | tag: %s, %d bytes after the header", aead, o)
		if i.Layout.Plaintext > 0 {
			tail = fmt.Sprintf("nonce | ct | tag: %s of the %d-byte plaintext, exactly %d bytes", aead,
				i.Layout.Plaintext, o+i.Layout.Plaintext)
		}
		lines = append(lines, indent+tail)
	}
	return strings.Join(lines, "\n")
}

// codeBlock renders the layouts of every version of kind the release reads as one fenced code block, each version's
// after a blank line.
func codeBlock(kind string) string {
	var layouts []string
	for _, i := range schemesOf(kind) {
		layouts = append(layouts, codeLayout(i))
	}
	return "```\n" + strings.Join(layouts, "\n\n") + "\n```\n"
}

// offsetsBlock renders compatibility.md's byte-by-byte table of ciphertext formats a and b (one layout under two
// format bytes): each row's bytes and the element it is, the content (prose) by element.
func offsetsBlock(ps *problems, a, b uint32) func([][]string) string {
	return func(old [][]string) string {
		var sa, sb format.SchemeInfo
		for _, i := range schemesOf("ciphertext") {
			switch i.Version {
			case a:
				sa = i
			case b:
				sb = i
			}
		}
		if sa.Version != a || sb.Version != b || !slices.Equal(sa.Layout.Fields, sb.Layout.Fields) || sa.Suite != sb.Suite {
			ps.add("formats %d and %d are not one layout the release reads under two format bytes", a, b)
			return renderTable([]string{"bytes", "element", "content"}, nil)
		}
		var rows [][]string
		row := func(bytes, element string) {
			rows = append(rows, []string{bytes, element, prose(old, 1, element, 2)})
		}
		span := func(at, n int) string {
			if n == 1 {
				return strconv.Itoa(at)
			}
			return fmt.Sprintf("%d to %d", at, at+n-1)
		}
		at, variable := 0, ""
		fixed := func(name string, n int) {
			if variable == "" {
				row(span(at, n), name)
				at += n
			} else {
				row(fmt.Sprintf("the next %d", n), name)
			}
		}
		fixed("magic", len(sa.Marker)-1)
		fixed("format", 1)
		for _, f := range sa.Layout.Fields {
			switch {
			case f.Prefix == 0 && f.Min == f.Max:
				fixed(f.Name, f.Max)
			case f.Prefix == 1 && variable == "":
				row(strconv.Itoa(at), "length of the "+f.Name+": n")
				row(fmt.Sprintf("%d to %d + n", at+1, at), f.Name)
				variable = "n"
			default:
				ps.add("format %d: the field %q has a shape the offsets do not render", a, f.Name)
			}
		}
		fixed("salt", sa.Suite.SaltLen())
		row("the rest", "nonce, ciphertext and tag")
		return renderTable([]string{"bytes", "element", "content"}, rows)
	}
}

// blocks replaces each generated block of doc by gen(name, the block's table rows); a block gen has and doc lacks,
// and a block doc has and gen lacks, are problems.
func blocks(ps *problems, doc string, gen map[string]func([][]string) string) string {
	re := regexp.MustCompile(`(?s)<!-- format:([a-z0-9-]+) -->\n(.*?)<!-- /format -->`)
	found := map[string]bool{}
	out := re.ReplaceAllStringFunc(doc, func(m string) string {
		sub := re.FindStringSubmatch(m)
		g, ok := gen[sub[1]]
		if !ok {
			ps.add("an unknown generated block %q", sub[1])
			return m
		}
		found[sub[1]] = true
		return "<!-- format:" + sub[1] + " -->\n" + g(tableRows(sub[2])) + "<!-- /format -->"
	})
	for name := range gen {
		if !found[name] {
			ps.add("the block %q is not in the document", name)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| ") && strings.HasSuffix(line, " |  |") {
			ps.add("a row the catalog adds has no prose yet: %s", line)
		}
	}
	return out
}

// generated renders every generated block of api.md and compatibility.md.
func generated(ps *problems, api, compat string) (string, string) {
	api = blocks(ps, api, map[string]func([][]string) string{
		"ciphertext-layouts": func(old [][]string) string { return layoutsBlock(ps, old) },
		"ciphertext-keys":    keysBlock,
		"tenant-key-blob":    func([][]string) string { return codeBlock("tenant key blob") },
		"segmented-object":   func([][]string) string { return codeBlock("segmented object") },
	})
	compat = blocks(ps, compat, map[string]func([][]string) string{
		"ciphertext-bytes-4-5": offsetsBlock(ps, uint32(transport.FormatVersioned), uint32(transport.FormatVersionedAAD)),
		"ciphertext-bytes-3-6": offsetsBlock(ps, uint32(transport.FormatTenantKey), uint32(transport.FormatTenantKeyAAD)),
	})
	return api, compat
}

func TestDocsLayoutTablesAreTheCatalog(t *testing.T) {
	files := []string{docsDir + "api.md", docsDir + "compatibility.md"}
	var raw []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, string(b))
	}
	var ps problems
	api, compat := generated(&ps, raw[0], raw[1])
	for _, p := range ps {
		t.Error(p)
	}
	for k, got := range []string{api, compat} {
		if got == raw[k] {
			continue
		}
		if *updateDocs {
			if err := os.WriteFile(files[k], []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s's generated blocks are not the catalog's (-update-docs rewrites them):\n%s", files[k],
			diffLines(raw[k], got))
	}
}

// versionsProblems: compatibility.md's table of every format has a row for every kind of the protocol's release, named as
// the kind, whose version cell names exactly the versions read (a prefixed or tokened kind: its markers); and the
// named format sections — each of which must exist — list the ciphertext's formats as the release reads them.
func versionsProblems(compat, api string) problems {
	var ps problems
	read := map[string][]string{}
	var order []string
	for i := range transport.Release().Schemes() {
		if _, ok := read[i.Kind]; !ok {
			order = append(order, i.Kind)
		}
		v := strconv.FormatUint(uint64(i.Version), 10)
		if i.Form == format.Prefixed || i.Form == format.Tokened {
			v = i.Marker
		}
		read[i.Kind] = append(read[i.Kind], v)
	}
	sections := map[string]string{}
	for _, s := range []struct{ name, doc, heading string }{
		{"compatibility.md, every format", compat, "## Every format and its version"},
		{"compatibility.md, the ciphertexts", compat, "## The ciphertext formats"},
		{"compatibility.md, the algorithm", compat, "## The algorithm is named by the stored bytes"},
		{"api.md, ciphertext formats", api, "## Ciphertext formats"},
	} {
		text, ok := section(s.doc, s.heading)
		if !ok {
			ps.add("%s: the heading %q is not in the document (renamed or deleted: the check reads that section)",
				s.name, s.heading)
			continue
		}
		sections[s.name] = text
	}
	rows := map[string]string{}
	for _, line := range strings.Split(sections["compatibility.md, every format"], "\n") {
		if c := tableRows(line)[0]; strings.HasPrefix(line, "| ") && len(c) > 2 {
			rows[c[0]] = c[2]
		}
	}
	tick := regexp.MustCompile("`([^`]*)`")
	for _, k := range order {
		cell, ok := rows[k]
		if !ok {
			ps.add("compatibility.md has no row of the %q kind", k)
			continue
		}
		var got []string
		for _, m := range tick.FindAllStringSubmatch(cell, -1) {
			if m[1] != "" && (strings.Trim(m[1], "0123456789") == "" || slices.Contains(read[k], m[1])) {
				got = append(got, m[1])
			}
		}
		if !slices.Equal(got, read[k]) {
			ps.add("the %s row's versions %q, the release reads %q", k, got, read[k])
		}
	}
	// The ciphertext is the one kind of more than one version: every enumeration of three or more format numbers, or
	// range, in the named sections is its read set.
	var formats []string
	for _, i := range schemesOf("ciphertext") {
		formats = append(formats, strconv.FormatUint(uint64(i.Version), 10))
	}
	list := regexp.MustCompile("(?:`?(\\d+)`?, )+`?(\\d+)`?,? (?:and|or) `?(\\d+)`?|`(\\d+)`(?:, `(\\d+)`){2,}|formats (\\d+) to (\\d+)")
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range sections {
			if !yield(n) {
				return
			}
		}
	}) {
		for _, m := range list.FindAllString(sections[name], -1) {
			nums := regexp.MustCompile(`\d+`).FindAllString(m, -1)
			if strings.HasPrefix(m, "formats ") {
				if nums[0] != formats[0] || nums[1] != formats[len(formats)-1] {
					ps.add("%s: %q is not formats %s to %s", name, m, formats[0], formats[len(formats)-1])
				}
				continue
			}
			if !slices.Equal(nums, formats) {
				ps.add("%s: %q lists %v, the release reads %v", name, m, nums, formats)
			}
		}
	}
	return ps
}

func TestDocsVersionsAreTheCatalog(t *testing.T) {
	compat, err := os.ReadFile(docsDir + "compatibility.md")
	if err != nil {
		t.Fatal(err)
	}
	api, err := os.ReadFile(docsDir + "api.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range versionsProblems(string(compat), string(api)) {
		t.Error(p)
	}
}

// TestTheDocsChecksRefuse: the checks fail on a document whose named heading was renamed, whose generated block was
// deleted, whose version cell or format enumeration disagrees with the release — never pass silently on a document
// they cannot read.
func TestTheDocsChecksRefuse(t *testing.T) {
	compatB, err := os.ReadFile(docsDir + "compatibility.md")
	if err != nil {
		t.Fatal(err)
	}
	apiB, err := os.ReadFile(docsDir + "api.md")
	if err != nil {
		t.Fatal(err)
	}
	compat, api := string(compatB), string(apiB)
	if ps := versionsProblems(compat, api); len(ps) != 0 {
		t.Fatalf("the documents as they are: %v", ps)
	}
	for _, c := range []struct {
		name, compat, api, want string
	}{
		{"a renamed compatibility.md heading", strings.Replace(compat, "\n## The ciphertext formats\n",
			"\n## Ciphertext formats, renamed\n", 1), api, `"## The ciphertext formats" is not in the document`},
		{"a deleted api.md heading", compat, strings.Replace(api, "\n## Ciphertext formats\n", "\n", 1),
			`"## Ciphertext formats" is not in the document`},
		{"a renamed table heading", strings.Replace(compat, "\n## Every format and its version\n",
			"\n## Every format\n", 1), api, `"## Every format and its version" is not in the document`},
		{"an enumeration short of a format", strings.Replace(compat, "\n## The ciphertext formats\n",
			"\n## The ciphertext formats\n\nFormats 3, 4 or 5.\n", 1), api, `lists [3 4 5]`},
	} {
		ps := versionsProblems(c.compat, c.api)
		if !slices.ContainsFunc(ps, func(p string) bool { return strings.Contains(p, c.want) }) {
			t.Errorf("%s: no problem names %q (problems: %q)", c.name, c.want, ps)
		}
	}
	for _, c := range []struct {
		name, compat, api, want string
	}{
		{"a deleted block", strings.Replace(compat, "<!-- format:ciphertext-bytes-3-6 -->", "<!-- removed -->", 1), api,
			`the block "ciphertext-bytes-3-6" is not in the document`},
		{"an unknown block", compat, strings.Replace(api, "<!-- format:segmented-object -->",
			"<!-- format:segmented-objects -->", 1), `an unknown generated block "segmented-objects"`},
	} {
		var ps problems
		generated(&ps, c.api, c.compat)
		if !slices.ContainsFunc(ps, func(p string) bool { return strings.Contains(p, c.want) }) {
			t.Errorf("%s: no problem names %q (problems: %q)", c.name, c.want, ps)
		}
	}
	// A generated cell edited by hand is a difference the update would undo.
	var ps problems
	edited := strings.Replace(api, "| 3 | `\"CPH1\" \\| 0x03 \\|", "| 3 | `\"CPH1\" \\| 0x07 \\|", 1)
	if edited == api {
		t.Fatal("the format-3 layout cell is not where the test looks for it")
	}
	if got, _ := generated(&ps, edited, compat); got == edited {
		t.Error("a hand-edited layout cell is kept")
	}
}

// section is the text of the markdown section whose heading line is heading, up to the next heading of its level or
// above; false when doc has no such heading line.
func section(doc, heading string) (string, bool) {
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		return "", false
	}
	level := strings.Count(strings.Fields(heading)[0], "#")
	rest := doc[i+len(heading)+2:]
	for _, l := range []int{1, 2, 3, 4} {
		if l > level {
			break
		}
		if j := strings.Index(rest, "\n"+strings.Repeat("#", l)+" "); j >= 0 {
			rest = rest[:j]
		}
	}
	return rest, true
}

// diffLines lists the lines of b that a does not have.
func diffLines(a, b string) string {
	have := map[string]bool{}
	for _, l := range strings.Split(a, "\n") {
		have[l] = true
	}
	var out []string
	for _, l := range strings.Split(b, "\n") {
		if !have[l] {
			out = append(out, "+ "+l)
		}
	}
	return strings.Join(out, "\n")
}
