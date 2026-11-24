#!/usr/bin/env python3
"""Every cipheron label is built from one purpose table: no Go string literal spells "cipheron/v<n>|" elsewhere.

RULE 1: a label cipheron and its clients derive a key under, sign or hash begins with a label namespace —
"cipheron/v1|", or the seal slots' "cipheron/seal/v1|" — and production Go code builds it from the purpose table,
wire/format/labels.go (format.LabelDigest.String() is "cipheron/v1|digest"; format.LabelKeyCheck.For(d) is
"cipheron/v1|<d>|kcv"; the shape builders). That file is the only place a namespace is spelled; no string literal in
any other non-test Go code holds one.

RULE 2: no non-test Go file names format.TestNamespace or format.TestSuite (a word match on the code, comments and
strings aside: Go cannot rename an imported identifier, so no import alias or dot import escapes it) in a file that
imports the package, but the two files that define them. A test's suite owns a test's namespace only: production code never makes a suite.

WHY IT IS A GATE. The namespace's version is what a later layout of everything under it changes.
Spelled by hand in some fifteen files, a later version would be a search-and-replace that misses one
label — a key derived, or a transcript signed, under the old namespace while everything else moved —
and nothing would fail until two releases disagreed. Built by one constructor, the version is in one
place. Comments are not code: a comment that writes a label's layout out ("lp(\"cipheron/v1|digest\")")
is documentation, and is not checked.

THE ALLOWLIST is a ratchet, not a pass. Each entry names a file, how many literals it may hold and
why. A count above the entry's fails; a count below it is reported, so the entry is lowered with
the change that removed them. Test files are exempt: tests spell the layouts out to check them.

Run: make check-label-namespace
     python3 scripts/checks/check-label-namespace.py --self-test
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

NAMESPACE_RE = re.compile(r"cipheron/(?:[a-z0-9-]+/)*v[0-9]+\|")

# path -> (the most literals the file may hold, why)
ALLOW = {
    "wire/format/labels.go": (
        2,
        "THE PURPOSE TABLE: the only place a namespace is spelled — the protocol's \"cipheron/v1|\" and the seal "
        "slots' \"cipheron/seal/v1|\"; every label is built from it.",
    ),
}


def string_literals(text: str):
    """Yields (line number, literal body) for every Go string literal ("..." and `...`), skipping comments and runes."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif c == '"':
            j, start = i + 1, line
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            yield start, text[i + 1:j]
            i = j + 1
        elif c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            yield line, text[i + 1:j]
            line += text.count("\n", i, j)
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and text[j] != "'" and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
        else:
            i += 1


def literals_in(rel: str, text: str):
    """Yields (line number, literal) for every literal that spells a label namespace, in one non-test Go file."""
    if rel.endswith("_test.go"):
        return
    for n, lit in string_literals(text):
        if NAMESPACE_RE.search(lit):
            yield n, lit


# The test-only constructors (rule 2), and the files that define them.
TEST_ONLY_RE = re.compile(r"\bTest(?:Namespace|Suite)\b")
FORMAT_IMPORT = '"github.com/nnicora/cipheron/wire/format"'
TEST_ONLY_DEFINED_IN = {"wire/format/labels.go", "wire/format/suite.go"}


def code_only(text: str) -> str:
    """text with every comment and string literal blanked: what names an identifier."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            out.append('""')
        elif c == "`":
            j = text.find("`", i + 1)
            i = n if j < 0 else j + 1
            out.append('""')
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_only_uses(rel: str, text: str):
    """Yields (line number, name) for every use of a test-only constructor in a non-test Go file (rule 2)."""
    if rel.endswith("_test.go") or rel in TEST_ONLY_DEFINED_IN or FORMAT_IMPORT not in text:
        return
    code = code_only(text)
    for m in TEST_ONLY_RE.finditer(code):
        yield code.count("\n", 0, m.start()) + 1, m.group(0)


def go_files():
    try:
        out = subprocess.run(
            ["git", "ls-files", "-co", "--exclude-standard", "-z", "--", "*.go"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout.decode().split("\0")
        files = [f for f in out if f]
    except (OSError, subprocess.CalledProcessError):
        files = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.go")]
    return [f for f in files if not f.startswith(("vendor/", ".claude/"))]


def verdict(found):
    """found: {rel: [(line, literal)]}. Returns (failures, notes)."""
    failures, notes = [], []
    for rel in sorted(found):
        hits = found[rel]
        allowed = ALLOW.get(rel, (0, ""))[0]
        if len(hits) > allowed:
            where = ", ".join(f"{rel}:{n} {lit!r}" for n, lit in hits)
            if allowed:
                failures.append(f"{rel}: {len(hits)} namespace literals, the allowlist admits {allowed}: {where}")
            else:
                failures.append(f"{where}: a label namespace spelled by hand")
    for rel, (allowed, _) in sorted(ALLOW.items()):
        have = len(found.get(rel, []))
        if have < allowed:
            notes.append(f"{rel}: holds {have} where the allowlist admits {allowed} — lower the entry with the change that removed them")
    return failures, notes


def check() -> int:
    found, test_only = {}, []
    for rel in go_files():
        try:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = list(literals_in(rel, text))
        if hits:
            found[rel] = hits
        test_only += [f"{rel}:{n}: {name} outside a test" for n, name in test_only_uses(rel, text)]
    failures, notes = verdict(found)
    failures += test_only
    for n in notes:
        print("note: " + n)
    if failures:
        print("FAIL: a cipheron label namespace spelled by hand outside the allowlist\n")
        print("\n".join(failures))
        print(
            "\nBuild the label from the purpose table (wire/format/labels.go): a Fixed label's String,\n"
            "a Scoped label's For(domain), or a shape builder; add a word to the table for a new label. A\n"
            "test's suite and namespace (format.TestSuite, format.TestNamespace) are for tests only. Code that\n"
            "implements the documented layouts as a third party does goes in ALLOW in this script with the reason."
        )
        return 1
    total = sum(len(v) for v in found.values())
    print(f"label namespace: OK — {total} literal(s), all within the allowlist of {len(ALLOW)} file(s)")
    return 0


def self_test() -> int:
    cases = [
        ("a literal label is found", "x/y.go", 'const l = "cipheron/v1|digest"', ["cipheron/v1|digest"]),
        ("a bare namespace is found", "x/y.go", 'b = append(b, "cipheron/v1|"...)', ["cipheron/v1|"]),
        ("a later version is found", "x/y.go", 'l := "cipheron/v12|x"', ["cipheron/v12|x"]),
        ("a scope's namespace is found", "x/y.go", 'c := "cipheron/seal/v1|" + d', ["cipheron/seal/v1|"]),
        ("a raw string is found", "x/y.go", "l := `cipheron/v1|x`", ["cipheron/v1|x"]),
        ("a line comment is not code", "x/y.go", '// lp("cipheron/v1|digest")\nfunc f() {}', []),
        ("a trailing comment is not code", "x/y.go", 'f() // "cipheron/v1|digest"', []),
        ("a block comment is not code", "x/y.go", '/* "cipheron/v1|x"\n "cipheron/v1|y" */ f()', []),
        ("a comment inside a string is a string", "x/y.go", 'l := "// cipheron/v1|x"', ["// cipheron/v1|x"]),
        ("an escaped quote does not end the string", "x/y.go", r'l := "a\"cipheron/v1|b"', [r'a\"cipheron/v1|b']),
        ("a rune quote is no string", "x/y.go", "r := '\"'; l := \"cipheron/v1|x\"", ["cipheron/v1|x"]),
        ("no separator is no namespace", "x/y.go", 'k := "cipheron/v1"', []),
        ("a path is no namespace", "x/y.go", 'k := "cipheron/" + d + "/hpke"', []),
        ("tests are exempt", "x/y_test.go", 'l := "cipheron/v1|x"', []),
    ]
    failed = 0
    for name, rel, text, want in cases:
        got = [lit for _, lit in literals_in(rel, text)]
        if got != want:
            failed += 1
            print(f"self-test FAIL: {name}: got {got}, want {want}")
    IMP = "import f " + FORMAT_IMPORT + "\n"
    rule2 = [
        ("a test suite in production code fails", "x/y.go", IMP + "s := format.TestSuite(a, b)", ["TestSuite"]),
        ("a test namespace in production code fails", "x/y.go", IMP + "n := f.TestNamespace(\"\")", ["TestNamespace"]),
        ("a dot import's bare name fails", "x/y.go", IMP + "s := TestSuite(a)", ["TestSuite"]),
        ("a test file is exempt", "x/y_test.go", IMP + "s := format.TestSuite(a)", []),
        ("the defining file is exempt", "wire/format/suite.go", IMP + "func TestSuite() {}", []),
        ("a comment is not code", "x/y.go", IMP + "// format.TestSuite is for tests\nf()", []),
        ("a string is not code", "x/y.go", IMP + 'm := "TestNamespace"', []),
        ("a longer name is another", "x/y.go", IMP + "TestSuiteName()", []),
        ("a file not importing format is another's TestSuite", "x/y.go", "s := TestSuite(a)", []),
    ]
    for name, rel, text, want in rule2:
        got = [n for _, n in test_only_uses(rel, text)]
        if got != want:
            failed += 1
            print(f"self-test FAIL: {name}: got {got}, want {want}")
    cases += rule2
    rel = "wire/format/labels.go"
    verdicts = [
        ("an allowlisted file within its count passes", {rel: [(1, "a"), (2, "b")]}, False, False),
        ("an allowlisted file above its count fails", {rel: [(1, "a"), (2, "b"), (3, "c")]}, True, False),
        ("an allowlisted file below its count passes with a note", {rel: [(1, "a")]}, False, True),
        ("a file nobody allowlisted fails", {"x/new.go": [(9, "cipheron/v1|x")]}, True, True),
    ]
    for name, found, want_fail, want_note in verdicts:
        failures, notes = verdict(found)
        if bool(failures) != want_fail or (want_note and not notes):
            failed += 1
            print(f"self-test FAIL: {name}: failures={failures} notes={len(notes)}")
    if failed:
        return 1
    print(f"check-label-namespace self-test: OK — {len(cases) + len(verdicts)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv[1:] else check())
