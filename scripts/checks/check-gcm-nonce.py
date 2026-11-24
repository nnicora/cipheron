#!/usr/bin/env python3
"""AES-GCM is built so the Go Cryptographic Module draws the IV: no cipher.NewGCM outside an allowlist.

THE RULE: production code builds AES-GCM with cipher.NewGCMWithRandomNonce, which generates the IV
inside the module and lays the output out as nonce || ciphertext || tag. It does not call
cipher.NewGCM, cipher.NewGCMWithNonceSize or cipher.NewGCMWithTagSize, all of which take an IV from
the caller.

WHY IT IS A GATE. Under FIPS 140-3 IG C.H the IV of an approved GCM encryption must be generated
inside the module's boundary. The Go Cryptographic Module records a Seal through cipher.NewGCM with a
caller's nonce as a NON-approved service, and under GODEBUG=fips140=only cipher.NewGCM refuses to
build at all ("use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode"). A key wrap or a
seal that drew its own IV would fail in the module's strictest mode, and in FIPS mode would be, by the
module's own indicator, not an approved service. Nothing stops the next caller writing cipher.NewGCM;
this does.

THE ALLOWLIST is a ratchet, not a pass. Each entry names a file, how many constructions it may hold
and why. A count above the entry's is a failure; a count below it is reported, so the entry is
lowered with the fix that removed the call. A new file is never allowlisted to get a change through:
adding an entry is a decision for review. Two kinds of entry exist:

  * PROTOCOL — the caller's IV is the protocol: a request that names its IV must use that IV. That is
    not a module-generated IV and is labelled non-approved where it is served.
  * DEBT — a construction that should move to NewGCMWithRandomNonce and has not yet; the reason names
    where it is tracked. These are what fips140=only would still refuse.

Test files are exempt: tests build GCM directly to produce inputs and compare layouts.

Run: make check-gcm-nonce
     python3 scripts/checks/check-gcm-nonce.py --self-test
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

IMPORT_PATH = "crypto/cipher"
FORBIDDEN = ("NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize")

# path -> (the most constructions the file may hold, why)
ALLOW: dict[str, tuple[int, str]] = {
    # Empty: no file of this repository builds AES-GCM with a caller's IV.
}

# Both import forms: a line inside `import ( ... )` and the single-line `import [alias] "path"`.
IMPORT_RE = re.compile(r'^\s*(?:import\s+)?(?:(\w+|_|\.)\s+)?"' + re.escape(IMPORT_PATH) + r'"', re.M)


def strip_comment(line: str) -> str:
    """Drops a // comment that is not inside a string literal (good enough for this gate)."""
    if line.lstrip().startswith("//"):
        return ""
    i = line.find("//")
    while i != -1:
        before = line[:i]
        if before.count('"') % 2 == 0 and before.count("`") % 2 == 0:
            return before
        i = line.find("//", i + 2)
    return line


def calls_in(rel: str, text: str):
    """Yields (line number, constructor) for every caller-IV GCM construction in one Go file."""
    if rel.endswith("_test.go"):
        return
    m = IMPORT_RE.search(text)
    if not m:
        return
    alias = m.group(1) or "cipher"
    if alias in ("_",):
        return
    prefix = "" if alias == "." else re.escape(alias) + r"\."
    call_re = re.compile(r"(?<![\w.])" + prefix + r"(" + "|".join(FORBIDDEN) + r")\s*\(")
    for n, raw in enumerate(text.splitlines(), 1):
        for c in call_re.finditer(strip_comment(raw)):
            yield n, c.group(1)


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
    """found: {rel: [(line, ctor)]}. Returns (failures, notes)."""
    failures, notes = [], []
    for rel in sorted(found):
        hits = found[rel]
        allowed = ALLOW.get(rel, (0, ""))[0]
        if len(hits) > allowed:
            where = ", ".join(f"{rel}:{n} cipher.{c}" for n, c in hits)
            if allowed:
                failures.append(f"{rel}: {len(hits)} caller-IV GCM constructions, the allowlist admits {allowed}: {where}")
            else:
                failures.append(f"{where}: a caller-IV GCM construction")
    for rel, (allowed, _) in sorted(ALLOW.items()):
        have = len(found.get(rel, []))
        if have < allowed:
            notes.append(f"{rel}: holds {have} where the allowlist admits {allowed} — lower the entry with the change that removed them")
    return failures, notes


def check() -> int:
    found = {}
    for rel in go_files():
        try:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = list(calls_in(rel, text))
        if hits:
            found[rel] = hits
    failures, notes = verdict(found)
    for n in notes:
        print("note: " + n)
    if failures:
        print("FAIL: AES-GCM built with a caller's IV outside the allowlist\n")
        print("\n".join(failures))
        print(
            "\nSeal with cipher.NewGCMWithRandomNonce(block): the module draws the IV and returns\n"
            "nonce || ciphertext || tag — the same bytes the caller-IV code wrote — and Open takes the same\n"
            "layout. Under GODEBUG=fips140=only cipher.NewGCM refuses to build. A construction that must take\n"
            "the caller's IV (a protocol that names it) goes in ALLOW in this script with the reason."
        )
        return 1
    total = sum(len(v) for v in found.values())
    print(f"gcm nonce: OK — {total} caller-IV construction(s), all within the allowlist of {len(ALLOW)} file(s)")
    return 0


def self_test() -> int:
    cases = [
        ("a caller-IV NewGCM is found", "x/y.go", 'import "crypto/cipher"\nfunc f() { cipher.NewGCM(b) }', ["NewGCM"]),
        ("the nonce-size variant is found", "x/y.go", 'import "crypto/cipher"\nfunc f() { cipher.NewGCMWithNonceSize(b, 16) }', ["NewGCMWithNonceSize"]),
        ("the tag-size variant is found", "x/y.go", 'import "crypto/cipher"\nfunc f() { cipher.NewGCMWithTagSize(b, 12) }', ["NewGCMWithTagSize"]),
        ("the module-IV constructor is allowed", "x/y.go", 'import "crypto/cipher"\nfunc f() { cipher.NewGCMWithRandomNonce(b) }', []),
        ("an aliased import is followed", "x/y.go", 'import goCipher "crypto/cipher"\nfunc f() { goCipher.NewGCM(b) }', ["NewGCM"]),
        ("an import block is followed", "x/y.go", 'import (\n\t"fmt"\n\tgc "crypto/cipher"\n)\nfunc f() { gc.NewGCM(b) }', ["NewGCM"]),
        ("a comment is not a call", "x/y.go", 'import "crypto/cipher"\n// cipher.NewGCM(b) used to be here\nfunc f() {}', []),
        ("a trailing comment is not a call", "x/y.go", 'import "crypto/cipher"\nfunc f() { g() } // not cipher.NewGCM(b)', []),
        ("a file that does not import crypto/cipher is ignored", "x/y.go", "func f() { cipher.NewGCM(b) }", []),
        ("tests are exempt", "x/y_test.go", 'import "crypto/cipher"\nfunc f() { cipher.NewGCM(b) }', []),
        ("a method of the same name is not the constructor", "x/y.go", 'import "crypto/cipher"\nfunc f() { x.cipher.NewGCM(b) }', []),
        ("a dot import is followed", "x/y.go", 'import . "crypto/cipher"\nfunc f() { NewGCM(b) }', ["NewGCM"]),
    ]
    failed = 0
    for name, rel, text, want in cases:
        got = [c for _, c in calls_in(rel, text)]
        if got != want:
            failed += 1
            print(f"self-test FAIL: {name}: got {got}, want {want}")
    rel = "x/protocol_iv.go"
    ALLOW[rel] = (2, "a self-test entry")
    verdicts = [
        ("an allowlisted file within its count passes", {rel: [(1, "NewGCM"), (2, "NewGCM")]}, False, False),
        ("an allowlisted file above its count fails", {rel: [(1, "NewGCM"), (2, "NewGCM"), (3, "NewGCM")]}, True, False),
        ("an allowlisted file below its count passes with a note", {rel: [(1, "NewGCM")]}, False, True),
        ("a file nobody allowlisted fails", {"x/new.go": [(9, "NewGCM")]}, True, True),
    ]
    for name, found, want_fail, want_note in verdicts:
        failures, notes = verdict(found)
        if bool(failures) != want_fail or (want_note and not notes):
            failed += 1
            print(f"self-test FAIL: {name}: failures={failures} notes={len(notes)}")
    del ALLOW[rel]
    if failed:
        return 1
    print(f"check-gcm-nonce self-test: OK — {len(cases) + len(verdicts)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv[1:] else check())
