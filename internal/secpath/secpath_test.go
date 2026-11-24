//go:build linux || darwin

package secpath

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPrefixes(t *testing.T) {
	if got := prefixes("/a/b/c"); !slices.Equal(got, []string{"/", "/a", "/a/b", "/a/b/c"}) {
		t.Fatalf("prefixes = %v", got)
	}
	if got := prefixes("/"); !slices.Equal(got, []string{"/"}) {
		t.Fatalf("prefixes(/) = %v", got)
	}
}

func TestCheckDirectory(t *testing.T) {
	base := t.TempDir()
	mk := func(rel string, mode os.FileMode) string {
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	safe := mk("safe/leaf", 0o755)
	if err := CheckDirectory(safe, true); err != nil {
		t.Fatalf("a safe directory: %v", err)
	}
	if err := CheckDirectory("relative/dir", false); err == nil {
		t.Fatal("a relative path passed")
	}

	open := mk("open", 0o777)
	leaf := filepath.Join(open, "leaf")
	if err := os.Mkdir(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(leaf, false); err == nil {
		t.Fatal("a world-writable non-sticky ancestor passed")
	}
	if err := os.Chmod(open, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(leaf, true); err != nil {
		t.Fatalf("a sticky ancestor owned by this user: %v", err)
	}
	if err := CheckDirectory(open, true); err == nil {
		t.Fatal("a world-writable leaf passed the strict rule")
	}
	if err := CheckDirectory(open, false); err != nil {
		t.Fatalf("a sticky leaf, non-strict: %v", err)
	}

	// A link from a safe place into an unsafe one is judged by where it leads.
	bad := mk("bad", 0o777)
	link := filepath.Join(safe, "link")
	if err := os.Symlink(bad, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(link, false); err == nil {
		t.Fatal("a link into a world-writable directory passed")
	}
	if err := CheckDirectory(link, true); err == nil {
		t.Fatal("a symbolic-link leaf passed the strict rule")
	}
	if err := CheckDirectory(filepath.Join(base, "missing"), false); err == nil {
		t.Fatal("a missing directory passed")
	}
}

// TestCheckExecutable (gap review S1): an external seal plugin's program is refused unless its path is absolute,
// has no symbolic link on it, and neither the program nor a directory above it can be replaced by anyone but
// root or this user.
func TestCheckExecutable(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a link to /private/var
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(dir, "seal-plugin")
	if err := os.WriteFile(prog, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(prog, "plugin"); err != nil {
		t.Fatalf("a safe program: %v", err)
	}

	refused := func(name, path string) {
		t.Helper()
		if err := CheckExecutable(path, "plugin"); err == nil {
			t.Fatalf("%s: %s passed", name, path)
		}
	}
	refused("relative", "bin/seal-plugin")
	refused("not clean", dir+"/../bin/seal-plugin")
	refused("missing", filepath.Join(dir, "missing"))
	refused("a directory", dir)

	fileLink := filepath.Join(dir, "link")
	if err := os.Symlink(prog, fileLink); err != nil {
		t.Fatal(err)
	}
	refused("a symbolic link to the program", fileLink)

	dirLink := filepath.Join(base, "binlink")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatal(err)
	}
	refused("a symbolic link to its directory", filepath.Join(dirLink, "seal-plugin"))

	if err := os.Chmod(prog, 0o775); err != nil {
		t.Fatal(err)
	}
	refused("a group-writable program", prog)
	if err := os.Chmod(prog, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	refused("a world-writable directory without the sticky bit", prog)
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(prog, "plugin"); err != nil {
		t.Fatalf("a sticky directory above an owned program (the secpath rule): %v", err)
	}
}

// TestCheckFileRefusesWhatReadFileRefuses (gap review S3, owner decision 2026-11-11): CheckFile holds a file to
// ReadFile's rules without reading it — the same refusals, for a reader that opens the file itself afterwards (the
// SDK's SourceRef resolver). A file in a Kubernetes-style volume (the key a link into ..data) passes both.
func TestCheckFileRefusesWhatReadFileRefuses(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(rel string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	both := func(path string, kind FileKind) (checkErr, readErr error) {
		_, readErr = ReadFile(path, "test file", kind, 64)
		return CheckFile(path, "test file", kind), readErr
	}

	for name, c := range map[string]struct {
		path string
		kind FileKind
	}{
		"a private 0400 file": {write("ok/0400", 0o400), Private},
		"a private 0640 file": {write("ok/0640", 0o640), Private},
		"a public 0644 file":  {write("ok/0644", 0o644), Public},
	} {
		if ce, re := both(c.path, c.kind); ce != nil || re != nil {
			t.Errorf("%s: CheckFile %v, ReadFile %v", name, ce, re)
		}
	}

	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	inOpen := write("open/key", 0o600)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(base, "links")
	if err := os.Mkdir(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A link in a safe directory into a world-writable one: refused for where it leads.
	linkIn := filepath.Join(linkDir, "key")
	if err := os.Symlink(inOpen, linkIn); err != nil {
		t.Fatal(err)
	}
	// A link in a world-writable directory into a safe file: refused for who can re-point it.
	safe := write("safe/key", 0o600)
	linkOut := filepath.Join(open, "link")
	if err := os.Symlink(safe, linkOut); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path string
		kind FileKind
	}{
		"private, world-readable":                {write("bad/0644", 0o644), Private},
		"private, group-writable":                {write("bad/0660", 0o660), Private},
		"public, world-writable":                 {write("bad/0666", 0o666), Public},
		"public, group-writable":                 {write("bad/0664", 0o664), Public},
		"relative":                               {"bad/0644", Private},
		"missing":                                {filepath.Join(base, "missing"), Private},
		"a directory":                            {filepath.Join(base, "ok"), Private},
		"in a world-writable directory":          {inOpen, Private},
		"a link into a world-writable directory": {linkIn, Private},
		"a link in a world-writable directory":   {linkOut, Private},
	} {
		ce, re := both(c.path, c.kind)
		if ce == nil || re == nil {
			t.Errorf("%s: CheckFile %v, ReadFile %v — want both refused", name, ce, re)
		}
		if ce != nil && strings.Contains(ce.Error(), "secret") {
			t.Errorf("%s: the refusal carries the content: %v", name, ce)
		}
	}
	if err := CheckFile(write("nokind", 0o600), "test file", 0); err == nil {
		t.Fatal("no file kind accepted")
	}
}
