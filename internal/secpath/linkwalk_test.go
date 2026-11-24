//go:build linux || darwin

package secpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// linkChain lays out base/a/key -> base/b/key2 -> base/c/real, with b (the directory holding the intermediate link)
// at bMode, and returns base/a/key.
func linkChain(t *testing.T, bMode os.FileMode) string {
	t.Helper()
	base := t.TempDir()
	a, b, c := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "c")
	for _, d := range []string{a, b, c} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(c, "real")
	if err := os.WriteFile(target, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(b, "key2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(b, "key2"), filepath.Join(a, "key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(b, bMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(b, 0o755) })
	return filepath.Join(a, "key")
}

// TestIntermediateLinkDirectory (review KC-3): the directory that holds a link in the middle of a chain is held to
// the directory rule, because whoever can write it can re-point the link at a file of their choosing.
func TestIntermediateLinkDirectory(t *testing.T) {
	key := linkChain(t, 0o777)
	if b, err := ReadFile(key, "test key", Private, 64); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("ReadFile through a link held in a 0777 directory: %q %v, want ErrUnsafe", b, err)
	} else if !strings.Contains(err.Error(), "holds a symbolic link") {
		t.Fatalf("ReadFile refusal does not name the link's directory: %v", err)
	}
	if err := CheckFile(key, "test key", Private); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("CheckFile through a link held in a 0777 directory: %v, want ErrUnsafe", err)
	}

	// The same chain with b at 0755 is a safe one.
	key = linkChain(t, 0o755)
	if b, err := ReadFile(key, "test key", Private, 64); err != nil || len(b) != 32 {
		t.Fatalf("ReadFile through a link held in a 0755 directory: %d bytes, %v", len(b), err)
	}
	if err := CheckFile(key, "test key", Private); err != nil {
		t.Fatalf("CheckFile through a link held in a 0755 directory: %v", err)
	}
	// A sticky directory others can write keeps others from re-pointing a link they do not own.
	key = linkChain(t, 0o777|os.ModeSticky)
	if _, err := ReadFile(key, "test key", Private, 64); err != nil {
		t.Fatalf("ReadFile through a link held in a 1777 directory: %v", err)
	}
}

// TestIntermediateRelativeLinkDirectory (review KC-3): a chain of relative links, a/key -> ../b/key2 -> ../c/real,
// holds b to the directory rule exactly as a chain of absolute links does.
func TestIntermediateRelativeLinkDirectory(t *testing.T) {
	// Resolved first, so the chain's only links are the two it lays out.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "c", "real"), []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../c/real", filepath.Join(base, "b", "key2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../b/key2", filepath.Join(base, "a", "key")); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(base, "a", "key")
	if b, err := ReadFile(key, "test key", Private, 64); err != nil || len(b) != 16 {
		t.Fatalf("ReadFile through relative links held in 0755 directories: %d bytes, %v", len(b), err)
	}

	b := filepath.Join(base, "b")
	if err := os.Chmod(b, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(b, 0o755) })
	if got, err := ReadFile(key, "test key", Private, 64); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("ReadFile through a relative link held in a 0777 directory: %q %v, want ErrUnsafe", got, err)
	}
	if err := CheckFile(key, "test key", Private); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("CheckFile through a relative link held in a 0777 directory: %v, want ErrUnsafe", err)
	}
}

// TestIntermediateLinkDirectoryOfDirectory: CheckDirectory follows the same walk, so a directory reached through a
// link held in a directory others can write is refused.
func TestIntermediateLinkDirectoryOfDirectory(t *testing.T) {
	base := t.TempDir()
	a, b, c := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "c")
	for _, d := range []string{a, b, filepath.Join(c, "real")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(c, "real"), filepath.Join(b, "d2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(b, "d2"), filepath.Join(a, "d")); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(filepath.Join(a, "d"), false); err != nil {
		t.Fatalf("a directory through a link held in a 0755 directory: %v", err)
	}
	if err := os.Chmod(b, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(b, 0o755) })
	if err := CheckDirectory(filepath.Join(a, "d"), false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("a directory through a link held in a 0777 directory: %v, want ErrUnsafe", err)
	}
}

// TestKubernetesDataLinks: a volume's key -> ..data/key, ..data -> ..<timestamp> links all sit in the volume's
// own directory, which is already checked, so the layout keeps working.
func TestKubernetesDataLinks(t *testing.T) {
	key := kubeVolume(t, filepath.Join(t.TempDir(), "secret"), 0o755)
	if b, err := ReadFile(key, "volume key", Public, 64); err != nil || string(b) != "x" {
		t.Fatalf("a ..data volume layout: %q %v", b, err)
	}
	if err := CheckFile(key, "volume key", Public); err != nil {
		t.Fatalf("CheckFile on a ..data volume layout: %v", err)
	}
}

// TestLinkLoopAndCap: a link loop, and a chain longer than the kernel's 40 links, are refused.
func TestLinkLoopAndCap(t *testing.T) {
	// Resolved first: a link above the temporary directory (darwin's /var) would count towards the cap.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	loop1, loop2 := filepath.Join(base, "l1"), filepath.Join(base, "l2")
	if err := os.Symlink(loop2, loop1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loop1, loop2); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(loop1, "loop", Private, 64); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("ReadFile on a link loop: %v, want ELOOP", err)
	}
	if err := CheckDirectory(loop1, false); !errors.Is(err, ErrUnsafe) || !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("CheckDirectory on a link loop: %v, want ErrUnsafe and ELOOP", err)
	}

	// A chain of n links to a real file: 40 is accepted, 41 is refused.
	chain := func(n int) string {
		dir := filepath.Join(base, fmt.Sprintf("chain%d", n))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "real")
		if err := os.WriteFile(target, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		prev := "real"
		for i := range n {
			name := fmt.Sprintf("link%d", i)
			if err := os.Symlink(prev, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			prev = name
		}
		return filepath.Join(dir, prev)
	}
	if b, err := ReadFile(chain(maxLinks), "chain", Private, 64); err != nil || string(b) != "k" {
		t.Fatalf("a chain of %d links: %q %v", maxLinks, b, err)
	}
	if _, err := ReadFile(chain(maxLinks+1), "chain", Private, 64); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a chain of %d links: %v, want ELOOP", maxLinks+1, err)
	}
}

// TestResolveLinksMatchesKernel: the walk resolves relative targets, "..", and absolute targets to the path the
// kernel opens.
func TestResolveLinksMatchesKernel(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"x/y", "z"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "x/y/f"), []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../x/y", filepath.Join(base, "z/up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "z/up/f"), filepath.Join(base, "abs")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"abs", "z/up/f", "z/../x/./y/f", "z/up/../y/f"} {
		in := filepath.Join(base, p)
		if p == "z/up/../y/f" {
			in = base + "/z/up/../y/f" // not cleaned: ".." after a link is the link target's parent
		}
		got, _, err := resolveLinks(in)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		want, err := filepath.EvalSymlinks(in)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got != want {
			t.Fatalf("%s: resolveLinks %s, EvalSymlinks %s", p, got, want)
		}
	}
}
