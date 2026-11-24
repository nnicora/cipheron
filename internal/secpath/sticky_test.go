//go:build linux || darwin

package secpath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stickyDir makes a directory of this user's at mode 1777: writable by everyone, sticky, as /tmp is.
func stickyDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
	return d
}

func writeFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("0123456789abcdef"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestLinkOwnerRule (review RP-4): a symbolic link in a directory its group or others can write must be owned by root
// or this process's user — fs.protected_symlinks' rule. A test cannot make a link owned by another uid without root,
// so the decision is asked of the internal function that resolveLinks calls with the link's real owner.
func TestLinkOwnerRule(t *testing.T) {
	const euid, stranger = 501, 4242
	sticky := fs.ModeDir | fs.ModeSticky | 0o777
	cases := []struct {
		name   string
		mode   fs.FileMode
		uid    uint32
		refuse bool
	}{
		{"a stranger's link in a sticky directory others can write", sticky, stranger, true},
		{"a stranger's link in a sticky directory its group can write", fs.ModeDir | fs.ModeSticky | 0o775, stranger, true},
		{"root's link in a sticky directory", sticky, 0, false},
		{"this user's link in a sticky directory", sticky, euid, false},
		{"a stranger's link in a directory nobody else can write", fs.ModeDir | 0o755, stranger, false},
	}
	for _, c := range cases {
		err := linkOwnerRule("/s/key", "/s", c.mode, c.uid, euid)
		if c.refuse != (err != nil) {
			t.Errorf("%s: %v, want refused=%v", c.name, err, c.refuse)
		}
		if err != nil && !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s: %v is not ErrUnsafe", c.name, err)
		}
	}
}

// TestOwnLinkInStickyDirectory: a link of this user's in a sticky directory, to a file in a safe one, still reads —
// the link-owner rule refuses only a link someone else made.
func TestOwnLinkInStickyDirectory(t *testing.T) {
	s := stickyDir(t)
	target := filepath.Join(t.TempDir(), "real")
	writeFile(t, target, 0o644)
	key := filepath.Join(s, "key")
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(key, "test file", Public, 64); err != nil || len(b) != 16 {
		t.Fatalf("ReadFile through this user's link in a sticky directory: %d bytes, %v", len(b), err)
	}
	if err := CheckFile(key, "test file", Public); err != nil {
		t.Fatalf("CheckFile through this user's link in a sticky directory: %v", err)
	}
}

// TestAStrangersLinkInAStickyDirectoryIsRefused (review RP-4): ReadFile, CheckFile and OpenLibrary each follow a
// path through resolveLinks, which holds every link to the link-owner rule. The link here is this user's, so the
// process reads it once as itself (accepted), and once as a process of another uid would (linkOwnerEUID answers that
// uid): the link is then a stranger's link in a sticky directory, and all three refuse it, naming the link.
func TestAStrangersLinkInAStickyDirectoryIsRefused(t *testing.T) {
	s := stickyDir(t)
	target := filepath.Join(t.TempDir(), "real")
	writeFile(t, target, 0o755)
	key := filepath.Join(s, "key")
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	reads := map[string]func() error{
		"ReadFile": func() error {
			_, err := ReadFile(key, "test file", Public, 64)
			return err
		},
		"CheckFile": func() error { return CheckFile(key, "test file", Public) },
		"OpenLibrary": func() error {
			f, _, err := OpenLibrary(key, "test module")
			if f != nil {
				_ = f.Close()
			}
			return err
		},
	}
	for name, read := range reads {
		if err := read(); err != nil {
			t.Fatalf("%s through this user's own link: %v", name, err)
		}
	}

	stranger := os.Geteuid() + 4242
	linkOwnerEUID = func() int { return stranger }
	t.Cleanup(func() { linkOwnerEUID = os.Geteuid })
	for name, read := range reads {
		err := read()
		if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "symbolic link") ||
			!strings.Contains(err.Error(), "neither root nor this process's uid") {
			t.Errorf("%s through a link another uid owns, in a sticky directory: %v, want ErrUnsafe naming the link's owner", name, err)
		}
	}
}

// TestHardLinkInStickyDirectory (review RP-4): a regular file with a second hard link, in a directory others can
// write, is refused — someone else's second name for a file root owns would pass the owner check. With one link it
// reads.
func TestHardLinkInStickyDirectory(t *testing.T) {
	s := stickyDir(t)
	f := filepath.Join(s, "file")
	writeFile(t, f, 0o644)
	if _, err := ReadFile(f, "test file", Public, 64); err != nil {
		t.Fatalf("one hard link in a sticky directory: %v", err)
	}
	other := filepath.Join(s, "other")
	if err := os.Link(f, other); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(f, "test file", Public, 64); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("ReadFile of a file with two hard links in a sticky directory: %v, want ErrUnsafe naming the hard links", err)
	}
	if err := CheckFile(f, "test file", Public); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("CheckFile of a file with two hard links in a sticky directory: %v, want ErrUnsafe", err)
	}
}

// TestPrivateHardLink (review RP-4): a private file with a second hard link is refused wherever it is; a public file
// with one in a directory nobody else can write reads.
func TestPrivateHardLink(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "key")
	writeFile(t, f, 0o600)
	if err := os.Link(f, filepath.Join(d, "copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(f, "test key", Private, 64); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("ReadFile of a private file with two hard links: %v, want ErrUnsafe", err)
	}
	if err := CheckFile(f, "test key", Private); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("CheckFile of a private file with two hard links: %v, want ErrUnsafe", err)
	}
	if _, err := ReadFile(f, "test file", Public, 64); err != nil {
		t.Fatalf("ReadFile of a public file with two hard links in a 0700 directory: %v", err)
	}
}

// TestReadFileTooLarge: the bound's refusal carries ErrTooLarge, so a caller can say so without the path.
func TestReadFileTooLarge(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big")
	writeFile(t, f, 0o644)
	if _, err := ReadFile(f, "test file", Public, 8); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile of 16 bytes bounded at 8: %v, want ErrTooLarge", err)
	}
}

// TestCheckExecutableHardLinkInStickyDirectory (review RP-4): the program rule refuses a second hard link in a shared
// directory too.
func TestCheckExecutableHardLinkInStickyDirectory(t *testing.T) {
	s, err := filepath.EvalSymlinks(stickyDir(t)) // a program is named by its real path
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s, "plugin")
	writeFile(t, p, 0o755)
	if err := CheckExecutable(p, "test plugin"); err != nil {
		t.Fatalf("one hard link: %v", err)
	}
	if err := os.Link(p, filepath.Join(s, "plugin2")); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(p, "test plugin"); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("two hard links in a sticky directory: %v, want ErrUnsafe", err)
	}
}

// TestOpenLibrary (review SP-1): the library rule — the executable rule with vendor symbolic links allowed through
// safe directories — is applied before anything can load the file, and the handle returned is the file checked.
func TestOpenLibrary(t *testing.T) {
	t.Run("a vendor symbolic link in a 0755 directory", func(t *testing.T) {
		d := t.TempDir()
		target := filepath.Join(d, "libvendor.so.2.1")
		writeFile(t, target, 0o755)
		link := filepath.Join(d, "libvendor.so")
		if err := os.Symlink("libvendor.so.2.1", link); err != nil {
			t.Fatal(err)
		}
		f, resolved, err := OpenLibrary(link, "auth.module_path")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		want, _ := filepath.EvalSymlinks(target)
		if resolved != want {
			t.Fatalf("resolved %s, want %s", resolved, want)
		}
		got, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if wfi, _ := os.Stat(target); !os.SameFile(got, wfi) {
			t.Fatal("the handle is not the library's file")
		}
	})

	refused := map[string]func(t *testing.T) string{
		"a library writable by others": func(t *testing.T) string {
			t.Helper()
			p := filepath.Join(t.TempDir(), "lib.so")
			writeFile(t, p, 0o666)
			return p
		},
		"a library in a directory writable by others without the sticky bit": func(t *testing.T) string {
			t.Helper()
			d := filepath.Join(t.TempDir(), "open")
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(d, "lib.so")
			writeFile(t, p, 0o755)
			if err := os.Chmod(d, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
			return p
		},
		"a symbolic link held in a directory writable by others": func(t *testing.T) string {
			t.Helper()
			safe := t.TempDir()
			target := filepath.Join(safe, "lib.so")
			writeFile(t, target, 0o755)
			open := filepath.Join(t.TempDir(), "open")
			if err := os.Mkdir(open, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(open, "lib.so")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(open, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(open, 0o755) })
			entry := filepath.Join(safe, "entry.so")
			if err := os.Symlink(filepath.Join(open, "lib.so"), entry); err != nil {
				t.Fatal(err)
			}
			return entry
		},
		"a library with a second hard link in a sticky directory": func(t *testing.T) string {
			t.Helper()
			s := stickyDir(t)
			p := filepath.Join(s, "lib.so")
			writeFile(t, p, 0o755)
			if err := os.Link(p, filepath.Join(s, "lib2.so")); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"a relative path":          func(*testing.T) string { return "lib/lib.so" },
		"a path not in clean form": func(t *testing.T) string { t.Helper(); return t.TempDir() + "/x/../lib.so" },
		"not a regular file":       func(t *testing.T) string { t.Helper(); return t.TempDir() },
	}
	for name, mk := range refused {
		t.Run(name, func(t *testing.T) {
			f, _, err := OpenLibrary(mk(t), "auth.module_path")
			if f != nil {
				_ = f.Close()
			}
			if !errors.Is(err, ErrUnsafe) {
				t.Fatalf("%v, want ErrUnsafe", err)
			}
			if !strings.Contains(err.Error(), "auth.module_path") {
				t.Fatalf("the refusal does not name the setting: %v", err)
			}
		})
	}
}
