//go:build linux || darwin

package secpath

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nnicora/cipheron/internal/zeroize"
)

// FileKind is what a file holds, which decides the permission bits ReadFile accepts on it.
type FileKind int

const (
	// Private is a secret: a master key, a TLS private key. No group-write and no bit for others: 0400, 0440,
	// 0600 or 0640.
	Private FileKind = iota + 1
	// Public is material anyone may read but only its owner may change: a certificate chain, a CA bundle, a
	// CRL. No group-write and no other-write. Whoever could replace a CA bundle could add a CA of their own and
	// be accepted as any identity it certifies, so it is held to the same directory chain as a key.
	Public
)

// ReadFile reads the file at path, after checking that no one but root and this process's user can put
// another file in its place, and returns at most maxBytes bytes (a longer file is refused). what names the
// file in every error ("static key file", "network.tls.privateKey"). The caller wipes a Private file's bytes.
//
//   - The path must be absolute. It is resolved first, one link at a time (a Kubernetes Secret volume links each
//     key to ..data/<key>; at most 40 links); the directory it is written in, the directory holding each link met
//     on the way and the resolved file's directory, and every directory above each, are checked (CheckDirectory;
//     a sticky directory others can write is accepted here, because the file's owner is checked next) — resolve,
//     below.
//   - The resolved file is opened ONCE, with O_NOFOLLOW, and everything else is asked of that handle: it is a
//     regular file, owned by root or this user, with the bits kind allows (checkLeaf, which CheckFile shares),
//     and the bytes are read from it — never from the path again, so a file swapped in after the checks is not
//     the one read.
func ReadFile(path, what string, kind FileKind, maxBytes int) ([]byte, error) {
	resolved, shared, err := resolve(path, what, kind)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := checkLeaf(fi, path, what, kind, shared); err != nil {
		return nil, err
	}
	buf := make([]byte, maxBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		zeroize.Bytes(buf)
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if n > maxBytes {
		zeroize.Bytes(buf)
		return nil, fmt.Errorf("%w: %s %s is larger than %d bytes", ErrTooLarge, what, path, maxBytes)
	}
	return buf[:n], nil
}

// CheckFile applies ReadFile's checks to the file at path without reading it: the path absolute, the directory it
// is written in, the directory holding each link on its resolution and the directory it resolves into — and every
// directory above each — owned by root or this
// process's user and not replaceable by others (CheckDirectory), the resolved file not a symbolic link, a regular
// file owned by root or this user, with the bits kind allows (Private: no group-write and no bit for others;
// Public: no group-write and no other-write). Every refusal is ErrUnsafe (or the file system's own error for a
// path that does not resolve).
//
// It is for a reader that opens the file itself afterwards (the common SDK's SourceRef resolver): it proves that
// only root or this user can change what the path names, so the file read after it is one they put there. It does
// not bound the size, and it does not hold the file open: ReadFile, which reads through the handle it checked, is
// the stronger reader where it can be used.
func CheckFile(path, what string, kind FileKind) error {
	resolved, shared, err := resolve(path, what, kind)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnsafe, what, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s %s resolves to a symbolic link", ErrUnsafe, what, path)
	}
	return checkLeaf(fi, path, what, kind, shared)
}

// resolve is the part of ReadFile and CheckFile that comes before the file itself: kind is one, the path is
// absolute, and the directory the path is written in, the directory holding each link its resolution follows and
// the one it resolves into (each with every directory above it) are safe. It returns the resolved path, and whether
// the directory it resolves into is shared (writable by its group or others, and sticky).
func resolve(path, what string, kind FileKind) (string, bool, error) {
	if kind != Private && kind != Public {
		return "", false, fmt.Errorf("%s: no file kind", what)
	}
	return resolveChecked(path, what)
}

// resolveChecked is resolve without the file kind: ReadFile's, CheckFile's and OpenLibrary's path rule.
func resolveChecked(path, what string) (string, bool, error) {
	if !filepath.IsAbs(path) {
		return "", false, fmt.Errorf("%w: %s %q: the path must be absolute", ErrUnsafe, what, path)
	}
	resolved, holders, err := resolveLinks(path)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", what, err)
	}
	// The directory the path is written in decides who can re-point a link at its end (a Kubernetes volume's
	// key -> ..data/key); the directory holding every other link met on the way decides who can re-point that
	// link (key -> b/key2 -> c/real: b); the resolved file's directory decides who can replace the file.
	if written := filepath.Dir(filepath.Clean(path)); written != filepath.Dir(resolved) {
		if err := CheckDirectory(written, false); err != nil {
			return "", false, fmt.Errorf("%s %s: %w", what, path, err)
		}
	}
	if err := walkHolders(holders); err != nil {
		return "", false, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if err := CheckDirectory(filepath.Dir(resolved), false); err != nil {
		return "", false, fmt.Errorf("%s %s: %w", what, path, err)
	}
	shared, err := sharedDirectory(filepath.Dir(resolved))
	if err != nil {
		return "", false, fmt.Errorf("%s %s: %w", what, path, err)
	}
	return resolved, shared, nil
}

// checkLeaf holds the file fi describes (path, as written, names it in errors) to kind's rules: a regular file,
// owned by root or this user, with the permission bits kind allows, and with a single hard link when it is Private
// or its directory is shared.
func checkLeaf(fi os.FileInfo, path, what string, kind FileKind, shared bool) error {
	if err := checkOwnedFile(fi, path, what, kind == Private || shared); err != nil {
		return err
	}
	perm := fi.Mode().Perm()
	switch kind {
	case Private:
		if perm&0o027 != 0 {
			return fmt.Errorf("%w: %s %s has mode %v: it must not be writable by its group nor readable or "+
				"writable by others (0400, 0440, 0600 or 0640)", ErrUnsafe, what, path, perm)
		}
	case Public:
		if perm&0o022 != 0 {
			return fmt.Errorf("%w: %s %s has mode %v: it must not be writable by its group or by others "+
				"(0444, 0644 or stricter)", ErrUnsafe, what, path, perm)
		}
	}
	return nil
}

// checkOwnedFile holds the file fi describes to the rule every file kind shares: a regular file, owned by root or this
// user, and — with singleLink — one hard link only. A second name of a file is made by whoever can write the directory
// it is made in: in a shared directory, or beside a private file, it may be someone else's name for a file root owns.
func checkOwnedFile(fi os.FileInfo, path, what string, singleLink bool) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s %s is not a regular file", ErrUnsafe, what, path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s %s: its owner cannot be read", ErrUnsafe, what, path)
	}
	if euid := uint32(os.Geteuid()); st.Uid != 0 && st.Uid != euid {
		return fmt.Errorf("%w: %s %s is owned by uid %d, neither root nor this process's uid %d", ErrUnsafe, what, path, st.Uid, euid)
	}
	if singleLink && st.Nlink > 1 {
		return fmt.Errorf("%w: %s %s has %d hard links: it must have one, because it is a private file or its directory "+
			"is writable by its group or by others", ErrUnsafe, what, path, st.Nlink)
	}
	return nil
}

// checkProgram holds the program or library fi describes to the executable rule: checkOwnedFile, and writable by
// neither its group nor others.
func checkProgram(fi os.FileInfo, path, what string, shared bool) error {
	if err := checkOwnedFile(fi, path, what, shared); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s %s has mode %v: it must not be writable by its group or by others (0755, 0555 or "+
			"stricter)", ErrUnsafe, what, path, perm)
	}
	return nil
}

// CheckExecutable checks the program at path before it is started as a plugin of this process: a program that
// returns master-key material (a seal plugin) is as sensitive as the key itself, and whoever can put another
// binary at its path runs their code with everything the process hands it. what names it in every error
// ("keyHierarchy.MasterKey.seal.shamir.shards[1].plugin.path").
//
//   - The path must be absolute and clean, and NO component of it may be a symbolic link: it is compared with
//     what the kernel resolves (filepath.EvalSymlinks), so the binary that is checked is the one that is
//     started, and a link that someone could re-point later is not on the way.
//   - Every directory above it follows CheckDirectory's rule: owned by root or this process's user, not
//     writable by its group or others unless sticky.
//   - The file itself is a regular file owned by root or this process's user, writable by neither its group nor
//     others.
//
// The check does not pin the program's content; a plugin's `checksum` does that (and the production posture
// requires it). It narrows who can replace the program between the check and the start to root and this user.
func CheckExecutable(path, what string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s %q is not an absolute path", ErrUnsafe, what, path)
	}
	if clean := filepath.Clean(path); clean != path {
		return fmt.Errorf("%w: %s %q is not a clean path (write %q)", ErrUnsafe, what, path, clean)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnsafe, what, err)
	}
	if resolved != path {
		return fmt.Errorf("%w: %s %s has a symbolic link on its path (it resolves to %s): name the program by its "+
			"real path", ErrUnsafe, what, path, resolved)
	}
	if err := CheckDirectory(filepath.Dir(path), false); err != nil {
		return fmt.Errorf("%s %s: %w", what, path, err)
	}
	shared, err := sharedDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("%s %s: %w", what, path, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnsafe, what, err)
	}
	return checkProgram(fi, path, what, shared)
}

// OpenLibrary opens the shared library at path to be loaded into this process, and returns it open with the path it
// resolves to. Loading a library runs its code inside the process at once (its constructors, at dlopen), so it is
// held to the executable rule, as a plugin program is (CheckExecutable), before anything loads it. what names it in
// every error ("auth.module_path").
//
//   - The path must be absolute and clean. Unlike a plugin program's, it may go through symbolic links — a vendor
//     installs libfoo.so -> libfoo.so.2.1 — and it is resolved one link at a time as ReadFile resolves a path: the
//     directory it is written in, the directory holding each link met on the way and the directory it resolves into,
//     with every directory above each, are owned by root or this process's user and are not writable by their group
//     or others unless sticky, and a link in a sticky directory is owned by root or this user. The directory it
//     resolves into is where the library's own $ORIGIN dependencies are found, so it is held to the rule too.
//   - The resolved file is opened once, with O_NOFOLLOW, and the handle is checked: a regular file owned by root or
//     this user, writable by neither its group nor others, with a single hard link when its directory is shared.
//
// The caller reads the bytes it pins from the returned handle and loads the library from that same handle where the
// platform allows (Linux: /proc/self/fd/N), then closes it.
func OpenLibrary(path, what string) (*os.File, string, error) {
	if clean := filepath.Clean(path); filepath.IsAbs(path) && clean != path {
		return nil, "", fmt.Errorf("%w: %s %q is not a clean path (write %q)", ErrUnsafe, what, path, clean)
	}
	resolved, shared, err := resolveChecked(path, what)
	if err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", what, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("%s: %w", what, err)
	}
	if err := checkProgram(fi, path, what, shared); err != nil {
		_ = f.Close()
		return nil, "", err
	}
	return f, resolved, nil
}
