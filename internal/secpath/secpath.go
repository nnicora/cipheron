// Package secpath decides whether a path is a safe place for something only this process's user (or root) may
// replace: the socket the clients trust, a key file, a credential. The client uses it for the files it reads (a
// request key, TLS material, the pins directory).
//
// A file is only as safe as every directory on its way from the root: whoever can write ANY directory on that
// path can rename the next component away and put their own in its place — their own socket, which the
// clients would then seal their plaintexts to, or their own key file. So every directory from "/" down to the
// one asked about must be owned by root or by this process's user, and must not be writable by its group or
// by others unless it has the sticky bit (as /tmp has), which keeps others from renaming or removing what
// they do not own. The directory itself may also be held to the stricter rule of no group or other write at
// all (the socket's directory: a sticky directory others can write still lets them occupy the path while
// cipheron is down).
//
// The path is checked as written, component by component (Lstat: a symbolic link on the way is checked as an
// entry of the directory that holds it, which the walk has already checked), and it is resolved one link at a
// time as the kernel resolves it (resolveLinks): the directory that holds every link met on the way, with every
// directory above it, is held to the same rule — whoever can write it can re-point the link — and so is the
// directory the path resolves into.
//
// A sticky directory others can write still lets them create names of their own in it. So a symbolic link met in
// such a directory must be owned by root or this process's user (the kernel's fs.protected_symlinks rule), and a
// regular file read from one must have a single hard link — a second name, made by someone else, of a file root
// owns would pass the owner check. A private file must have a single hard link wherever it is.
package secpath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrUnsafe is in the chain of every refusal.
var ErrUnsafe = errors.New("unsafe path")

// ErrTooLarge is in the chain of ReadFile's refusal of a file larger than its bound.
var ErrTooLarge = errors.New("file too large")

// maxLinks is how many symbolic links a resolution may follow, the kernel's own limit (Linux MAXSYMLINKS). A
// longer chain, or a loop, is refused with ELOOP.
const maxLinks = 40

// CheckDirectory checks dir and every directory above it, as written and as resolved, and the directory that holds
// each symbolic link the resolution follows (with every directory above it). With strictLeaf, dir itself must not
// be writable by its group or others even with the sticky bit, and must not be a symbolic link.
func CheckDirectory(dir string, strictLeaf bool) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %s is not an absolute path", ErrUnsafe, dir)
	}
	dir = filepath.Clean(dir)
	if err := walk(dir, strictLeaf); err != nil {
		return err
	}
	resolved, holders, err := resolveLinks(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	if err := walkHolders(holders); err != nil {
		return err
	}
	if resolved != dir {
		return walk(resolved, strictLeaf)
	}
	return nil
}

// walkHolders checks every directory that holds a link a resolution followed, each with every directory above it.
// They are resolved paths (no link on them), so the walk as written is the whole check.
func walkHolders(holders []string) error {
	for _, h := range holders {
		if err := walk(h, false); err != nil {
			return fmt.Errorf("%w (it holds a symbolic link on the path)", err)
		}
	}
	return nil
}

// resolveLinks resolves the absolute path p as the kernel does, one component at a time (Lstat, Readlink), and
// returns the resolved path and every directory, resolved and once each, that holds a symbolic link the resolution
// followed. filepath.EvalSymlinks gives the same resolved path but not the directories on the way: a link that leads
// to another link in a third directory would leave that directory unchecked, and whoever can write it could re-point
// the second link. More than maxLinks links (a loop included) is ELOOP.
func resolveLinks(p string) (string, []string, error) {
	if !filepath.IsAbs(p) {
		return "", nil, fmt.Errorf("%s is not an absolute path", p)
	}
	cur, rest := "/", p
	var holders []string
	links := 0
	for {
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			return cur, holders, nil
		}
		comp := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			comp, rest = rest[:i], rest[i:]
		} else {
			rest = ""
		}
		switch comp {
		case ".":
			continue
		case "..":
			// cur has no link on it, so its parent is the kernel's "..".
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", nil, err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		if links > maxLinks {
			return "", nil, &fs.PathError{Op: "resolve", Path: p, Err: syscall.ELOOP}
		}
		if err := checkLinkOwner(cur, next, fi); err != nil {
			return "", nil, err
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", nil, err
		}
		if target == "" {
			return "", nil, &fs.PathError{Op: "readlink", Path: next, Err: syscall.ENOENT}
		}
		if !contains(holders, cur) {
			holders = append(holders, cur)
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = target + "/" + rest
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// prefixes are "/", "/a", "/a/b", ... dir.
func prefixes(dir string) []string {
	out := []string{"/"}
	cur := ""
	for _, part := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if part == "" {
			continue
		}
		cur += "/" + part
		out = append(out, cur)
	}
	return out
}

func walk(dir string, strictLeaf bool) error {
	ps := prefixes(dir)
	for i, p := range ps {
		if err := checkOne(p, i == len(ps)-1, strictLeaf); err != nil {
			return err
		}
	}
	return nil
}
