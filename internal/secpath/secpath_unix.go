//go:build linux || darwin

package secpath

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func checkOne(p string, leaf, strictLeaf bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if leaf && strictLeaf {
			return fmt.Errorf("%w: %s is a symbolic link", ErrUnsafe, p)
		}
		// Who can replace the link is decided by the directory holding it, already checked; where it leads
		// is checked on the resolved path.
		return nil
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafe, p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: the owner of %s cannot be read", ErrUnsafe, p)
	}
	if euid := uint32(os.Geteuid()); st.Uid != 0 && st.Uid != euid {
		return fmt.Errorf("%w: %s is owned by uid %d, neither root nor this process's uid %d", ErrUnsafe, p, st.Uid, euid)
	}
	perm := fi.Mode().Perm()
	if perm&0o022 == 0 {
		return nil
	}
	if leaf && strictLeaf {
		return fmt.Errorf("%w: %s is writable by its group or by others (mode %v); make it 0755 or stricter", ErrUnsafe, p, perm)
	}
	if fi.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%w: %s is writable by its group or by others (mode %v) without the sticky bit: anyone who can "+
			"write it can rename what is below it and put their own in its place", ErrUnsafe, p, perm)
	}
	return nil
}

// checkLinkOwner holds the symbolic link fi describes, met at link in the directory holder (resolved: no link on it),
// to the rule the kernel's fs.protected_symlinks applies before it follows one: in a directory its group or others can
// write — a sticky one, the only kind the directory rule lets through — the link must be owned by root or this
// process's user. The sticky bit keeps others from renaming or removing what they do not own, but not from creating
// a name of their own there: a link they planted under a name the configuration uses would point the read wherever
// they chose.
func checkLinkOwner(holder, link string, fi fs.FileInfo) error {
	hfi, err := os.Lstat(holder)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: the owner of the symbolic link %s cannot be read", ErrUnsafe, link)
	}
	return linkOwnerRule(link, holder, hfi.Mode(), st.Uid, uint32(linkOwnerEUID()))
}

// linkOwnerEUID is the uid besides root that checkLinkOwner accepts as a link's owner: this process's effective uid.
// It is a variable for one reason: a test cannot make a link another uid owns without root, so it reads through a
// link of its own as a process of another uid would, by answering another uid here.
var linkOwnerEUID = os.Geteuid

// linkOwnerRule is checkLinkOwner's decision: a link owned by uid, in a directory of mode holderMode, read by a process
// of euid.
func linkOwnerRule(link, holder string, holderMode fs.FileMode, uid, euid uint32) error {
	if holderMode.Perm()&0o022 == 0 || uid == 0 || uid == euid {
		return nil
	}
	return fmt.Errorf("%w: the symbolic link %s is owned by uid %d, neither root nor this process's uid %d, and %s, "+
		"which holds it, is writable by its group or by others (mode %v): anyone who can write there can plant a link "+
		"of their own", ErrUnsafe, link, uid, euid, holder, holderMode.Perm())
}

// sharedDirectory reports whether the directory dir (resolved: no link on it) is writable by its group or by others —
// sticky, since the directory rule refuses any other — so that an entry in it may have been made by someone else.
func sharedDirectory(dir string) (bool, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	return fi.Mode().Perm()&0o022 != 0, nil
}
