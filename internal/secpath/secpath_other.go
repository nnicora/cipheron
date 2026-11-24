//go:build !linux && !darwin

package secpath

import (
	"fmt"
	"io/fs"
)

func checkOne(p string, _, _ bool) error {
	return fmt.Errorf("%w: %s: directory ownership and modes are checked on Linux and Darwin only", ErrUnsafe, p)
}

func checkLinkOwner(_, link string, _ fs.FileInfo) error {
	return fmt.Errorf("%w: %s: link owners are checked on Linux and Darwin only", ErrUnsafe, link)
}
