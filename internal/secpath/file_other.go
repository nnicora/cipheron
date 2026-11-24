//go:build !linux && !darwin

package secpath

import (
	"fmt"
	"os"
)

// FileKind is what a file holds.
type FileKind int

const (
	// Private is a secret.
	Private FileKind = iota + 1
	// Public is material anyone may read but only its owner may change.
	Public
)

// ReadFile has no implementation on this platform: the file's owner and handle cannot be checked.
func ReadFile(path, what string, _ FileKind, _ int) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s %s: files are read on Linux and Darwin only", ErrUnsafe, what, path)
}

// CheckExecutable has no implementation on this platform: the program's owner cannot be checked.
func CheckExecutable(path, what string) error {
	return fmt.Errorf("%w: %s %s: programs are checked on Linux and Darwin only", ErrUnsafe, what, path)
}

// CheckFile has no implementation on this platform: the file's owner cannot be checked.
func CheckFile(path, what string, _ FileKind) error {
	return fmt.Errorf("%w: %s %s: files are checked on Linux and Darwin only", ErrUnsafe, what, path)
}

// OpenLibrary has no implementation on this platform: the library's owner cannot be checked.
func OpenLibrary(path, what string) (*os.File, string, error) {
	return nil, "", fmt.Errorf("%w: %s %s: libraries are checked on Linux and Darwin only", ErrUnsafe, what, path)
}
