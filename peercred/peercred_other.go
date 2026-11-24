//go:build !linux && !darwin

package peercred

import "errors"

// fromFD has no implementation on this platform: without the kernel's word for who the peer is, nothing can
// be authorized by it.
func fromFD(int) (Creds, error) {
	return Creds{}, errors.New("peer credentials are not available on this platform")
}
