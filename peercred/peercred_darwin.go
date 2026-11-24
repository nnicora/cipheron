//go:build darwin

package peercred

import (
	"errors"

	"golang.org/x/sys/unix"
)

// xucredVersion is XUCRED_VERSION from <sys/ucred.h>; golang.org/x/sys/unix does not define it.
const xucredVersion = 0

// fromFD reads the credentials the kernel recorded for the peer of a connected unix socket: LOCAL_PEERCRED,
// what getpeereid(3) reads (the effective user id, and the effective group id as the first group), and
// LOCAL_PEERPID.
func fromFD(fd int) (Creds, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Creds{}, err
	}
	if cred.Version != xucredVersion || cred.Ngroups < 1 {
		return Creds{}, errors.New("LOCAL_PEERCRED returned no group")
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return Creds{}, err
	}
	return Creds{UID: cred.Uid, GID: cred.Groups[0], PID: int32(pid)}, nil
}
