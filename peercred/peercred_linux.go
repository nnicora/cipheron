//go:build linux

package peercred

import "golang.org/x/sys/unix"

// fromFD reads the credentials the kernel recorded for the peer of a connected unix socket: SO_PEERCRED. It answers
// them for a peer that has already hung up too: no ENOTCONN here (that is Darwin's, peercred.go).
func fromFD(fd int) (Creds, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Creds{}, err
	}
	return Creds{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
