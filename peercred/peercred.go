// Package peercred reads the credentials the kernel recorded for the other end of a connected unix socket:
// SO_PEERCRED on Linux, LOCAL_PEERCRED (what getpeereid(3) reads) and LOCAL_PEERPID on Darwin. On the
// accepting side they are the connecting process's; on the connecting side, the listening process's. Nothing
// the peer sends can change them. Other platforms have no implementation and every call fails.
//
// A peer that has already hung up: Linux's SO_PEERCRED answers the credentials recorded at connect whatever the
// peer's state; Darwin answers ENOTCONN (most likely from LOCAL_PEERPID, possibly LOCAL_PEERCRED).
package peercred

import (
	"fmt"
	"net"
)

// Creds are a peer's user id, (effective) group id and process id, as recorded when the connection was made.
type Creds struct {
	UID uint32
	GID uint32
	PID int32
}

// Of reads c's peer credentials.
func Of(c *net.UnixConn) (Creds, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Creds{}, err
	}
	var creds Creds
	var credErr error
	if err := raw.Control(func(fd uintptr) { creds, credErr = fromFD(int(fd)) }); err != nil {
		return Creds{}, err
	}
	if credErr != nil {
		return Creds{}, fmt.Errorf("peer credentials: %w", credErr)
	}
	return creds, nil
}
