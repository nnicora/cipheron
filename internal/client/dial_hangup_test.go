//go:build linux || darwin

package client

// dial_hangup_test.go — a socket server that closed the connection before WithServerUID's check read its
// credentials is not refused as the wrong server: cipheron closes, as it accepts it, a connection from a process no
// profile lists, and Darwin then answers ENOTCONN for the peer's pid (peercred). Before errServerHungUp that race
// failed the caller's calls with ErrServerIdentity instead of leaving them waiting until their deadline.

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAServerThatHungUpBeforeTheUIDCheckIsNotAnIdentityRefusal(t *testing.T) {
	dir, err := os.MkdirTemp("", "hu") // short: a unix socket path is limited to ~104 bytes on Darwin
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err == nil {
			err = c.Close() // the server hangs up at accept
		}
		accepted <- err
	}()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	// The client has seen the hang-up: the check below runs on a connection whose peer is gone, every time.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("reading a connection the server closed: %v, want EOF", err)
	}

	err = checkServerUID(c, sock, uint32(os.Getuid()))
	// Linux reads the credentials recorded at connect whatever the peer's state (nil); Darwin cannot (errServerHungUp).
	if err != nil && !errors.Is(err, errServerHungUp) {
		t.Fatalf("the check of a server that hung up: %v, want nil or errServerHungUp", err)
	}
	var idErr *identityError
	if errors.As(err, &idErr) {
		t.Fatalf("a server that hung up was refused as the wrong server: %v", err)
	}
}
