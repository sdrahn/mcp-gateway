package transport

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// PeerCred is the identity evidence of a local client, provided by the
// kernel at connect time.
type PeerCred struct {
	PID uint32
	UID uint32
	GID uint32
	// Label is the client's SELinux context (SO_PEERSEC), empty when
	// SELinux is disabled.
	Label string
}

// UnixConn is an accepted local client connection.
type UnixConn struct {
	*net.UnixConn
	Peer PeerCred
}

// UnixListener accepts local clients on a unix socket.
type UnixListener struct {
	l    *net.UnixListener
	path string
}

// ListenUnix creates the socket at path (replacing a stale one), sets its
// mode, and, if group is non-empty, its group.
func ListenUnix(path string, mode os.FileMode, group string) (*UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(path, -1, gid); err != nil {
			_ = l.Close()
			return nil, err
		}
	}
	return &UnixListener{l: l, path: path}, nil
}

// Accept waits for the next client and reads its peer credentials.
func (l *UnixListener) Accept() (*UnixConn, error) {
	c, err := l.l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	peer, err := peerCred(c)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("reading peer credentials: %w", err)
	}
	return &UnixConn{UnixConn: c, Peer: peer}, nil
}

// Close stops listening and removes the socket.
func (l *UnixListener) Close() error { return l.l.Close() }

// Addr returns the socket path.
func (l *UnixListener) Addr() string { return l.path }

func peerCred(c *net.UnixConn) (PeerCred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return PeerCred{}, err
	}
	var (
		p      PeerCred
		optErr error
	)
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			optErr = err
			return
		}
		p.PID, p.UID, p.GID = uint32(cred.Pid), cred.Uid, cred.Gid
		// ENOPROTOOPT / EINVAL without an LSM providing labels: no label.
		label, err := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_PEERSEC)
		if err == nil {
			p.Label = strings.TrimRight(label, "\x00")
		} else if !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EINVAL) {
			optErr = err
		}
	})
	if err != nil {
		return PeerCred{}, err
	}
	return p, optErr
}
