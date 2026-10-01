package audit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// auditTrustedApp is AUDIT_TRUSTED_APP (linux/audit.h): a free-form
// message from a trusted application.
const auditTrustedApp = 1121

// Netlink sends messages to the kernel audit subsystem. It needs
// CAP_AUDIT_WRITE (and, with SELinux, the netlink_audit_socket
// permissions from logging_send_audit_msgs).
type Netlink struct {
	mu  sync.Mutex
	fd  int
	seq uint32
}

// OpenNetlink opens the audit netlink socket and checks that messages are
// accepted, so misconfiguration shows up at startup.
func OpenNetlink() (*Netlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("audit netlink socket: %w", err)
	}
	tv := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	n := &Netlink{fd: fd}
	if err := n.Send("op=mcp-gateway-start res=success"); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return n, nil
}

// Send delivers one message and waits for the kernel's acknowledgement.
// userMessage builds the netlink message of a user audit record. The
// text ends with a NUL, as libaudit sends it: the kernel overwrites the
// last byte of the payload with one, which otherwise cut off the last
// character of the record ("res=succes").
func userMessage(seq uint32, msg string) []byte {
	buf := make([]byte, unix.NLMSG_HDRLEN+len(msg)+1)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(len(buf)))
	binary.NativeEndian.PutUint16(buf[4:6], auditTrustedApp)
	binary.NativeEndian.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(buf[8:12], seq)
	copy(buf[unix.NLMSG_HDRLEN:], msg)
	return buf
}

func (n *Netlink) Send(msg string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.seq++
	buf := userMessage(n.seq, msg)
	if err := unix.Sendto(n.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("audit send: %w", err)
	}
	ack := make([]byte, 4096)
	for {
		m, _, err := unix.Recvfrom(n.fd, ack, 0)
		if err != nil {
			return fmt.Errorf("audit ack: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(ack[:m])
		if err != nil {
			return err
		}
		for _, nm := range msgs {
			if nm.Header.Seq != n.seq || nm.Header.Type != unix.NLMSG_ERROR {
				continue
			}
			if len(nm.Data) < 4 {
				return errors.New("audit ack: short message")
			}
			if code := int32(binary.NativeEndian.Uint32(nm.Data[:4])); code != 0 {
				return fmt.Errorf("audit: %w", syscall.Errno(-code))
			}
			return nil
		}
	}
}

// Close closes the socket.
func (n *Netlink) Close() error { return unix.Close(n.fd) }
