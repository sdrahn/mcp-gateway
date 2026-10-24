package config

import (
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

// capabilities are the Linux capabilities sandbox.capabilities may name.
var capabilities = map[string]uint{
	"CAP_CHOWN":              unix.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":       unix.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":             unix.CAP_FOWNER,
	"CAP_FSETID":             unix.CAP_FSETID,
	"CAP_KILL":               unix.CAP_KILL,
	"CAP_SETGID":             unix.CAP_SETGID,
	"CAP_SETUID":             unix.CAP_SETUID,
	"CAP_SETPCAP":            unix.CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":    unix.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":      unix.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":          unix.CAP_NET_ADMIN,
	"CAP_NET_RAW":            unix.CAP_NET_RAW,
	"CAP_IPC_LOCK":           unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":          unix.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":         unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":          unix.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":         unix.CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":         unix.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":          unix.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":          unix.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":           unix.CAP_SYS_BOOT,
	"CAP_SYS_NICE":           unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":       unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":           unix.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":     unix.CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":              unix.CAP_MKNOD,
	"CAP_LEASE":              unix.CAP_LEASE,
	"CAP_AUDIT_WRITE":        unix.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":            unix.CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":       unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":          unix.CAP_MAC_ADMIN,
	"CAP_SYSLOG":             unix.CAP_SYSLOG,
	"CAP_WAKE_ALARM":         unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":      unix.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":         unix.CAP_AUDIT_READ,
	"CAP_PERFMON":            unix.CAP_PERFMON,
	"CAP_BPF":                unix.CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
}

// validateCapabilities checks sandbox.capabilities: known names, each
// once.
func (s *Sandbox) validateCapabilities() error {
	for i, c := range s.Capabilities {
		if _, ok := capabilities[c]; !ok {
			return fmt.Errorf("sandbox.capabilities: unknown capability %q (names as in capabilities(7), e.g. CAP_SYS_ADMIN)", c)
		}
		if slices.Contains(s.Capabilities[:i], c) {
			return fmt.Errorf("sandbox.capabilities: %s is named twice", c)
		}
	}
	return nil
}

// CapabilityMask is the bit mask of the capabilities (as systemd's
// CapabilityBoundingSet= and AmbientCapabilities= take it); 0 without.
func (s *Sandbox) CapabilityMask() uint64 {
	var m uint64
	for _, c := range s.Capabilities {
		if bit, ok := capabilities[c]; ok {
			m |= 1 << bit
		}
	}
	return m
}

// Elevated reports whether the backend holds rights beyond the sandbox:
// privileged, or with capabilities. Calls to such a server are approved
// as those to privileged servers are, audited in full, and an instance
// is not stopped while a call runs (docs/architecture.md, section 5.7.1).
func (b *Backend) Elevated() bool {
	return b.Privileged || len(b.Sandbox.Capabilities) > 0
}
