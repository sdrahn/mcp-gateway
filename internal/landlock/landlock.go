// Package landlock restricts the calling thread, and what it executes,
// to file hierarchies and TCP ports with the Landlock LSM
// (docs/architecture.md, roadmap step 30): a second wall behind an
// instance's SELinux domain and unit sandbox, per instance, binding root
// too. The launcher mcp-landlock applies a server definition's rules and
// then executes the server.
//
// Landlock restricts a thread: callers lock their OS thread
// (runtime.LockOSThread), call Restrict and execute the program from
// that thread, which carries the restriction into it.
package landlock

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Rules are the trees and ports an instance may use, beyond Base. A tree
// covers everything beneath it, followed as the file system has it
// (symbolic links lead nowhere else).
type Rules struct {
	// Read: read files and list directories.
	Read []string `yaml:"read" json:"read,omitempty"`
	// Write: also create, change, rename and remove; implies Read.
	Write []string `yaml:"write" json:"write,omitempty"`
	// Exec: also execute; implies Read.
	Exec []string `yaml:"exec" json:"exec,omitempty"`
	// TCPConnect and TCPBind, when set, are the only TCP ports the
	// instance may connect to or bind (Landlock ABI 4); unset leaves TCP
	// to the unit's sandbox (PrivateNetwork, IPAddressAllow).
	// An empty list (not unset) allows no port.
	TCPConnect []int `yaml:"tcp_connect" json:"tcp_connect"`
	TCPBind    []int `yaml:"tcp_bind" json:"tcp_bind"`
	// Required refuses to run without every restriction asked for (a
	// kernel without Landlock, or without a right the rules need).
	Required bool `yaml:"required" json:"required,omitempty"`
}

// Base are the trees every ruleset allows: the system's programs and
// libraries, its configuration and state as the unit's sandbox shows
// them, a few devices, the instance's private temporary directories and
// its credentials. What the instance works on comes from its rules.
var Base = Rules{
	Read: []string{"/etc", "/proc", "/sys", "/run/credentials"},
	Exec: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
	Write: []string{"/tmp", "/var/tmp", "/dev/shm", "/dev/null", "/dev/zero", "/dev/full",
		"/dev/random", "/dev/urandom"},
}

// Result is what Restrict did.
type Result struct {
	// ABI is the kernel's Landlock ABI, 0 without Landlock.
	ABI int
	// Missing are trees of the rules that do not exist (left out).
	Missing []string
	// Unsupported are restrictions the kernel cannot apply.
	Unsupported []string
	// Scoped: signals and abstract unix sockets are limited to the
	// instance (ABI 6).
	Scoped bool
}

func (r Result) String() string {
	if r.ABI == 0 {
		return "Landlock not available (a kernel without it, or not in the LSM list): no restriction"
	}
	out := fmt.Sprintf("Landlock ABI %d", r.ABI)
	if r.Scoped {
		out += ", scoped"
	}
	if len(r.Unsupported) > 0 {
		out += "; not supported by the kernel: " + strings.Join(r.Unsupported, ", ")
	}
	if len(r.Missing) > 0 {
		out += "; missing, left out: " + strings.Join(r.Missing, ", ")
	}
	return out
}

// ErrRequired is returned when Required rules cannot be applied in full.
var ErrRequired = errors.New("landlock: required, but the kernel cannot apply every restriction")

// ABI returns the kernel's Landlock ABI version, 0 without Landlock.
func ABI() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(v)
}

const (
	fsV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	readRights = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	execRights = readRights | unix.LANDLOCK_ACCESS_FS_EXECUTE
	// fileRights are those that apply to a file (not a directory).
	fileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	ruleNetPort = 2 // LANDLOCK_RULE_NET_PORT
)

// handledFS are the file system rights the kernel's ABI knows.
func handledFS(abi int) uint64 {
	h := uint64(fsV1)
	if abi >= 2 {
		h |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		h |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		h |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return h
}

// netPortAttr is struct landlock_net_port_attr.
type netPortAttr struct {
	allowedAccess uint64
	port          uint64
}

// Restrict restricts the calling thread to Base and r, with what the
// kernel supports; see the package documentation for the thread.
func Restrict(r Rules) (Result, error) {
	res := Result{ABI: ABI()}
	if res.ABI == 0 {
		if r.Required {
			return res, ErrRequired
		}
		return res, nil
	}
	handled := handledFS(res.ABI)
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	size := unsafe.Offsetof(attr.Access_net) // ABI 1 to 3: access_fs only
	netRights := map[uint64][]int{}
	if r.TCPConnect != nil || r.TCPBind != nil {
		if res.ABI >= 4 {
			size = unsafe.Offsetof(attr.Scoped)
			if r.TCPConnect != nil {
				attr.Access_net |= unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
				netRights[unix.LANDLOCK_ACCESS_NET_CONNECT_TCP] = r.TCPConnect
			}
			if r.TCPBind != nil {
				attr.Access_net |= unix.LANDLOCK_ACCESS_NET_BIND_TCP
				netRights[unix.LANDLOCK_ACCESS_NET_BIND_TCP] = r.TCPBind
			}
		} else {
			res.Unsupported = append(res.Unsupported, "TCP ports (ABI 4)")
		}
	}
	if res.ABI >= 6 {
		size = unsafe.Sizeof(attr)
		attr.Scoped = unix.LANDLOCK_SCOPE_SIGNAL | unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
		res.Scoped = true
	} else {
		res.Unsupported = append(res.Unsupported, "scoping of signals and abstract unix sockets (ABI 6)")
	}
	if r.Required && len(res.Unsupported) > 0 {
		return res, fmt.Errorf("%w: %s", ErrRequired, strings.Join(res.Unsupported, ", "))
	}

	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return res, fmt.Errorf("landlock: creating the ruleset: %w", errno)
	}
	ruleset := int(fd)
	defer func() { _ = unix.Close(ruleset) }()

	write := handled &^ unix.LANDLOCK_ACCESS_FS_EXECUTE
	for _, t := range []struct {
		paths  []string
		rights uint64
	}{
		{Base.Read, readRights}, {Base.Exec, execRights}, {Base.Write, write},
		{r.Read, readRights}, {r.Exec, execRights}, {r.Write, write},
	} {
		for _, p := range t.paths {
			missing, err := addPath(ruleset, p, t.rights&handled)
			if err != nil {
				return res, err
			}
			if missing && !isBase(p) {
				res.Missing = append(res.Missing, p)
			}
		}
	}
	for _, right := range []uint64{unix.LANDLOCK_ACCESS_NET_CONNECT_TCP, unix.LANDLOCK_ACCESS_NET_BIND_TCP} {
		for _, port := range netRights[right] {
			a := netPortAttr{allowedAccess: right, port: uint64(port)}
			if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), ruleNetPort,
				uintptr(unsafe.Pointer(&a)), 0, 0, 0); errno != 0 {
				return res, fmt.Errorf("landlock: TCP port %d: %w", port, errno)
			}
		}
	}
	sort.Strings(res.Missing)

	if err := restrictSelf(ruleset); err != nil {
		return res, err
	}
	return res, nil
}

func isBase(p string) bool {
	for _, l := range [][]string{Base.Read, Base.Exec, Base.Write} {
		for _, b := range l {
			if p == b {
				return true
			}
		}
	}
	return false
}

// addPath adds a rule for the tree (or file) at p; missing reports a
// path that does not exist, which is left out. It does not stat p: a
// server's SELinux domain may not get the attributes of a device such as
// /dev/random. The kernel refuses directory rights on a file (EINVAL),
// and then the rule is added again with file rights.
func addPath(ruleset int, p string, rights uint64) (missing bool, err error) {
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("landlock: %s: %w", p, err)
	}
	defer func() { _ = unix.Close(fd) }()
	add := func(rights uint64) unix.Errno {
		a := unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(fd)}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&a)), 0, 0, 0)
		return errno
	}
	errno := add(rights)
	if errno == unix.EINVAL && rights&^fileRights != 0 {
		if rights &= fileRights; rights == 0 {
			return false, nil
		}
		errno = add(rights)
	}
	if errno != 0 {
		return false, fmt.Errorf("landlock: %s: %w", p, errno)
	}
	return false, nil
}

// restrictSelf enforces the ruleset on the calling thread. Without
// CAP_SYS_ADMIN the thread needs no_new_privs first (an instance of a
// privileged server has the capability and may keep setuid programs).
func restrictSelf(ruleset int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0)
	if errno == unix.EPERM {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("landlock: no_new_privs: %w", err)
		}
		_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0)
	}
	if errno != 0 {
		return fmt.Errorf("landlock: restricting: %w", errno)
	}
	return nil
}

// Validate checks rules from a server definition: absolute, clean
// paths (${HOME} and ${USER} may stand for the principal's), ports from 1
// to 65535.
func (r Rules) Validate() error {
	for _, l := range []struct {
		key   string
		paths []string
	}{{"read", r.Read}, {"write", r.Write}, {"exec", r.Exec}} {
		for _, p := range l.paths {
			x := strings.NewReplacer("${HOME}", "/home/x", "${USER}", "x").Replace(p)
			if !strings.HasPrefix(x, "/") || path.Clean(x) != x || strings.Contains(x, "$") {
				return fmt.Errorf("landlock: %s: %q is not an absolute, clean path (only ${HOME} and ${USER} are expanded)", l.key, p)
			}
		}
	}
	for _, l := range []struct {
		key   string
		ports []int
	}{{"tcp_connect", r.TCPConnect}, {"tcp_bind", r.TCPBind}} {
		for _, n := range l.ports {
			if n < 1 || n > 65535 {
				return fmt.Errorf("landlock: %s: port %d is not from 1 to 65535", l.key, n)
			}
		}
	}
	return nil
}

// Expand returns r with expand applied to its paths (${HOME}, ${USER}).
func (r Rules) Expand(expand func(string) string) Rules {
	each := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		for i, p := range in {
			out[i] = expand(p)
		}
		return out
	}
	r.Read, r.Write, r.Exec = each(r.Read), each(r.Write), each(r.Exec)
	return r
}
