package supervisor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Resource limits applied to every instance; privileged instances
// (package installation: RPM scripts, initrd builds) get more.
const (
	instanceMemoryMax   = 512 << 20
	instanceTasksMax    = 64
	instanceRuntimeMax  = 8 * time.Hour
	privilegedMemoryMax = 4 << 30
	privilegedTasksMax  = 4096
)

// Systemd starts each backend instance as a transient systemd service,
// with stdin/stdout on one end of a socketpair owned by the gateway, a
// hardened sandbox, and, when SELinux is used, its own domain and MCS
// category pair (docs/architecture.md, sections 5.7 and 5.8).
type Systemd struct {
	Log *slog.Logger
	// SELinux enables SELinuxContext= on the units.
	SELinux bool
	MCS     *MCSAllocator

	mu   sync.Mutex
	conn *sddbus.Conn
	live map[[2]int]*unitInstance // by MCS pair
	// stop stops an instance (tests replace it).
	stop func(*unitInstance)
}

// SELinuxEnabled reports whether SELinux is enabled on this host: whether
// selinuxfs is mounted. It reads the mount table rather than selinuxfs
// itself, which a confined process may not be allowed to look at.
func SELinuxEnabled() bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		_, err := os.Stat("/sys/fs/selinux/enforce")
		return err == nil
	}
	defer func() { _ = f.Close() }()
	return hasSELinuxFS(f)
}

// hasSELinuxFS reports whether a mountinfo table lists a selinuxfs mount.
func hasSELinuxFS(r io.Reader) bool {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// ... mount-point options [optional fields] - fstype source super-options
		_, after, ok := strings.Cut(sc.Text(), " - ")
		if ok && strings.HasPrefix(after, "selinuxfs ") {
			return true
		}
	}
	return false
}

func (s *Systemd) bus(ctx context.Context) (*sddbus.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.conn.Connected() {
		return s.conn, nil
	}
	c, err := sddbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("supervisor: connecting to systemd: %w", err)
	}
	s.conn = c
	return c, nil
}

// Properties returns the transient unit properties for an instance whose
// stdio is fd. mcs is the category pair ("" without SELinux, and for
// privileged backends).
func (s *Systemd) Properties(b *config.Backend, p principal.Principal, fd int, mcs string) ([]sddbus.Property, error) {
	prop := func(name string, v any) sddbus.Property {
		return sddbus.Property{Name: name, Value: dbus.MakeVariant(v)}
	}
	props := []sddbus.Property{
		sddbus.PropDescription(fmt.Sprintf("MCP backend %s for %s", b.Name, p.Sub)),
		sddbus.PropExecStart(command(b, p), false),
		prop("Environment", environment(b, p)),
		prop("StandardInputFileDescriptor", dbus.UnixFD(fd)),
		prop("StandardOutputFileDescriptor", dbus.UnixFD(fd)),
		prop("StandardError", "journal"),
		prop("CollectMode", "inactive-or-failed"),
		prop("RuntimeMaxUSec", uint64(instanceRuntimeMax/time.Microsecond)),
	}
	if b.Privileged {
		props = append(props, privilegedProperties(b, prop)...)
	} else {
		props = append(props, sandboxProperties(b, prop)...)
	}
	if b.Sandbox.StateDirectory != "" {
		props = append(props, prop("StateDirectory", []string{b.Sandbox.StateDirectory}),
			prop("StateDirectoryMode", uint32(0o700)))
	}
	switch b.RunAs {
	case "principal":
		if p.UID == nil {
			// A remote principal without a local account (decision D1):
			// a throwaway user, isolated by the instance's MCS pair.
			props = append(props, prop("DynamicUser", true))
			break
		}
		props = append(props, prop("User", p.Sub))
		if p.Home != "" {
			props = append(props, prop("WorkingDirectory", p.Home))
		}
	case "dynamic":
		props = append(props, prop("DynamicUser", true))
	default:
		props = append(props, prop("User", b.RunAs))
	}
	switch {
	case mcs != "":
		props = append(props, prop("SELinuxContext", fmt.Sprintf("system_u:system_r:%s:s0:%s", b.SELinuxType, mcs)))
	case b.Privileged && s.SELinux:
		// No categories: files the backend installs must stay readable
		// for services running at s0.
		props = append(props, prop("SELinuxContext", fmt.Sprintf("system_u:system_r:%s:s0", b.SELinuxType)))
	}
	creds, err := b.ParseCredentials()
	if err != nil {
		return nil, err
	}
	if len(creds) > 0 {
		// systemd (as root) reads the files and exposes them to the
		// backend below $CREDENTIALS_DIRECTORY; the gateway never sees them.
		type loadCredential struct{ ID, Path string }
		lc := make([]loadCredential, len(creds))
		for i, c := range creds {
			lc[i] = loadCredential{c.Name, c.Path}
		}
		props = append(props, prop("LoadCredential", lc))
	}
	return props, nil
}

// privilegedProperties are those of a root system service that may
// change the system as a whole (docs/architecture.md, section 5.7.1):
// all capabilities, a writable system, no system call filter, and
// NoNewPrivileges off (SELinux transitions to rpm_t, setuid helpers in
// package scripts).
func privilegedProperties(b *config.Backend, prop func(string, any) sddbus.Property) []sddbus.Property {
	return []sddbus.Property{
		prop("NoNewPrivileges", false),
		prop("PrivateTmp", true),
		prop("PrivateNetwork", !b.Network),
		prop("UMask", uint32(0o022)),
		prop("MemoryMax", uint64(privilegedMemoryMax)),
		prop("TasksMax", uint64(privilegedTasksMax)),
	}
}

// sandboxProperties are the hardened sandbox of ordinary instances.
func sandboxProperties(b *config.Backend, prop func(string, any) sddbus.Property) []sddbus.Property {
	protectHome := b.Sandbox.ProtectHome
	if protectHome == "read-write" {
		protectHome = "no"
	}
	props := []sddbus.Property{
		prop("NoNewPrivileges", true),
		prop("ProtectSystem", "strict"),
		prop("ProtectHome", protectHome),
		prop("PrivateTmp", true),
		prop("PrivateDevices", true),
		prop("PrivateNetwork", !b.Network),
		prop("ProtectKernelTunables", true),
		prop("ProtectKernelModules", true),
		prop("ProtectControlGroups", true),
		prop("ProtectKernelLogs", true),
		prop("ProtectClock", true),
		prop("ProtectHostname", true),
		prop("LockPersonality", true),
		prop("RestrictRealtime", true),
		prop("RestrictSUIDSGID", true),
		// No capabilities at all, and only the syscalls of ordinary
		// services. (MemoryDenyWriteExecute stays off: it breaks JIT
		// runtimes such as Node.js, which many MCP servers use.)
		prop("CapabilityBoundingSet", uint64(0)),
		prop("AmbientCapabilities", uint64(0)),
		prop("SystemCallArchitectures", []string{"native"}),
		prop("SystemCallFilter", struct {
			Allow    bool
			Syscalls []string
		}{true, []string{"@system-service"}}),
		prop("SystemCallErrorNumber", int32(unix.EPERM)),
		prop("UMask", uint32(0o077)),
		prop("MemoryMax", uint64(instanceMemoryMax)),
		prop("TasksMax", uint64(instanceTasksMax)),
	}
	if len(b.Sandbox.ReadWritePaths) > 0 {
		props = append(props, prop("ReadWritePaths", b.Sandbox.ReadWritePaths))
	}
	if !b.Network {
		props = append(props, prop("RestrictAddressFamilies", struct {
			Allow    bool
			Families []string
		}{true, []string{"AF_UNIX"}}))
	}
	return props
}

// Start implements Launcher.
func (s *Systemd) Start(ctx context.Context, b *config.Backend, p principal.Principal, id string) (Instance, error) {
	conn, err := s.bus(ctx)
	if err != nil {
		return nil, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	gwFile := os.NewFile(uintptr(fds[0]), "mcp-backend")
	childFD := fds[1]
	defer func() { _ = unix.Close(childFD) }()

	var mcs string
	if s.SELinux && !b.Privileged {
		if mcs, err = s.MCS.Allocate(); err != nil {
			_ = gwFile.Close()
			return nil, err
		}
	}
	fail := func(err error) (Instance, error) {
		_ = gwFile.Close()
		if mcs != "" {
			s.MCS.Release(mcs)
		}
		return nil, err
	}

	props, err := s.Properties(b, p, childFD, mcs)
	if err != nil {
		return fail(err)
	}
	name := unitName(b, id)
	done := make(chan string, 1)
	if _, err := conn.StartTransientUnitContext(ctx, name, "fail", props, done); err != nil {
		return fail(fmt.Errorf("supervisor: starting %s: %w", name, err))
	}
	select {
	case res := <-done:
		if res != "done" {
			return fail(fmt.Errorf("supervisor: starting %s: job %s", name, res))
		}
	case <-ctx.Done():
		return fail(ctx.Err())
	}

	gwConn, err := net.FileConn(gwFile)
	_ = gwFile.Close()
	if err != nil {
		return fail(err)
	}
	if s.Log != nil {
		s.Log.Info("backend started", "instance", name, "selinux_mcs", mcs)
	}
	inst := &unitInstance{Conn: gwConn, name: name, mcs: mcs, s: s}
	if pair, ok := parsePair("s0:" + mcs); ok {
		s.mu.Lock()
		if s.live == nil {
			s.live = map[[2]int]*unitInstance{}
		}
		s.live[pair] = inst
		s.mu.Unlock()
	}
	return inst, nil
}

// MCSCollision is an instance whose category pair another workload
// holds as well.
type MCSCollision struct {
	Instance string
	Pair     string
	Foreign  ForeignProc
}

// Collisions stops the instances whose category pair appears in scan (a
// container or virtual machine started after the instance picked the
// same pair; podman and libvirt do not know the gateway's pairs). The
// sessions using them get a new instance, with a new pair, on their next
// call.
func (s *Systemd) Collisions(scan MCSScan) []MCSCollision {
	s.mu.Lock()
	var hits []MCSCollision
	var stop []*unitInstance
	for pair, inst := range s.live {
		if f, ok := scan.Pairs[pair]; ok {
			hits = append(hits, MCSCollision{Instance: inst.name, Pair: inst.mcs, Foreign: f})
			stop = append(stop, inst)
		}
	}
	s.mu.Unlock()
	for _, inst := range stop {
		if s.stop != nil {
			s.stop(inst)
			continue
		}
		go func() { _ = inst.Close() }()
	}
	return hits
}

type unitInstance struct {
	net.Conn
	name string
	mcs  string
	s    *Systemd
	once sync.Once
}

func (i *unitInstance) Name() string { return i.name }

// Close closes the stdio socket (ending a well-behaved server) and stops
// the unit.
func (i *unitInstance) Close() error {
	var err error
	i.once.Do(func() {
		err = i.Conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if conn, bErr := i.s.bus(ctx); bErr == nil {
			done := make(chan string, 1)
			if _, sErr := conn.StopUnitContext(ctx, i.name, "replace", done); sErr == nil {
				select {
				case <-done:
				case <-ctx.Done():
				}
			} else if !isNoSuchUnit(sErr) {
				err = errors.Join(err, sErr)
			}
		}
		if i.mcs != "" {
			i.s.mu.Lock()
			if pair, ok := parsePair("s0:" + i.mcs); ok && i.s.live[pair] == i {
				delete(i.s.live, pair)
			}
			i.s.mu.Unlock()
			i.s.MCS.Release(i.mcs)
		}
	})
	return err
}

func isNoSuchUnit(err error) bool {
	var dErr dbus.Error
	return errors.As(err, &dErr) && dErr.Name == "org.freedesktop.systemd1.NoSuchUnit"
}
