// Package polkit asks polkit whether a local process may do an action,
// letting polkit authenticate its user interactively (roadmap step 40):
// the gateway uses it for decisions on a user's own approvals over the
// control socket, which only the user's password, not the user's agent,
// may make.
package polkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

// DecideOwn is the action of deciding on one's own approval.
const DecideOwn = "io.github.sdrahn.mcp-gateway.decide-own"

const (
	busName       = "org.freedesktop.PolicyKit1"
	objectPath    = "/org/freedesktop/PolicyKit1/Authority"
	checkMethod   = "org.freedesktop.PolicyKit1.Authority.CheckAuthorization"
	allowInteract = uint32(1) // CheckAuthorizationFlags.AllowUserInteraction
)

// ErrNoAgent is a refusal for want of anyone to authenticate the user:
// no polkit agent for the process (no terminal, no desktop session).
var ErrNoAgent = errors.New("polkit: no authentication agent for the process")

// Authority checks authorizations with polkitd on the system bus.
type Authority struct {
	mu   sync.Mutex
	conn *dbus.Conn
	// StartTime reads a process's start time (default: /proc).
	StartTime func(pid uint32) (uint64, error)
}

// Check asks whether the process pid of user uid may do action, letting
// polkit authenticate the user (interaction allowed). details are shown
// in the authentication dialog. It returns ErrNoAgent when polkit could
// not ask anyone.
func (a *Authority) Check(ctx context.Context, pid, uid uint32, action string, details map[string]string) (bool, error) {
	start := a.StartTime
	if start == nil {
		start = ProcStartTime
	}
	st, err := start(pid)
	if err != nil {
		return false, fmt.Errorf("polkit: process %d: %w", pid, err)
	}
	conn, err := a.bus()
	if err != nil {
		return false, fmt.Errorf("polkit: system bus: %w", err)
	}
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{"unix-process", map[string]dbus.Variant{
		"pid":        dbus.MakeVariant(pid),
		"start-time": dbus.MakeVariant(st),
		"uid":        dbus.MakeVariant(int32(uid)),
	}}
	if details == nil {
		details = map[string]string{}
	}
	var result struct {
		Authorized, Challenge bool
		Details               map[string]string
	}
	call := conn.Object(busName, objectPath).CallWithContext(ctx, checkMethod, 0, subject, action, details, allowInteract, "")
	if call.Err != nil {
		return false, fmt.Errorf("polkit: %w", call.Err)
	}
	if err := call.Store(&result.Authorized, &result.Challenge, &result.Details); err != nil {
		return false, fmt.Errorf("polkit: %w", err)
	}
	if !result.Authorized && result.Details["polkit.dismissed"] == "" && result.Challenge {
		return false, ErrNoAgent
	}
	return result.Authorized, nil
}

func (a *Authority) bus() (*dbus.Conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil && a.conn.Connected() {
		return a.conn, nil
	}
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	a.conn = c
	return c, nil
}

// ProcStartTime reads the start time of process pid (clock ticks since
// boot, field 22 of /proc/<pid>/stat), which polkit compares so that a
// new process with a reused pid is not mistaken for it.
func ProcStartTime(pid uint32) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, err
	}
	return parseStartTime(string(b))
}

func parseStartTime(stat string) (uint64, error) {
	// The command name (field 2) is in parentheses and may hold spaces
	// and parentheses: the fields after it follow the last ")".
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(stat[i+1:])
	// fields[0] is field 3 (state): field 22 is fields[19].
	if len(fields) < 20 {
		return 0, errors.New("malformed stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
