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
}

// Check asks whether the process pid of user uid may do action, letting
// polkit authenticate the user (interaction allowed). details are shown
// in the authentication dialog. It returns ErrNoAgent when polkit could
// not ask anyone.
//
// The subject is the process with its uid; its start time, which tells
// it from a later process with the same pid, polkitd reads itself (0
// asks it to): the gateway's sandbox does not see other users'
// processes in /proc.
func (a *Authority) Check(ctx context.Context, pid, uid uint32, action string, details map[string]string) (bool, error) {
	conn, err := a.bus()
	if err != nil {
		return false, fmt.Errorf("polkit: system bus: %w", err)
	}
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{"unix-process", map[string]dbus.Variant{
		"pid":        dbus.MakeVariant(pid),
		"start-time": dbus.MakeVariant(uint64(0)),
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
