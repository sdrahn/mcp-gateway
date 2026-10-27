package notify

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// SSSD's InfoPipe (sssd-ifp, from the package sssd-dbus) on the system
// bus.
const (
	ifpBus       = "org.freedesktop.sssd.infopipe"
	ifpUsersPath = "/org/freedesktop/sssd/infopipe/Users"
	ifpUsers     = "org.freedesktop.sssd.infopipe.Users"
	ifpUser      = "org.freedesktop.sssd.infopipe.Users.User"
)

// MaxInfoPipeUsers bounds the users one lookup has SSSD fetch from its
// directories (ListByName "*"); SSSD's own wildcard_limit may set less.
const MaxInfoPipeUsers = 10000

// infoPipeTTL is how long a group's primary members, or a failed lookup,
// are kept: each lookup searches the directory for all its users.
const infoPipeTTL = 10 * time.Minute

// ErrNoInfoPipe: SSSD's InfoPipe is not on the system bus (sssd-dbus not
// installed, or SSSD not running).
var ErrNoInfoPipe = errors.New("SSSD's InfoPipe is not available (sssd-dbus not installed, or SSSD not running)")

// ErrInfoPipeDenied: InfoPipe refuses the caller (not in allowed_uids of
// the [ifp] section of sssd.conf).
var ErrInfoPipeDenied = errors.New("SSSD's InfoPipe refuses this user (allowed_uids in the [ifp] section of sssd.conf)")

// InfoPipe finds the users whose primary group a group is in SSSD's
// directories, which NSS finds only by enumerating (SSSD does not
// without enumerate = true): it has SSSD search its directories for all
// users (a wildcard lookup, which needs no enumeration) and lists those
// in SSSD's cache with the group's gid. A nil InfoPipe finds nobody.
type InfoPipe struct {
	// Connect returns the system bus (default: dbus.ConnectSystemBus).
	Connect func() (*dbus.Conn, error)
	// Limit bounds the users fetched (default MaxInfoPipeUsers).
	Limit uint32
	now   func() time.Time

	mu    sync.Mutex
	conn  *dbus.Conn
	cache map[uint32]ifpResult
}

// ifpResult is a lookup kept for infoPipeTTL.
type ifpResult struct {
	names     []string
	truncated bool
	err       error
	at        time.Time
}

// PrimaryMembers returns the names of the users whose primary group is
// gid, and whether SSSD's search stopped at the limit (some may be
// missing). Lookups are kept for 10 minutes, failed ones too.
func (p *InfoPipe) PrimaryMembers(ctx context.Context, gid uint32) (names []string, truncated bool, err error) {
	if p == nil {
		return nil, false, ErrNoInfoPipe
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.cache[gid]; ok && now().Sub(r.at) < infoPipeTTL {
		return r.names, r.truncated, r.err
	}
	names, truncated, err = p.lookup(ctx, gid)
	if ctx.Err() == nil {
		if p.cache == nil {
			p.cache = map[uint32]ifpResult{}
		}
		p.cache[gid] = ifpResult{names: names, truncated: truncated, err: err, at: now()}
	}
	return names, truncated, err
}

func (p *InfoPipe) lookup(ctx context.Context, gid uint32) ([]string, bool, error) {
	conn, err := p.bus()
	if err != nil {
		return nil, false, fmt.Errorf("system bus: %w", err)
	}
	limit := p.Limit
	if limit == 0 {
		limit = MaxInfoPipeUsers
	}
	users := conn.Object(ifpBus, ifpUsersPath)
	// The wildcard lookup brings the directories' users into SSSD's
	// cache; ListByAttr then searches the cache.
	var all []dbus.ObjectPath
	if err := users.CallWithContext(ctx, ifpUsers+".ListByName", 0, "*", limit).Store(&all); err != nil {
		return nil, false, ifpError(err)
	}
	var paths []dbus.ObjectPath
	if err := users.CallWithContext(ctx, ifpUsers+".ListByAttr", 0, "gidNumber", strconv.FormatUint(uint64(gid), 10), limit).Store(&paths); err != nil {
		return nil, false, ifpError(err)
	}
	var names []string
	for _, path := range paths {
		v, err := conn.Object(ifpBus, path).GetProperty(ifpUser + ".name")
		if err != nil {
			continue // a user since removed
		}
		// The gid is checked again: ListByAttr's filter is SSSD's.
		g, gerr := conn.Object(ifpBus, path).GetProperty(ifpUser + ".gidNumber")
		if name, ok := v.Value().(string); ok && gerr == nil && g.Value() == gid {
			names = appendNew(names, name)
		}
	}
	return names, uint32(len(all)) >= limit, nil
}

// ifpError names the two refusals an administrator can fix.
func ifpError(err error) error {
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner":
			return ErrNoInfoPipe
		case "org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.AuthFailed":
			// (SSSD answers a uid not in allowed_uids with EACCES, which
			// it sends as AuthFailed.)
			return ErrInfoPipeDenied
		}
	}
	return fmt.Errorf("SSSD's InfoPipe: %w", err)
}

func (p *InfoPipe) bus() (*dbus.Conn, error) {
	if p.conn != nil && p.conn.Connected() {
		return p.conn, nil
	}
	connect := p.Connect
	if connect == nil {
		connect = func() (*dbus.Conn, error) { return dbus.ConnectSystemBus() }
	}
	c, err := connect()
	if err != nil {
		return nil, err
	}
	p.conn = c
	return c, nil
}
