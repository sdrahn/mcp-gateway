package notify

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

// testBus starts a private bus (dbus-daemon) for the test and returns
// its address.
func testBus(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("no dbus-daemon")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("dbus-daemon: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("dbus-daemon address: %v", err)
	}
	return strings.TrimSpace(addr)
}

func connect(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	c, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// fakeIfp is SSSD's InfoPipe as the gateway uses it: ListByName "*"
// returns all users, ListByAttr those whose attribute has the value (as
// SSSD's cache does, but answering for any gid if loose).
type fakeIfp struct {
	users  []fakeUser
	loose  bool  // ListByAttr also returns users of other gids
	refuse bool  // every call AccessDenied, as allowed_uids does
	calls  int32 // ListByName calls
	limit  atomic.Uint32
}

type fakeUser struct {
	name string
	gid  uint32
}

func (f *fakeIfp) ListByName(filter string, limit uint32) ([]dbus.ObjectPath, *dbus.Error) {
	atomic.AddInt32(&f.calls, 1)
	f.limit.Store(limit)
	if f.refuse {
		return nil, dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []any{"not allowed"})
	}
	var paths []dbus.ObjectPath
	for i := range f.users {
		if uint32(len(paths)) == limit {
			break
		}
		paths = append(paths, userPath(i))
	}
	return paths, nil
}

func (f *fakeIfp) ListByAttr(attr, value string, limit uint32) ([]dbus.ObjectPath, *dbus.Error) {
	if f.refuse {
		return nil, dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []any{"not allowed"})
	}
	var paths []dbus.ObjectPath
	for i, u := range f.users {
		if attr == "gidNumber" && (f.loose || value == strconv.FormatUint(uint64(u.gid), 10)) {
			paths = append(paths, userPath(i))
		}
	}
	return paths, nil
}

func userPath(i int) dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/sssd/infopipe/Users/vmtest/" + strconv.Itoa(20000+i))
}

// serve puts f on the bus at addr under SSSD's name.
func (f *fakeIfp) serve(t *testing.T, addr string) {
	t.Helper()
	c := connect(t, addr)
	if err := c.Export(f, ifpUsersPath, ifpUsers); err != nil {
		t.Fatal(err)
	}
	for i, u := range f.users {
		_, err := prop.Export(c, userPath(i), prop.Map{ifpUser: {
			"name":      {Value: u.name},
			"gidNumber": {Value: u.gid},
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if reply, err := c.RequestName(ifpBus, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName: %v %v", reply, err)
	}
}

func testInfoPipe(addr string) *InfoPipe {
	return &InfoPipe{Connect: func() (*dbus.Conn, error) {
		c, err := dbus.Dial(addr)
		if err != nil {
			return nil, err
		}
		if err := c.Auth(nil); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, c.Hello()
	}}
}

// The users whose primary group is the gid, by name, and nobody else:
// whatever ListByAttr returns, the gid is checked. Lookups are kept for
// ten minutes.
func TestInfoPipePrimaryMembers(t *testing.T) {
	addr := testBus(t)
	f := &fakeIfp{loose: true, users: []fakeUser{{"dirk", 20001}, {"dex", 20101}, {"dana", 20002}, {"dora", 20101}}}
	f.serve(t, addr)
	p := testInfoPipe(addr)
	now := time.Unix(1000, 0)
	p.now = func() time.Time { return now }
	names, truncated, err := p.PrimaryMembers(context.Background(), 20101)
	if err != nil || truncated || !slices.Equal(names, []string{"dex", "dora"}) {
		t.Fatalf("%v %v %v", names, truncated, err)
	}
	if l := f.limit.Load(); l != MaxInfoPipeUsers {
		t.Errorf("limit %d", l)
	}
	if _, _, _ = p.PrimaryMembers(context.Background(), 20101); atomic.LoadInt32(&f.calls) != 1 {
		t.Errorf("not kept: %d lookups", atomic.LoadInt32(&f.calls))
	}
	now = now.Add(infoPipeTTL)
	if _, _, _ = p.PrimaryMembers(context.Background(), 20101); atomic.LoadInt32(&f.calls) != 2 {
		t.Errorf("kept too long: %d lookups", atomic.LoadInt32(&f.calls))
	}
	if names, _, err := p.PrimaryMembers(context.Background(), 30000); err != nil || names != nil {
		t.Errorf("a gid nobody has: %v %v", names, err)
	}
}

// A search that returns as many users as the limit may have stopped.
func TestInfoPipeTruncated(t *testing.T) {
	addr := testBus(t)
	f := &fakeIfp{users: []fakeUser{{"a", 1}, {"b", 2}, {"c", 1}}}
	f.serve(t, addr)
	p := testInfoPipe(addr)
	p.Limit = 3
	if _, truncated, err := p.PrimaryMembers(context.Background(), 1); err != nil || !truncated {
		t.Errorf("at the limit: %v %v", truncated, err)
	}
	p = testInfoPipe(addr)
	p.Limit = 4
	if names, truncated, err := p.PrimaryMembers(context.Background(), 1); err != nil || truncated || len(names) != 2 {
		t.Errorf("below it: %v %v %v", names, truncated, err)
	}
}

// Without InfoPipe on the bus, and refused by it: the errors that name
// what to do; kept too, so a mail does not ask again.
func TestInfoPipeErrors(t *testing.T) {
	addr := testBus(t)
	p := testInfoPipe(addr)
	if _, _, err := p.PrimaryMembers(context.Background(), 1); !errors.Is(err, ErrNoInfoPipe) {
		t.Errorf("no InfoPipe: %v", err)
	}
	f := &fakeIfp{refuse: true}
	f.serve(t, addr)
	if _, _, err := p.PrimaryMembers(context.Background(), 1); !errors.Is(err, ErrNoInfoPipe) {
		t.Errorf("the failed lookup is not kept: %v", err)
	}
	if _, _, err := testInfoPipe(addr).PrimaryMembers(context.Background(), 1); !errors.Is(err, ErrInfoPipeDenied) {
		t.Errorf("refused: %v", err)
	}
	var nilPipe *InfoPipe
	if _, _, err := nilPipe.PrimaryMembers(context.Background(), 1); !errors.Is(err, ErrNoInfoPipe) {
		t.Errorf("nil: %v", err)
	}
}

// Approval mail's group expansion: the primary-group members InfoPipe
// finds are members, after the others and once; a refusal is logged as
// a warning once, InfoPipe's absence not at all.
func TestGroupMembersInfoPipe(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("no getent")
	}
	addr := testBus(t)
	f := &fakeIfp{users: []fakeUser{{"root", 0}, {"dex", 0}, {"dirk", 20001}}}
	f.serve(t, addr)
	members, dir, err := getentMembers(context.Background(), "root", nil, testInfoPipe(addr))
	if err != nil {
		t.Skipf("getent: %v", err)
	}
	if !slices.Contains(members, "root") || !slices.Contains(members, "dex") || slices.Contains(members, "dirk") {
		t.Errorf("members %v", members)
	}
	if !slices.Equal(dir.Names, []string{"dex"}) || dir.Err != nil {
		t.Errorf("from the directory: %+v", dir)
	}

	var logs bytes.Buffer
	e := &Email{Log: slog.New(slog.NewTextHandler(&logs, nil))}
	e.logDirectory("root", Directory{Err: ErrNoInfoPipe})
	if logs.Len() != 0 {
		t.Errorf("absence logged: %s", logs.String())
	}
	e.logDirectory("root", Directory{Err: ErrInfoPipeDenied})
	e.logDirectory("root", Directory{Err: ErrInfoPipeDenied})
	if n := strings.Count(logs.String(), "allowed_uids"); n != 1 {
		t.Errorf("refusal logged %d times: %s", n, logs.String())
	}
	e.logDirectory("root", Directory{Truncated: true})
	if !strings.Contains(logs.String(), "stopped at") {
		t.Errorf("truncation not logged: %s", logs.String())
	}
}
