package notifyagent

import (
	"bufio"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// privateBus starts a session bus for the test.
func privateBus(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not found")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", strings.TrimSpace(addr))
}

// fakeServer implements the notification server methods the agent uses.
type fakeServer struct {
	mu     sync.Mutex
	bodies []string
	closed []uint32
}

func (f *fakeServer) GetCapabilities() ([]string, *dbus.Error) {
	return []string{"actions", "body", "body-markup"}, nil
}

func (f *fakeServer) Notify(app string, replaces uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies = append(f.bodies, body)
	if replaces != 0 {
		return replaces, nil
	}
	return uint32(len(f.bodies)), nil
}

func (f *fakeServer) CloseNotification(id uint32) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, id)
	return nil
}

func TestDBusNotifier(t *testing.T) {
	privateBus(t)
	srvConn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvConn.Close() }()
	fake := &fakeServer{}
	if err := srvConn.Export(fake, notifyPath, notifyIface); err != nil {
		t.Fatal(err)
	}
	if reply, err := srvConn.RequestName(notifyName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", reply, err)
	}

	n, err := NewDBusNotifier()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDBusNotifier(); err != ErrRunning {
		t.Fatalf("second agent: %v, want ErrRunning", err)
	}
	id, err := n.Show(Notification{Summary: "s", Body: "<b>fs</b> & co"})
	if err != nil || id != 1 {
		t.Fatalf("show: %d %v", id, err)
	}
	fake.mu.Lock()
	body := fake.bodies[0]
	fake.mu.Unlock()
	if body != "&lt;b&gt;fs&lt;/b&gt; &amp; co" {
		t.Fatalf("body not escaped for markup: %q", body)
	}
	if err := n.Close(id); err != nil {
		t.Fatal(err)
	}

	// A look-alike signal from another client is ignored; the server's
	// own is delivered.
	spoof, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spoof.Close() }()
	if err := spoof.Emit(notifyPath, notifyIface+".ActionInvoked", uint32(7), "default"); err != nil {
		t.Fatal(err)
	}
	if err := srvConn.Emit(notifyPath, notifyIface+".ActionInvoked", id, "default"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-n.Actions():
		if got != id {
			t.Fatalf("action for %d delivered (spoofed?), want %d", got, id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("action not delivered")
	}
}
