package notifyagent

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// Desktop notifications per the freedesktop.org specification.
const (
	notifyName  = "org.freedesktop.Notifications"
	notifyPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notifyIface = "org.freedesktop.Notifications"
	// agentName makes the agent single-instance per session.
	agentName = "io.github.sdrahn.McpGatewayNotify"
)

// ErrRunning means another agent runs in this session.
var ErrRunning = errors.New("notifyagent: already running in this session")

// DBusNotifier shows notifications through the session's notification
// server.
type DBusNotifier struct {
	conn    *dbus.Conn
	obj     dbus.BusObject
	actions chan uint32
	markup  bool
}

// NewDBusNotifier connects to the session bus.
func NewDBusNotifier() (*DBusNotifier, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("notifyagent: session bus: %w", err)
	}
	reply, err := conn.RequestName(agentName, dbus.NameFlagDoNotQueue)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		_ = conn.Close()
		return nil, ErrRunning
	}
	n := &DBusNotifier{conn: conn, obj: conn.Object(notifyName, notifyPath), actions: make(chan uint32, 16)}
	var caps []string
	if err := n.obj.Call(notifyIface+".GetCapabilities", 0).Store(&caps); err == nil {
		for _, c := range caps {
			if c == "body-markup" {
				n.markup = true
			}
		}
	}
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(notifyIface), dbus.WithMatchMember("ActionInvoked")); err != nil {
		_ = conn.Close()
		return nil, err
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	go n.signals(signals)
	return n, nil
}

// signals forwards ActionInvoked from the notification server only (any
// session client could emit a look-alike signal).
func (n *DBusNotifier) signals(ch <-chan *dbus.Signal) {
	for sig := range ch {
		if sig.Name != notifyIface+".ActionInvoked" || len(sig.Body) < 1 {
			continue
		}
		var owner string
		if err := n.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, notifyName).Store(&owner); err != nil || sig.Sender != owner {
			continue
		}
		if id, ok := sig.Body[0].(uint32); ok {
			select {
			case n.actions <- id:
			default:
			}
		}
	}
}

// Show implements Notifier.
func (n *DBusNotifier) Show(no Notification) (uint32, error) {
	body := no.Body
	if n.markup {
		body = EscapeMarkup(body)
	}
	var id uint32
	err := n.obj.Call(notifyIface+".Notify", 0,
		"MCP Gateway", no.Replaces, "dialog-password", no.Summary, body,
		[]string{"default", "Open approval page"},
		map[string]dbus.Variant{"urgency": dbus.MakeVariant(byte(2)), "desktop-entry": dbus.MakeVariant("mcp-gateway-notify")},
		int32(0)).Store(&id)
	return id, err
}

// Close implements Notifier.
func (n *DBusNotifier) Close(id uint32) error {
	return n.obj.Call(notifyIface+".CloseNotification", 0, id).Err
}

// Actions implements Notifier.
func (n *DBusNotifier) Actions() <-chan uint32 { return n.actions }
