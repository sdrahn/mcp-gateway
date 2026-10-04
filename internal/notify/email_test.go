package notify

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

type fakePolicy []string

func (f fakePolicy) Strings(context.Context, string, any) ([]string, error) { return f, nil }

// fakeSMTP accepts one mail per connection and records it.
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	rcpt []string
	data string
	got  chan struct{}
}

func startSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := &fakeSMTP{addr: l.Addr().String(), got: make(chan struct{}, 4)}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.TrimSpace(line)[len("RCPT TO:"):])
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go on")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
			f.got <- struct{}{}
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func pending() broker.Pending {
	uid := uint32(1001)
	return broker.Pending{ID: "a-1", Channel: "oob", Action: "tools.call", Server: "fs", Name: "write_file\r\nBcc: x@evil",
		Principal: principal.Principal{Sub: "alice", UID: &uid, Transport: principal.TransportUnix},
		Args:      map[string]any{"path": "/home/alice/secret"}, Expires: time.Now().Add(time.Minute), Waiting: true}
}

func TestEmail(t *testing.T) {
	srv := startSMTP(t)
	e, err := NewEmail(config.Email{SMTP: srv.addr, From: "mcp-gateway@gw", To: "{user}@example.com", StartTLS: "auto"},
		fakePolicy{"user:alice", "group:wheel", "user:bad name", "user:alice"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.GroupMembers = func(_ context.Context, g string) ([]string, error) {
		if g != "wheel" {
			t.Errorf("group %q", g)
		}
		return []string{"carol", "alice"}, nil
	}
	e.URL = func(id string) string { return "https://gw.example.com/approvals/" + id }

	events := make(chan broker.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, events)
	p := pending()
	events <- broker.Event{Type: "pending", ID: p.ID, New: true, Pending: &p}
	select {
	case <-srv.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no mail")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if strings.Join(srv.rcpt, ",") != "<alice@example.com>,<carol@example.com>" {
		t.Fatalf("recipients %v", srv.rcpt)
	}
	for _, want := range []string{"To: undisclosed-recipients:;", "Auto-Submitted: auto-generated",
		"https://gw.example.com/approvals/a-1", "alice via unix"} {
		if !strings.Contains(srv.data, want) {
			t.Errorf("mail lacks %q:\n%s", want, srv.data)
		}
	}
	if strings.Contains(srv.data, "\r\nBcc:") || strings.Contains(srv.data, "\nBcc:") {
		t.Errorf("header injection through the tool name:\n%s", srv.data)
	}
	if strings.Contains(srv.data, "secret") {
		t.Errorf("arguments in the mail without include_args:\n%s", srv.data)
	}
}

func TestEmailOnlyNewApprovals(t *testing.T) {
	sent := make(chan []string, 4)
	e, _ := NewEmail(config.Email{SMTP: "x:25", From: "gw@x", To: "{user}"}, fakePolicy{"user:alice"}, nil)
	e.Send = func(_ context.Context, to []string, _ []byte) error { sent <- to; return nil }
	events := make(chan broker.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, events)
	p := pending()
	events <- broker.Event{Type: "pending", ID: p.ID, New: false, Pending: &p} // taken over / orphaned
	events <- broker.Event{Type: "resolved", ID: p.ID}
	events <- broker.Event{Type: "pending", ID: "a-2", New: true, Pending: &p}
	select {
	case to := <-sent:
		if strings.Join(to, ",") != "alice" {
			t.Fatalf("to %v", to)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no mail for the new approval")
	}
	select {
	case to := <-sent:
		t.Fatalf("extra mail to %v", to)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIncludeArgs(t *testing.T) {
	e, _ := NewEmail(config.Email{SMTP: "x:25", From: "gw@x", To: "{user}", IncludeArgs: true}, fakePolicy{}, nil)
	if msg := string(e.Message(pending())); !strings.Contains(msg, "/home/alice/secret") {
		t.Fatalf("arguments missing with include_args:\n%s", msg)
	}
}

func TestGetentMembers(t *testing.T) {
	if _, err := getentMembers(context.Background(), "bad name"); err == nil {
		t.Fatal("invalid group name accepted")
	}
	members, err := getentMembers(context.Background(), "root")
	if err != nil {
		t.Skipf("getent: %v", err)
	}
	// root's primary group is root's: it is a member now.
	if !slices.Contains(members, "root") {
		t.Errorf("root not among the members of root: %v", members)
	}
}

// Users whose primary group it is count as members, after the listed
// ones and once.
func TestGroupMembersParsing(t *testing.T) {
	gid, listed := parseGroup("approvers:x:1500:alice,bob\n")
	if gid != "1500" || strings.Join(listed, ",") != "alice,bob" {
		t.Fatalf("parseGroup: %q %v", gid, listed)
	}
	if gid, listed := parseGroup("empty:x:1600:"); gid != "1600" || listed != nil {
		t.Errorf("no listed members: %q %v", gid, listed)
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"carol:x:1001:1500:Carol:/home/carol:/bin/bash\n" +
		"bob:x:1002:1500:Bob:/home/bob:/bin/bash\n" +
		"dave:x:1003:100:Dave:/home/dave:/bin/bash\n" +
		"broken line\n"
	got := appendNew(listed, primaryMembers(passwd, gid)...)
	if strings.Join(got, ",") != "alice,bob,carol" {
		t.Errorf("members: %v", got)
	}
}

// A reload reads the password file anew; a configuration that does not
// load leaves the one in force; without smtp nothing is sent.
func TestEmailConfigure(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Email{SMTP: "x:25", From: "gw@x", To: "{user}", Username: "gw", PasswordFile: pw}
	e, err := NewEmail(cfg, fakePolicy{"user:alice"}, nil)
	if err != nil || e.state.Load().password != "old" || !e.Enabled() {
		t.Fatalf("%v %+v", err, e.state.Load())
	}
	if err := os.WriteFile(pw, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Configure(cfg); err != nil || e.state.Load().password != "new" {
		t.Fatalf("%v %q", err, e.state.Load().password)
	}
	bad := cfg
	bad.PasswordFile = filepath.Join(t.TempDir(), "missing")
	bad.From = "other@x"
	if err := e.Configure(bad); err == nil || e.config().From != "gw@x" {
		t.Fatalf("%v %+v", err, e.config())
	}
	var sent int
	e.Send = func(context.Context, []string, []byte) error { sent++; return nil }
	if err := e.Configure(config.Email{}); err != nil || e.Enabled() {
		t.Fatalf("%v enabled=%v", err, e.Enabled())
	}
	e.notify(context.Background(), broker.Pending{ID: "a-1"})
	if sent != 0 {
		t.Fatal("mail sent without smtp")
	}
}
