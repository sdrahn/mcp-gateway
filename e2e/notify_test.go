package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"
)

// mailSink is a minimal SMTP server that hands over each mail's
// recipients and data.
func mailSink(t *testing.T) (addr string, mails <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	out := make(chan string, 4)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				r := bufio.NewReader(conn)
				say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
				say("220 sink")
				var mail strings.Builder
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(cmd, "RCPT TO"):
						mail.WriteString(line)
						say("250 ok")
					case cmd == "DATA":
						say("354 go on")
						for {
							l, err := r.ReadString('\n')
							if err != nil || l == ".\r\n" {
								break
							}
							mail.WriteString(l)
						}
						say("250 queued")
						out <- mail.String()
					case cmd == "QUIT":
						say("221 bye")
						return
					default:
						say("250 ok")
					}
				}
			}(conn)
		}
	}()
	return l.Addr().String(), out
}

func TestApprovalNotifications(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-notify")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	smtpAddr, mails := mailSink(t)
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "oob"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`notifications:
  email:
    smtp: %s
    from: mcp-gateway@test
    to: "{user}@example.com"
`, smtpAddr))

	// The desktop agent's view: the control API's event stream.
	resp, err := controlClient(e.ctlSock).Get("http://control/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	events := make(chan map[string]any, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var ev map[string]any
				if json.Unmarshal([]byte(data), &ev) == nil {
					events <- ev
				}
			}
		}
	}()
	nextEvent := func() map[string]any {
		t.Helper()
		select {
		case ev := <-events:
			return ev
		case <-time.After(10 * time.Second):
			t.Fatal("no event")
		}
		return nil
	}

	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	c.request(2, "tools/call", map[string]any{"name": "write_file",
		"arguments": map[string]any{"path": home + "/n.txt", "content": "x"}})

	ev := nextEvent()
	if ev["type"] != "pending" || ev["new"] != true {
		t.Fatalf("event %v", ev)
	}
	id, _ := ev["id"].(string)

	// The principal (the default "self" approver) gets a mail.
	select {
	case mail := <-mails:
		if !strings.Contains(mail, "<"+me.Username+"@example.com>") || !strings.Contains(mail, "Approval needed: fs/write_file") ||
			!strings.Contains(mail, id) {
			t.Fatalf("mail:\n%s", mail)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no mail")
	}

	if code := controlDo(t, controlClient(e.ctlSock), "POST", "/v1/approvals/"+id, `{"decision":"deny"}`, nil); code != http.StatusNoContent {
		t.Fatalf("deny: %d", code)
	}
	if ev := nextEvent(); ev["type"] != "resolved" || ev["id"] != id {
		t.Fatalf("event %v", ev)
	}
}
