package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A trusted local service posts a notice about an agent over the control
// socket (post_notice allows it); under the real policy its audience is
// the approvers of the agent's requests on the notice's servers: they
// see it in GET /v1/notices and on the event stream, its notify
// recipients get one mail, and it is audited; dismissing hides it.
func TestNotices(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	smtpAddr, mails := mailSink(t)
	// The current user approves fs only; the default rules name nobody
	// the test runs as.
	rbac := fmt.Sprintf(`{
	  "roles": {},
	  "approvers": {"fs": [%q], "default": ["user:nobody-in-particular"]},
	  "bindings": {"groups": {}, "users": {}}
	}`, "user:"+me.Username)
	module := fmt.Sprintf(`package mcp.approvals

import rego.v1

post_notice if input.approver.name == %q
`, me.Username)
	e := setupWith(t, rbac, nil, fmt.Sprintf(`notifications:
  email:
    smtp: %s
    from: mcp-gateway@test
    to: "{user}@example.com"
`, smtpAddr), func(tmp, opaSock string) []string {
		modules, _ := filepath.Glob(filepath.Join("..", "policy", "mcp", "*.rego"))
		extra := filepath.Join(tmp, "e2e_notices.rego")
		writeFile(t, extra, module)
		return append([]string{"run", "--server", "--addr", "unix://" + opaSock},
			append(modules, extra, "mcp:"+filepath.Join(tmp, "data"))...)
	})
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()
	ctl := controlClient(e.ctlSock)

	resp, err := ctl.Get("http://control/v1/events")
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

	var n map[string]any
	if code := controlDo(t, ctl, "POST", "/v1/notices", `{"principal": "agent-patch-pilot", "servers": ["fs"],
		"severity": "warning", "title": "patch-errata demoted", "text": "Override rate 7.1 % above 5.0 %: back to supervised."}`, &n); code != 201 {
		t.Fatalf("post: %d %v", code, n)
	}
	id, _ := n["id"].(string)
	if id == "" || n["posted_by"] != me.Username {
		t.Fatalf("notice %v", n)
	}
	select {
	case ev := <-events:
		if ev["type"] != "notice" || ev["id"] != id {
			t.Fatalf("event %v", ev)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
	select {
	case mail := <-mails:
		if !strings.Contains(mail, "<"+me.Username+"@example.com>") || !strings.Contains(mail, "Warning: patch-errata demoted") ||
			!strings.Contains(mail, "Override rate 7.1 %") {
			t.Fatalf("mail:\n%s", mail)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no mail")
	}
	audited := false
	for i := 0; i < 100 && !audited; i++ {
		audited = strings.Contains(e.gwLogs.String(), `"event":"mcp-notice"`) && strings.Contains(e.gwLogs.String(), `"id":"`+id+`"`)
		time.Sleep(20 * time.Millisecond)
	}
	if !audited {
		t.Fatal("the post is not audited")
	}

	// Not for the current user: a notice on a server it does not approve.
	var other map[string]any
	if code := controlDo(t, ctl, "POST", "/v1/notices", `{"principal": "agent-patch-pilot", "servers": ["zypp"], "title": "elsewhere"}`, &other); code != 201 {
		t.Fatalf("post: %d", code)
	}
	var list []map[string]any
	controlDo(t, ctl, "GET", "/v1/notices", "", &list)
	if me.Uid != "0" && (len(list) != 1 || list[0]["id"] != id) {
		t.Fatalf("notices %v", list)
	}
	if code := controlDo(t, ctl, "POST", "/v1/notices/"+id+"/dismiss", "", nil); code != 204 {
		t.Fatalf("dismiss: %d", code)
	}
	list = nil
	controlDo(t, ctl, "GET", "/v1/notices", "", &list)
	for _, l := range list {
		if l["id"] == id {
			t.Fatalf("dismissed notice listed: %v", list)
		}
	}
	// (Root, the approver of everything, also sees the second notice.)
	for {
		select {
		case ev := <-events:
			if ev["type"] == "notice" && ev["id"] == other["id"] && me.Uid == "0" {
				continue
			}
			if ev["type"] != "notice-closed" || ev["id"] != id {
				t.Fatalf("event %v", ev)
			}
			return
		case <-time.After(10 * time.Second):
			t.Fatal("no notice-closed event")
		}
	}
}
