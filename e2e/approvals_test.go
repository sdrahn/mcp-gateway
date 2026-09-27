package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// controlClient talks to the gateway's control API as the current user.
func controlClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
}

func controlDo(t *testing.T, c *http.Client, method, path, body string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, "http://control"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// readUntilResponse reads client messages until the response with id,
// returning it and the notification methods seen before it.
// A cancellation of the elicitation request withdrawn (the gateway
// withdraws it when the approval is decided before the client's answer to
// the elicitation arrives, which is a race in these tests) is not listed.
func readUntilResponse(c *client, id int, elicitation json.RawMessage) (msg, []string) {
	c.t.Helper()
	var seen []string
	for {
		m := c.read()
		if m.Method == "notifications/cancelled" && elicitation != nil {
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			if json.Unmarshal(m.Params, &p) == nil && string(p.RequestID) == string(elicitation) {
				continue
			}
		}
		if m.Method != "" {
			seen = append(seen, m.Method)
			continue
		}
		if string(m.ID) == fmt.Sprint(id) {
			return m, seen
		}
	}
}

func TestApprovalChannels(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-appr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })

	// write_file needs approval via the default channel (url, falling back
	// to out-of-band).
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "args": {"path": %q}}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, "^"+regexp.QuoteMeta(home)+"/", me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	ctl := controlClient(e.ctlSock)

	var who map[string]any
	if code := controlDo(t, ctl, "GET", "/v1/whoami", "", &who); code != 200 || who["name"] != me.Username {
		t.Fatalf("whoami: %d %v", code, who)
	}

	write := func(c *client, id int, name string) {
		c.request(id, "tools/call", map[string]any{"name": "write_file",
			"arguments": map[string]any{"path": filepath.Join(home, name), "content": name}})
	}

	t.Run("url mode, approved on the approval page", func(t *testing.T) {
		c := newClient(t, e.connect, e.gwSock, "fs")
		c.initialize(map[string]any{"elicitation": map[string]any{"url": map[string]any{}}})
		write(c, 2, "a.txt")
		el := c.read()
		var p struct {
			Mode, URL, ElicitationID string
		}
		_ = json.Unmarshal(el.Params, &p)
		if el.Method != "elicitation/create" || p.Mode != "url" || p.URL != "https://gw.example.com/approvals/"+p.ElicitationID {
			t.Fatalf("elicitation %+v %s", el, el.Params)
		}
		// The user agrees to open the page ...
		c.send(map[string]any{"jsonrpc": "2.0", "id": el.ID, "result": map[string]any{"action": "accept"}})
		// ... which shows the request and records the decision.
		var pending map[string]any
		if code := controlDo(t, ctl, "GET", "/v1/approvals/"+p.ElicitationID, "", &pending); code != 200 || pending["name"] != "write_file" {
			t.Fatalf("pending: %d %v", code, pending)
		}
		var g map[string]any
		if code := controlDo(t, ctl, "POST", "/v1/approvals/"+p.ElicitationID, `{"decision":"approve","scope":"session"}`, &g); code != 200 {
			t.Fatalf("approve: %d %v", code, g)
		}
		res, seen := readUntilResponse(c, 2, el.ID)
		text, isErr := toolResult(t, res)
		if isErr || !strings.HasPrefix(text, "wrote") {
			t.Fatalf("got %q %v", text, isErr)
		}
		if strings.Join(seen, ",") != "notifications/elicitation/complete" {
			t.Fatalf("notifications %v", seen)
		}

		// The session grant shows up in the grants list; revoking it makes
		// the next write ask again.
		var grants []map[string]any
		controlDo(t, ctl, "GET", "/v1/grants", "", &grants)
		if len(grants) != 1 || grants[0]["channel"] != "url" || grants[0]["approved_by"] != me.Username {
			t.Fatalf("grants %v", grants)
		}
		text, _ = toolResult(t, c.call(3, "write_file", map[string]any{"path": filepath.Join(home, "b.txt"), "content": "b"}))
		if !strings.HasPrefix(text, "wrote") {
			t.Fatalf("with grant: %q", text)
		}
		if code := controlDo(t, ctl, "DELETE", "/v1/grants/"+grants[0]["id"].(string), "", nil); code != 204 {
			t.Fatalf("revoke: %d", code)
		}
		write(c, 4, "c.txt")
		if m := c.read(); m.Method != "elicitation/create" {
			t.Fatalf("after revoke: %+v", m)
		}
	})

	t.Run("out of band, denied in the inbox", func(t *testing.T) {
		c := newClient(t, e.connect, e.gwSock, "fs")
		c.initialize(map[string]any{}) // no elicitation support
		write(c, 2, "d.txt")
		note := c.read()
		if note.Method != "notifications/message" || !strings.Contains(string(note.Params), "Waiting for approval") {
			t.Fatalf("notice %+v", note)
		}
		var pending []map[string]any
		controlDo(t, ctl, "GET", "/v1/approvals", "", &pending)
		var id string
		for _, p := range pending {
			if p["channel"] == "oob" {
				id = p["id"].(string)
			}
		}
		if id == "" {
			t.Fatalf("no oob approval in %v", pending)
		}
		if code := controlDo(t, ctl, "POST", "/v1/approvals/"+id, `{"decision":"deny"}`, nil); code != 204 {
			t.Fatalf("deny: %d", code)
		}
		res, _ := readUntilResponse(c, 2, nil)
		text, isErr := toolResult(t, res)
		if !isErr || !strings.Contains(text, "declined") {
			t.Fatalf("got %q %v", text, isErr)
		}
		if _, err := os.Stat(filepath.Join(home, "d.txt")); err == nil {
			t.Fatal("file written despite denial")
		}
	})
}

func TestPendingApprovalSurvivesRestart(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-restart")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "oob"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	write := func(c *client, id int) {
		c.request(id, "tools/call", map[string]any{"name": "write_file",
			"arguments": map[string]any{"path": filepath.Join(home, "r.txt"), "content": "after restart"}})
	}
	pending := func() []map[string]any {
		var ps []map[string]any
		controlDo(t, controlClient(e.ctlSock), "GET", "/v1/approvals", "", &ps)
		return ps
	}

	// A call waits for an out-of-band approval; then the gateway restarts.
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	write(c, 2)
	if note := c.read(); note.Method != "notifications/message" {
		t.Fatalf("notice %+v", note)
	}
	before := pending()
	if len(before) != 1 || before[0]["waiting"] != true {
		t.Fatalf("pending before the restart: %v", before)
	}
	e.restartGateway(t)

	// The approval is still pending, without a waiting call and without
	// the session scope.
	after := pending()
	if len(after) != 1 || after[0]["id"] != before[0]["id"] || after[0]["waiting"] != false {
		t.Fatalf("pending after the restart: %v", after)
	}
	if strings.Contains(fmt.Sprint(after[0]["scopes"]), "session") {
		t.Fatalf("session scope offered after the restart: %v", after[0]["scopes"])
	}
	id := after[0]["id"].(string)
	if code := controlDo(t, controlClient(e.ctlSock), "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"once"}`, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}

	// The agent's next attempt goes through once; the one after asks again.
	c2 := newClient(t, e.connect, e.gwSock, "fs")
	c2.initialize(map[string]any{})
	write(c2, 2)
	text, isErr := toolResult(t, c2.read())
	if isErr || !strings.HasPrefix(text, "wrote") {
		t.Fatalf("retry: %q %v", text, isErr)
	}
	write(c2, 3)
	if note := c2.read(); note.Method != "notifications/message" || !strings.Contains(string(note.Params), "Waiting for approval") {
		t.Fatalf("second retry: %+v", note)
	}
}
