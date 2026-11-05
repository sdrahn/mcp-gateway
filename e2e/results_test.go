package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// mcpResult waits for the mcp-result audit record of the call with
// progress token tok in the gateway's logs.
func mcpResult(t *testing.T, e *env, tok string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(e.gwLogs.String(), "\n") {
			if !strings.Contains(line, `"event":"mcp-result"`) || !strings.Contains(line, `"progress_token":"`+tok+`"`) {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("%v: %s", err, line)
			}
			return rec
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no mcp-result record for %s:\n%s", tok, e.gwLogs.String())
	return nil
}

// The outcome of each forwarded call is audited by the gateway (event
// mcp-result), with the real policy and server: ok, a tool error with no
// text in the digest mode, and an approved call naming its approval and
// grant.
func TestCallResults(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello world")
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "read_*"},
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "oob"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})

	call := func(id int, tool, tok string, args map[string]any) {
		c.request(id, "tools/call", map[string]any{"name": tool, "arguments": args,
			"_meta": map[string]any{"progressToken": tok}})
	}
	call(2, "read_file", "ok-1", map[string]any{"path": filepath.Join(home, "hello.txt")})
	if text, isErr := toolResult(t, c.read()); isErr || text != "hello world" {
		t.Fatalf("read: %q %v", text, isErr)
	}
	rec := mcpResult(t, e, "ok-1")
	if rec["outcome"] != "ok" || rec["server"] != "fs" || rec["name"] != "read_file" || rec["sub"] != me.Username {
		t.Fatalf("ok: %+v", rec)
	}
	ids := regexp.MustCompile(`"decision_id":"([0-9a-f]{32})"`).FindAllStringSubmatch(e.gwLogs.String(), -1)
	if len(ids) == 0 || rec["decision_id"] != ids[0][1] {
		t.Fatalf("decision id %v, decisions %v", rec["decision_id"], ids)
	}

	call(3, "read_file", "err-1", map[string]any{"path": filepath.Join(home, "missing.txt")})
	if _, isErr := toolResult(t, c.read()); !isErr {
		t.Fatal("reading a missing file succeeded")
	}
	if rec := mcpResult(t, e, "err-1"); rec["outcome"] != "tool_error" || rec["error"] != nil {
		t.Fatalf("tool error (digest mode, no text): %+v", rec)
	}

	call(4, "write_file", "approved-1", map[string]any{"path": filepath.Join(home, "a.txt"), "content": "x"})
	ctl := controlClient(e.ctlSock)
	var id string
	for i := 0; i < 250 && id == ""; i++ {
		var pending []map[string]any
		controlDo(t, ctl, "GET", "/v1/approvals", "", &pending)
		if len(pending) == 1 {
			id, _ = pending[0]["id"].(string)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no approval pending")
	}
	var g struct {
		ID         string `json:"id"`
		ApprovalID string `json:"approval_id"`
	}
	if code := controlDo(t, ctl, "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"session"}`, &g); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if g.ApprovalID != id {
		t.Fatalf("grant %+v for approval %s", g, id)
	}
	if res, _ := readUntilResponse(c, 4, nil); res.Error != nil {
		t.Fatalf("approved write: %+v", res)
	}
	if rec := mcpResult(t, e, "approved-1"); rec["outcome"] != "ok" || rec["approval_id"] != id || rec["grant"] != g.ID {
		t.Fatalf("approved (approval %s, grant %s): %+v", id, g.ID, rec)
	}

	// The next write is allowed by the session's grant.
	call(5, "write_file", "granted-1", map[string]any{"path": filepath.Join(home, "b.txt"), "content": "x"})
	if res, _ := readUntilResponse(c, 5, nil); res.Error != nil {
		t.Fatalf("granted write: %+v", res)
	}
	if rec := mcpResult(t, e, "granted-1"); rec["outcome"] != "ok" || rec["grant"] != g.ID || rec["approval_id"] != id {
		t.Fatalf("by grant %s: %+v", g.ID, rec)
	}
}
