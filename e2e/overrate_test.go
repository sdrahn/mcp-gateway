package e2e

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A permission's approval_over_rate under the real policy: two calls in
// the minute run, the third waits for an approval out of band, once only,
// that names the rate; approved, it runs; the decision and approval
// records carry over_rate.
func TestApprovalOverRate(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-overrate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello")
	rbac := fmt.Sprintf(`{
	  "roles": {"reader": {"permissions": [
	    {"server": "fs", "tool": "read_file", "obligations": {"approval_over_rate": "2/m"}}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["reader"]}}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	args := map[string]any{"path": filepath.Join(home, "hello.txt")}
	for i := range 2 {
		if text, isErr := toolResult(t, c.call(10+i, "read_file", args)); isErr || text != "hello" {
			t.Fatalf("call %d: %q", i, text)
		}
	}
	c.request(12, "tools/call", map[string]any{"name": "read_file", "arguments": args})
	ctl := controlClient(e.ctlSock)
	var pending []map[string]any
	for i := 0; i < 250 && len(pending) == 0; i++ {
		controlDo(t, ctl, "GET", "/v1/approvals", "", &pending)
		time.Sleep(20 * time.Millisecond)
	}
	if len(pending) != 1 || pending[0]["over_rate"] != "2/m" || pending[0]["channel"] != "oob" ||
		fmt.Sprint(pending[0]["scopes"]) != "[once]" || !strings.Contains(fmt.Sprint(pending[0]["prompt"]), "Rate 2/m reached") {
		t.Fatalf("pending %v", pending)
	}
	id, _ := pending[0]["id"].(string)
	if code := controlDo(t, ctl, "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"once"}`, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	res, _ := readUntilResponse(c, 12, nil)
	if text, isErr := toolResult(t, res); isErr || text != "hello" {
		t.Fatalf("approved call: %q", text)
	}
	var decision, approval bool
	for i := 0; i < 100 && (!decision || !approval); i++ {
		for _, line := range strings.Split(e.gwLogs.String(), "\n") {
			if !strings.Contains(line, `"over_rate":"2/m"`) {
				continue
			}
			decision = decision || strings.Contains(line, `"name":"read_file"`) && strings.Contains(line, `"effect":"allow"`)
			approval = approval || strings.Contains(line, `"event":"mcp-approval"`)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !decision || !approval {
		t.Fatalf("over_rate in the decision record %v, in mcp-approval %v", decision, approval)
	}
}
