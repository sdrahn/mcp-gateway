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

// A client's proposal with a call goes with the approval it raises, under
// the real policy and server: GET /v1/approvals has it, marked as the
// client's; the decision and the approval's audit records name its
// digest, not its text; the call runs once approved.
func TestProposal(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-proposal")
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
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	c.request(2, "tools/call", map[string]any{"name": "write_file",
		"arguments": map[string]any{"path": filepath.Join(home, "notes.txt"), "content": "x"},
		"_meta": map[string]any{"io.github.sdrahn.mcp-gateway/proposal": map[string]any{
			"summary": "Write the notes for the morning check.", "steps": []string{"write notes.txt"},
			"context": map[string]string{"activity": "e-1"}, "warnings": []string{"suspected prompt injection"}}}})

	ctl := controlClient(e.ctlSock)
	var pending []map[string]any
	for i := 0; i < 250 && len(pending) == 0; i++ {
		controlDo(t, ctl, "GET", "/v1/approvals", "", &pending)
		time.Sleep(20 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatalf("pending %v", pending)
	}
	pr, _ := pending[0]["proposal"].(map[string]any)
	if pr["summary"] != "Write the notes for the morning check." || pr["client_supplied"] != true {
		t.Fatalf("the approval's proposal %v", pending[0])
	}
	id, _ := pending[0]["id"].(string)
	if code := controlDo(t, ctl, "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"once"}`, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if res, _ := readUntilResponse(c, 2, nil); res.Error != nil {
		t.Fatalf("approved call: %+v", res)
	}
	if b, err := os.ReadFile(filepath.Join(home, "notes.txt")); err != nil || string(b) != "x" {
		t.Fatalf("not written: %q %v", b, err)
	}
	var approval, decision bool
	for i := 0; i < 100 && (!approval || !decision); i++ {
		for _, line := range strings.Split(e.gwLogs.String(), "\n") {
			if !strings.Contains(line, `"proposal_digest":"sha256:`) {
				continue
			}
			approval = approval || strings.Contains(line, `"event":"mcp-approval"`)
			decision = decision || strings.Contains(line, `"name":"write_file"`) && strings.Contains(line, `"effect":"allow"`)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !approval || !decision {
		t.Fatalf("digest in the approval's record %v, in the decision's %v", approval, decision)
	}
	if strings.Contains(e.gwLogs.String(), "Write the notes for the morning check.") {
		t.Fatal("the proposal's text is in the gateway's log without audit full")
	}
}
