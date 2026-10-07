package e2e

import (
	"encoding/json"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// Tool descriptions say what the principal's roles allow, as the real
// policy computes it (roadmap step 29): an argument constraint, expanded
// for the principal, and an approval with its channel; a tool allowed
// without limits keeps its description.
func TestToolHints(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	rbac := fmt.Sprintf(`{
	  "roles": {"reader": {"permissions": [
	    {"server": "files", "tool": "read_text_file", "args": {"path": "^%s/docs/"}},
	    {"server": "files", "tool": "write_file", "require_approval": true, "approval_channel": "oob"},
	    {"server": "files", "tool": "list_directory"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["reader"]}}
	}`, root, me.Username)
	e := setup(t, rbac, map[string]string{"files": root}, "")
	c := newClient(t, e.connect, e.gwSock, "files")
	c.initialize(map[string]any{})

	c.request(2, "tools/list", map[string]any{})
	m := c.read()
	var res struct {
		Tools []struct{ Name, Description string }
	}
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatalf("tools/list: %v %s", err, m.Result)
	}
	desc := map[string]string{}
	for _, tl := range res.Tools {
		desc[tl.Name] = tl.Description
	}
	if d := desc["read_text_file"]; !strings.Contains(d, "[mcp-gateway] According to your roles, calls need path starting with "+filepath.Join(root, "docs")+"/.") {
		t.Errorf("read_text_file: %q", d)
	}
	if d := desc["write_file"]; !strings.Contains(d, "Each call needs a human approval, out of band") {
		t.Errorf("write_file: %q", d)
	}
	if d := desc["list_directory"]; strings.Contains(d, "[mcp-gateway]") {
		t.Errorf("list_directory: %q", d)
	}
	if _, ok := desc["delete_file"]; ok {
		t.Errorf("delete_file listed: %v", desc)
	}

	// A call outside the constraint is denied with what the roles allow,
	// without the value sent.
	text, isErr := toolResult(t, c.call(3, "read_text_file", map[string]any{"path": "/etc/hostname"}))
	want := "no matching permission: the arguments are outside what your roles allow (path: ^" + root + "/docs/)"
	if !isErr || !strings.Contains(text, want) || strings.Contains(text, "/etc/hostname") {
		t.Errorf("denial: %q, want %q", text, want)
	}
}
