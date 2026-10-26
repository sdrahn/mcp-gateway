package e2e

import (
	"encoding/json"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// A rule the policy cannot decide for one tool (two values, as issue
// #298's two channels gave) hides that tool alone: the listing is
// decided again tool by tool, under the real OPA, and the principal
// keeps the others. The call of the tool is denied.
func TestListingContainsPolicyErrors(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	rbac := fmt.Sprintf(`{
	  "roles": {"editor": {"permissions": [{"server": "files", "tool": "*"}]}},
	  "bindings": {"groups": {}, "users": {%q: ["editor"]}}
	}`, me.Username)
	conflict := `package mcp.authz

import rego.v1

e2e_conflict := 1 if input.resource.name == "write_file"

e2e_conflict := 2 if input.resource.name == "write_file"

denied if e2e_conflict == 3
`
	e := setupWith(t, rbac, map[string]string{"files": root}, "", func(tmp, opaSock string) []string {
		modules, _ := filepath.Glob(filepath.Join("..", "policy", "mcp", "*.rego"))
		extra := filepath.Join(tmp, "e2e_conflict.rego")
		writeFile(t, extra, conflict)
		return append([]string{"run", "--server", "--addr", "unix://" + opaSock},
			append(modules, extra, "mcp:"+filepath.Join(tmp, "data"))...)
	})
	c := newClient(t, e.connect, e.gwSock, "files")
	c.initialize(map[string]any{})

	c.request(2, "tools/list", map[string]any{})
	m := c.read()
	var res struct{ Tools []struct{ Name string } }
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatalf("tools/list: %v %s", err, m.Result)
	}
	listed := map[string]bool{}
	for _, tl := range res.Tools {
		listed[tl.Name] = true
	}
	if !listed["read_text_file"] || !listed["list_directory"] || listed["write_file"] {
		t.Fatalf("listed %v, want all but write_file\n%s", listed, e.gwLogs.String())
	}
	logs := e.gwLogs.String()
	if !strings.Contains(logs, "filtering failed; hiding what the policy cannot decide") ||
		!strings.Contains(logs, "hidden=write_file") || !strings.Contains(logs, "eval_conflict_error") {
		t.Errorf("the journal does not name the hidden tool and OPA's error:\n%s", logs)
	}
	if strings.Contains(logs, "hiding everything") {
		t.Errorf("hid everything")
	}

	m = c.call(3, "write_file", map[string]any{"path": filepath.Join(root, "x"), "content": "x"})
	if m.Error == nil && !strings.Contains(string(m.Result), `"isError":true`) {
		t.Errorf("write_file ran: %s", m.Result)
	}
}
