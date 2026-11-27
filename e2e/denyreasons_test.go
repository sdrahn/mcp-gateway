package e2e

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// A policy module gives the reason for a denial it causes
// (deny_reasons) and explains a request that matches no permission
// (unmatched_reasons): under the real OPA, the client's error and the
// audit record name them instead of "denied by policy" and "no matching
// permission"; a denial the module does not explain reads as before.
func TestModuleDenialReasons(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	rbac := fmt.Sprintf(`{
	  "roles": {"reader": {"permissions": [
	    {"server": "files", "tool": "read_*"},
	    {"server": "files", "tool": "write_file"},
	    {"server": "files", "tool": "create_directory", "effect": "deny"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["reader"]}}
	}`, me.Username)
	module := `package mcp.authz

import rego.v1

denied if input.resource.name == "write_file"

deny_reasons contains "the agent is paused" if input.resource.name == "write_file"

unmatched_reasons contains "task category files-cleanup is not enabled on this host" if {
	input.resource.name == "move_file"
}
`
	e := setupWith(t, rbac, map[string]string{"files": root}, "", func(tmp, opaSock string) []string {
		modules, _ := filepath.Glob(filepath.Join("..", "policy", "mcp", "*.rego"))
		extra := filepath.Join(tmp, "e2e_reasons.rego")
		writeFile(t, extra, module)
		return append([]string{"run", "--server", "--addr", "unix://" + opaSock},
			append(modules, extra, "mcp:"+filepath.Join(tmp, "data"))...)
	})
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()
	c := newClient(t, e.connect, e.gwSock, "files")
	c.initialize(map[string]any{})

	for i, tc := range []struct {
		tool   string
		args   map[string]any
		reason string
	}{
		// The module's denial, with its reason.
		{"write_file", map[string]any{"path": filepath.Join(root, "x"), "content": "x"}, "the agent is paused"},
		// No permission, explained by the module.
		{"move_file", map[string]any{"source": filepath.Join(root, "a"), "destination": filepath.Join(root, "b")},
			"task category files-cleanup is not enabled on this host"},
		// No permission, not explained: as before.
		{"edit_file", map[string]any{"path": filepath.Join(root, "x"), "edits": []any{}}, "no matching permission"},
		// A permission denies it, no module reason: as before.
		{"create_directory", map[string]any{"path": filepath.Join(root, "d")}, "denied by policy"},
	} {
		m := c.call(10+i, tc.tool, tc.args)
		if m.Error != nil || !strings.Contains(string(m.Result), `"isError":true`) ||
			!strings.Contains(string(m.Result), "mcp-gateway: "+tc.reason) {
			t.Errorf("%s: the client got %s %v, want the reason %q", tc.tool, m.Result, m.Error, tc.reason)
		}
		audited := false
		for _, line := range strings.Split(e.gwLogs.String(), "\n") {
			if strings.Contains(line, `"audit":true`) && strings.Contains(line, `"name":"`+tc.tool+`"`) &&
				strings.Contains(line, `"effect":"deny"`) && strings.Contains(line, `"reason":"`+tc.reason+`"`) {
				audited = true
			}
		}
		if !audited {
			t.Errorf("%s: no audit record of the denial with the reason %q", tc.tool, tc.reason)
		}
	}
}
