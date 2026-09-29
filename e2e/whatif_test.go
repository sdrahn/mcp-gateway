package e2e

import (
	"encoding/json"
	"os/user"
	"strings"
	"testing"
)

// TestPolicyWhatIf asks the control API what a role data change would
// change: real OPA with the shipped policy, the tool list from the demo
// server's shared discovery instance.
func TestPolicyWhatIf(t *testing.T) {
	opaBinary(t)
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home := t.TempDir()
	current := `{"roles": {"reader": {"permissions": [{"server": "fs", "tool": "read_*"}]}},
	  "bindings": {"users": {"` + me.Username + `": ["reader"]}, "groups": {}},
	  "approvers": {"default": ["self", "user:` + me.Username + `"]}}`
	e := setup(t, current, map[string]string{"fs": home}, "")

	proposed := strings.Replace(current, `[{"server": "fs", "tool": "read_*"}]`,
		`[{"server": "fs", "tool": "read_*"}, {"server": "fs", "tool": "write_*", "require_approval": true}]`, 1)
	proposed = strings.Replace(proposed, `"groups": {}`, `"groups": {"e2e-nobody": ["reader"]}`, 1)
	var out struct {
		Changes []struct {
			Principal, Server, Kind, Name, Before, After string
		} `json:"changes"`
		Principals int               `json:"principals"`
		Resources  int               `json:"resources"`
		Unchecked  map[string]string `json:"unchecked"`
	}
	if code := controlDo(t, controlClient(e.ctlSock), "POST", "/v1/policy/whatif", proposed, &out); code != 200 {
		t.Fatalf("status %d", code)
	}
	if out.Principals != 2 || out.Resources == 0 || len(out.Unchecked) != 0 {
		t.Fatalf("%+v", out)
	}
	got := map[string]bool{}
	for _, c := range out.Changes {
		got[c.Principal+" "+c.Server+"/"+c.Name+" "+c.Before+"→"+c.After] = true
	}
	for _, want := range []string{
		"user:" + me.Username + " fs/write_file deny→ask",
		"group:e2e-nobody fs/read_file deny→allow",
	} {
		if !got[want] {
			b, _ := json.Marshal(out.Changes)
			t.Errorf("missing %q in %s", want, b)
		}
	}

	// The same role data changes nothing.
	if code := controlDo(t, controlClient(e.ctlSock), "POST", "/v1/policy/whatif", current, &out); code != 200 || len(out.Changes) != 0 {
		t.Fatalf("status %d, changes %+v", code, out.Changes)
	}
}
