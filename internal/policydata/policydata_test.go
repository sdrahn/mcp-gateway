package policydata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedData(t *testing.T) {
	for _, file := range []string{
		filepath.Join("..", "..", "policy", "mcp", "rbac", "data.json"),
		filepath.Join("..", "..", "examples", "poc", "rbac", "data.json"),
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		problems, err := Check(data)
		if err != nil || len(problems) > 0 {
			t.Errorf("%s: %v %q", file, err, problems)
		}
	}
}

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       []string // substrings, one per problem, in order
	}{
		{"minimal", `{"roles": {}}`, nil},
		{"version 1", `{"version": 1, "roles": {}}`, nil},
		{"newer version", `{"version": 2, "roles": {}}`, []string{"/version: 2 is newer than this gateway reads (1)"}},
		{"version 0", `{"version": 0, "roles": {}}`, []string{"/version: 0 is not supported"}},
		{"version not a number", `{"version": "1", "roles": {}}`, []string{"/version: must be a number"}},
		{"version not an integer", `{"version": 1.5, "roles": {}}`, []string{"/version: must be an integer"}},
		{"full permission", `{"roles": {"r": {"description": "d", "permissions": [
			{"server": "fs", "tool": "write_*", "require_approval": true, "approval_channel": "form",
			 "args": {"path": "^/srv/"}, "require_client_cert": true,
			 "obligations": {"redact_output": ["secret"], "max_output_bytes": 1000, "rate_limit": "10/m",
			   "arg_constraints": {"path": "^/srv/"}, "audit": "full", "reidentify": "customer",
			   "pseudonymize": {"detect": ["email", "iban"], "patterns": {"customer": "C-[0-9]+"}, "fields": {"name": "person"}}}},
			{"server": "*", "client": "sampling.create", "allow_sensitive": true},
			{"server": "*", "resource": "file://${home}/*", "effect": "deny"}]}},
			"bindings": {"users": {"alice": ["r"]}, "groups": {"dev": ["r"]}},
			"approvers": {"default": ["self", "role:r", "group:wheel", "user:bob"]}}`, nil},
		{"approval scopes", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_approval": true,
			"approval_scopes": ["once", "session", "30m", "720h"]}]}}}`, nil},
		{"bad approval scopes", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_approval": true,
			"approval_scopes": ["1d"]}]}}}`, []string{"/roles/r/permissions/0/approval_scopes/0: "}},
		{"approval scope too long", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_approval": true,
			"approval_scopes": ["once", "721h"]}]}}}`, []string{`/roles/r/permissions/0/approval_scopes/1: "721h" is longer than 720h`}},
		{"not JSON", `{"roles": `, []string{"not valid JSON"}},
		{"typo at top level", `{"roles": {}, "binding": {}}`, []string{"/: additional properties 'binding' not allowed"}},
		{"no roles", `{}`, []string{"/: missing property 'roles'"}},
		{"permission without target", `{"roles": {"r": {"permissions": [{"server": "fs"}]}}}`,
			[]string{"/roles/r/permissions/0: missing property 'client', or missing property 'prompt'"}},
		{"misspelt field", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_aproval": true}]}}}`,
			[]string{"/roles/r/permissions/0: additional properties 'require_aproval' not allowed"}},
		{"bad values", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "effect": "block",
			"obligations": {"rate_limit": "10/min", "pseudonymize": {"detect": "name"}}}]}}}`,
			[]string{"/roles/r/permissions/0/effect: value must be one of",
				"/roles/r/permissions/0/obligations/pseudonymize/detect: got string, want array, or value must be one of 'email'",
				"/roles/r/permissions/0/obligations/rate_limit: "}},
		{"binding not a list", `{"roles": {"r": {"permissions": []}}, "bindings": {"users": {"alice": "r"}}}`,
			[]string{"/bindings/users/alice: got string, want array"}},
		{"bad approver rule", `{"roles": {}, "approvers": {"default": ["admins"]}}`,
			[]string{"/approvers/default/0: 'admins' does not match pattern"}},
		{"bad regular expressions", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "args": {"path": "("},
			"obligations": {"redact_output": "[", "arg_constraints": {"a": ["ok", "*"]}, "pseudonymize": {"patterns": {"c": "(?P<"}}}}]}}}`,
			[]string{"/roles/r/permissions/0/args/path: invalid regular expression",
				"/roles/r/permissions/0/obligations/arg_constraints/a/1: invalid regular expression",
				"/roles/r/permissions/0/obligations/pseudonymize/patterns/c: invalid regular expression",
				"/roles/r/permissions/0/obligations/redact_output/0: invalid regular expression"}},
		{"unknown roles", `{"roles": {"r": {"permissions": []}}, "bindings": {"users": {"alice": ["r", "admn"]}, "groups": {"dev": ["x"]}},
			"approvers": {"db": ["self", "role:dba"]}}`,
			[]string{`/approvers/db/1: unknown role "dba"`, `/bindings/groups/dev/0: unknown role "x"`, `/bindings/users/alice/1: unknown role "admn"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problems, err := Check([]byte(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != len(tc.want) {
				t.Fatalf("got %d problems, want %d:\n%s", len(problems), len(tc.want), strings.Join(problems, "\n"))
			}
			for i, w := range tc.want {
				if !strings.Contains(problems[i], w) {
					t.Errorf("problem %d: %q, want %q", i, problems[i], w)
				}
			}
		})
	}
}

func TestShippedRoles(t *testing.T) {
	dir := t.TempDir()
	write := func(setup, content string) {
		t.Helper()
		p := filepath.Join(dir, "mcp", "profiles", setup)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "data.json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("systemd", `{"roles": {"systemd-reader": {"permissions": [{"server": "systemd", "tool": "list_*"}]}}}`)
	write("zypp", `{"roles": {"zypp-reader": {"permissions": [{"server": "zypp", "tool": "search_packages"}]},
		"systemd-reader": {"permissions": []}}}`)
	write("broken", `{"roles": {"x": {}}}`)

	roles, problems, err := ShippedRoles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if roles["systemd-reader"] != "systemd" || roles["zypp-reader"] != "zypp" || len(roles) != 2 {
		t.Errorf("roles %v", roles)
	}
	if len(problems) != 2 || !strings.Contains(problems[0], "broken/data.json") ||
		!strings.Contains(problems[1], `role "systemd-reader" is shipped by setup "systemd" as well`) {
		t.Errorf("problems %q", problems)
	}

	// Bindings may name shipped roles.
	data := []byte(`{"roles": {}, "bindings": {"users": {"alice": ["systemd-reader", "nope"]}}}`)
	ps, err := CheckWith(data, roles)
	if err != nil || len(ps) != 1 || !strings.Contains(ps[0], `unknown role "nope"`) {
		t.Errorf("CheckWith: %v %q", err, ps)
	}

	if roles, problems, err := ShippedRoles(filepath.Join(dir, "missing")); err != nil || len(roles) != 0 || len(problems) != 0 {
		t.Errorf("missing dir: %v %v %v", roles, problems, err)
	}
}
