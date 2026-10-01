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
