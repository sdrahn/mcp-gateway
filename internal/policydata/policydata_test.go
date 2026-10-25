package policydata

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedData(t *testing.T) {
	for _, file := range []string{
		filepath.Join("..", "..", "policy", "mcp", "rbac", "data.yaml"),
		filepath.Join("..", "..", "examples", "dev", "rbac", "data.json"),
	} {
		_, data, _, err := Read(file)
		if err != nil {
			t.Fatal(err)
		}
		problems, err := Check(data)
		if err != nil || len(problems) > 0 {
			t.Errorf("%s: %v %q", file, err, problems)
		}
	}
}

// The update test's copy of 1.4's default (test/vm/default-1.4.json) is
// one the package removes from /etc on update: its checksum is listed.
func TestPreviousDefault(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "vm", "default-1.4.json"))
	if err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile(filepath.Join("..", "..", "packaging", "rbac", "previous-defaults.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if !strings.Contains("\n"+string(sums), "\n"+hex.EncodeToString(sum[:])+"\n") {
		t.Errorf("previous-defaults.sha256 does not list test/vm/default-1.4.json (%x)", sum)
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
			{"server": "*", "client": "sampling/createMessage", "allow_sensitive": true},
			{"server": "*", "resource": "file://${home}/*", "effect": "deny"}]}},
			"bindings": {"users": {"alice": ["r"]}, "groups": {"dev": ["r"]}},
			"approvers": {"default": ["self", "role:r", "group:wheel", "user:bob"]}}`, nil},
		{"approval scopes", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_approval": true,
			"approval_scopes": ["once", "session", "30m", "720h"]}]}}}`, nil},
		{"bad approval scopes", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_approval": true,
			"approval_scopes": ["1d"]}]}}}`, []string{"/roles/r/permissions/0/approval_scopes/0: "}},
		{"approval scope too long", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "require_approval": true,
			"approval_scopes": ["once", "721h"]}]}}}`, []string{`/roles/r/permissions/0/approval_scopes/1: "721h" is longer than 720h`}},
		{"not JSON", `{"roles": `, []string{"not valid JSON: line 1, column 10: unexpected end of JSON input"}},
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
		{"remote approver rules", `{"roles": {}, "approvers": {"fs": ["remote-user:u-7f3a", "remote-group:ops"]}}`, nil},
		{"bad remote approver rule", `{"roles": {}, "approvers": {"fs": ["remote:u-7f3a"]}}`,
			[]string{"/approvers/fs/0: 'remote:u-7f3a' does not match pattern"}},
		{"bad approver rule", `{"roles": {}, "approvers": {"default": ["admins"]}}`,
			[]string{"/approvers/default/0: 'admins' does not match pattern"}},
		{"bad regular expressions", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "args": {"path": "("},
			"obligations": {"redact_output": "[", "arg_constraints": {"a": ["ok", "*"]}, "pseudonymize": {"patterns": {"c": "(?P<"}}}}]}}}`,
			[]string{"/roles/r/permissions/0/args/path: invalid regular expression",
				"/roles/r/permissions/0/obligations/arg_constraints/a/1: invalid regular expression",
				"/roles/r/permissions/0/obligations/pseudonymize/patterns/c: invalid regular expression",
				"/roles/r/permissions/0/obligations/redact_output/0: invalid regular expression"}},
		{"scopes", `{"roles": {"viewer": {"permissions": []}}, "scopes": {
			"mcp:read": {"roles": ["viewer"]},
			"mcp:fs": {"description": "d", "permissions": [{"server": "fs", "tool": "*", "args": {"path": "^/srv/"}}, {"server": "fs", "resource": "*"}]},
			"mcp:admin": {"unlimited": true}, "default": {"permissions": []}}}`, nil},
		{"scope ceiling with qualifying fields", `{"roles": {}, "scopes": {"mcp:fs": {"permissions": [
			{"server": "fs", "tool": "*", "require_approval": true}]}}}`,
			[]string{"/scopes/mcp:fs/permissions/0: additional properties 'require_approval' not allowed"}},
		{"scope ceiling empty or limited", `{"roles": {}, "scopes": {"a": {}, "b": {"unlimited": false}}}`,
			[]string{"/scopes/a: missing property", "/scopes/b/unlimited: value must be true"}},
		{"scope ceiling problems", `{"roles": {}, "scopes": {"mcp:x": {"roles": ["viewr"], "permissions": [{"server": "fs", "tool": "x", "args": {"p": "("}}]}}}`,
			[]string{`/scopes/mcp:x/permissions/0/args/p: invalid regular expression`, `/scopes/mcp:x/roles/0: unknown role "viewr"`}},
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
	write := func(setup, name, content string) {
		t.Helper()
		p := filepath.Join(dir, "mcp", "profiles", setup)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("systemd", "data.json", `{"roles": {"systemd-reader": {"permissions": [{"server": "systemd", "tool": "list_*"}]}}}`)
	write("zypp", "data.json", `{"roles": {"zypp-reader": {"permissions": [{"server": "zypp", "tool": "search_packages"}]},
		"systemd-reader": {"permissions": []}}}`)
	write("broken", "data.json", `{"roles": {"x": {}}}`)
	// A setup in YAML; its JSON next to it is ignored.
	write("podman", "data.yaml", "roles:\n  podman-reader:\n    permissions:\n      - {server: podman, tool: container_list}\n")
	write("podman", "data.json", `{"roles": {"podman-old": {"permissions": []}}}`)
	write("unparsed", "data.yaml", "roles: [\n")

	roles, problems, err := ShippedRoles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if roles["systemd-reader"] != "systemd" || roles["zypp-reader"] != "zypp" || roles["podman-reader"] != "podman" || len(roles) != 3 {
		t.Errorf("roles %v", roles)
	}
	if len(problems) != 3 || !strings.Contains(problems[0], "broken/data.json") ||
		!strings.Contains(problems[1], "unparsed/data.yaml: not valid YAML") ||
		!strings.Contains(problems[2], `role "systemd-reader" is shipped by setup "systemd" as well`) {
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
