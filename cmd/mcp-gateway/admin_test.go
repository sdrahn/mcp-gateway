package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

func TestAdminUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runAdminServer([]string{"extra"}, &out, &errb); rc != 2 {
		t.Errorf("extra argument: rc %d", rc)
	}
	if rc := runAdminServer([]string{"-h"}, &out, &errb); rc != 0 || !strings.Contains(errb.String(), "usage: mcp-gateway admin-server") {
		t.Errorf("-h: rc %d, %s", rc, errb.String())
	}
}

// testAdmin is an admin server on a configuration in a temporary
// directory: gateway.yaml, one server definition, role data.
func testAdmin(t *testing.T) (*adminServer, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("servers.d/sys.yaml", "name: sys\ncommand: [/usr/bin/true]\nenv:\n  API_TOKEN: s3cret\n  LEVEL: info\n")
	cfg := write("gateway.yaml", "servers_dir: "+filepath.Join(dir, "servers.d")+"\nvendor_servers_dir: "+filepath.Join(dir, "none")+
		"\nstate_dir: "+filepath.Join(dir, "state")+
		"\npolicy:\n  opa_socket: "+filepath.Join(dir, "opa.sock")+"\napprovals:\n  control_socket: "+filepath.Join(dir, "control.sock")+"\n")
	rbac := write("etc-policy/rbac/data.json", `{"roles": {"reader": {"permissions": [{"server": "sys", "tool": "read_*"}]}},
"bindings": {"users": {"`+currentUser(t)+`": ["reader"]}}}`)
	return &adminServer{configPath: cfg, policyData: rbac, shipped: filepath.Join(dir, "shipped"),
		etcPolicy: filepath.Join(dir, "etc-policy"), opa: "opa"}, dir
}

func currentUser(t *testing.T) string {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	return u.Username
}

// callTool calls a tool and returns its text and whether it is an error.
func callTool(t *testing.T, a *adminServer, name string, args any) (string, bool, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := a.call(context.Background(), name, raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	m := res.(map[string]any)
	text := m["content"].([]map[string]any)[0]["text"].(string)
	isErr, _ := m["isError"].(bool)
	sc, _ := m["structuredContent"].(map[string]any)
	return text, isErr, sc
}

func TestAdminToolList(t *testing.T) {
	a, _ := testAdmin(t)
	res, err := a.handle(context.Background(), "tools/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.(map[string]any)["tools"].([]map[string]any) {
		names = append(names, tool["name"].(string))
		if tool["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Errorf("%s: not read-only", tool["name"])
		}
	}
	if got := strings.Join(names, " "); got != "doctor check_config explain_decision show_config recent_audit selinux_denials" {
		t.Errorf("tools: %s", got)
	}
	if _, err := a.call(context.Background(), "nope", nil); err == nil {
		t.Error("unknown tool accepted")
	}
	if text, isErr, _ := callTool(t, a, "recent_audit", map[string]any{"usr": "x"}); !isErr || !strings.Contains(text, "unknown field") {
		t.Errorf("misspelt argument: %v %s", isErr, text)
	}
}

// The doctor of the server starts no servers and does not ask OPA or the
// gateway, which servers cannot reach.
func TestAdminDoctor(t *testing.T) {
	a, _ := testAdmin(t)
	text, isErr, sc := callTool(t, a, "doctor", map[string]any{})
	if isErr {
		t.Fatal(text)
	}
	for _, want := range []string{"configuration: ", "1 servers (sys)", "policy: servers cannot reach OPA", "servers: not started"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "gateway status") {
		t.Errorf("asked the gateway:\n%s", text)
	}
	if sc["results"] == nil {
		t.Error("no structured results")
	}
	if text, isErr, _ := callTool(t, a, "doctor", map[string]any{"since": "-1h"}); !isErr {
		t.Errorf("negative since: %s", text)
	}
	text, _, _ = callTool(t, a, "check_config", map[string]any{})
	if !strings.Contains(text, "configuration: ") || !strings.Contains(text, "role data: ") || strings.Contains(text, "polkit") {
		t.Errorf("check_config:\n%s", text)
	}
}

func TestMaskSecrets(t *testing.T) {
	in := "env:\n  API_TOKEN: sec1\n  LEVEL: info\n  db_password: sec2\n  - client_secret: sec3\n\"private_key\": \"sec4\",\nkeys: [a]\ntoken_file:\n"
	out, n := maskSecrets(in)
	if n != 4 {
		t.Errorf("masked %d, want 4:\n%s", n, out)
	}
	for _, secret := range []string{"sec1", "sec2", "sec3", "sec4"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q not masked:\n%s", secret, out)
		}
	}
	for _, kept := range []string{"LEVEL: info", "keys: [a]", "token_file:"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q masked:\n%s", kept, out)
		}
	}
}

func TestReadConfig(t *testing.T) {
	a, dir := testAdmin(t)
	text, _, sc := callTool(t, a, "show_config", map[string]any{})
	files := sc["files"].([]string)
	if len(files) != 3 || !strings.Contains(text, filepath.Join(dir, "servers.d", "sys.yaml")) {
		t.Fatalf("files: %v", files)
	}
	text, isErr, _ := callTool(t, a, "show_config", map[string]any{"file": filepath.Join(dir, "servers.d", "sys.yaml")})
	if isErr || strings.Contains(text, "s3cret") || !strings.Contains(text, "API_TOKEN: <masked>") || !strings.Contains(text, "LEVEL: info") {
		t.Errorf("sys.yaml:\n%s", text)
	}
	for _, other := range []string{"/etc/shadow", filepath.Join(dir, "servers.d", "..", "..", "..", "etc", "shadow")} {
		if text, isErr, _ := callTool(t, a, "show_config", map[string]any{"file": other}); !isErr {
			t.Errorf("%s read: %s", other, text)
		}
	}
}

func TestRecentAudit(t *testing.T) {
	a, _ := testAdmin(t)
	var gotArgs []string
	a.journal = func(_ context.Context, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte(`starting
{"time":"t1","level":"INFO","msg":"mcp","audit":true,"sub":"alice","action":"tools.call","server":"fs","name":"read_file","effect":"allow"}
{"time":"t2","level":"INFO","msg":"mcp","audit":true,"sub":"bob","action":"tools.call","server":"fs","name":"delete_file","effect":"deny","reason":"denied by policy"}
{"time":"t3","level":"INFO","msg":"listening"}
{"time":"t4","level":"INFO","msg":"mcp","audit":true,"event":"approval","ok":true,"sub":"alice","server":"zypp"}
`), nil
	}
	text, isErr, sc := callTool(t, a, "recent_audit", map[string]any{})
	if isErr || len(sc["records"].([]map[string]any)) != 3 {
		t.Fatalf("all: %s", text)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "--unit mcp-gateway.service --since ") {
		t.Errorf("journalctl %v", gotArgs)
	}
	if !strings.Contains(text, "t2 sub=bob action=tools.call server=fs name=delete_file effect=deny reason=denied by policy") {
		t.Errorf("line:\n%s", text)
	}
	text, _, _ = callTool(t, a, "recent_audit", map[string]any{"effect": "deny"})
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, "bob") {
		t.Errorf("deny:\n%s", text)
	}
	text, _, _ = callTool(t, a, "recent_audit", map[string]any{"user": "alice", "limit": 1})
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, "t4") {
		t.Errorf("alice, limit 1:\n%s", text)
	}
	if text, isErr, _ := callTool(t, a, "recent_audit", map[string]any{"limit": 5000}); !isErr {
		t.Errorf("limit 5000: %s", text)
	}
}

// explain_decision evaluates the installed layout of the policy with opa
// (OPA=path, else opa on PATH).
func TestExplainDecision(t *testing.T) {
	opa := os.Getenv("OPA")
	if opa == "" {
		var err error
		if opa, err = exec.LookPath("opa"); err != nil {
			t.Skip("no opa")
		}
	}
	a, _ := testAdmin(t)
	a.opa = opa
	// The shipped policy as installed: the Rego files without tests.
	rego, _ := filepath.Glob("../../policy/mcp/*.rego")
	if err := os.MkdirAll(filepath.Join(a.shipped, "mcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range rego {
		if strings.HasSuffix(f, "_test.rego") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(a.shipped, "mcp", filepath.Base(f)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	me := currentUser(t)

	text, isErr, sc := callTool(t, a, "explain_decision", map[string]any{"user": me, "server": "sys", "name": "read_file"})
	if isErr || !strings.Contains(text, ": allow") || !strings.Contains(text, "roles: reader") || !strings.Contains(text, `"tool":"read_*"`) {
		t.Errorf("allowed:\n%s", text)
	}
	if sc["decision"] == nil {
		t.Error("no structured decision")
	}
	text, _, _ = callTool(t, a, "explain_decision", map[string]any{"user": me, "server": "sys", "name": "write_file"})
	if !strings.Contains(text, ": deny") || !strings.Contains(text, "matching permissions: none") {
		t.Errorf("denied:\n%s", text)
	}
	text, _, _ = callTool(t, a, "explain_decision", map[string]any{"user": me, "server": "nope", "name": "x"})
	if !strings.Contains(text, `no server "nope" is registered`) {
		t.Errorf("unknown server:\n%s", text)
	}
	if text, isErr, _ := callTool(t, a, "explain_decision", map[string]any{"user": "no-such-user-here", "server": "sys", "name": "x"}); !isErr {
		t.Errorf("unknown user: %s", text)
	}
	if text, isErr, _ := callTool(t, a, "explain_decision", map[string]any{"user": me, "server": "sys", "name": "x", "kind": "file"}); !isErr {
		t.Errorf("unknown kind: %s", text)
	}
}

// The definition the package installs runs this command as root in the
// sandbox (not privileged), in its own domain.
func TestAdminDefinition(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("..", "..", "packaging", "admin", "gateway-admin.yaml.in"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	def := strings.ReplaceAll(string(in), "@BINDIR@", "/usr/bin")
	if err := os.WriteFile(filepath.Join(dir, "gateway-admin.yaml"), []byte(def), 0o644); err != nil {
		t.Fatal(err)
	}
	backends, err := config.LoadBackends(dir, filepath.Join(dir, "none"))
	if err != nil {
		t.Fatal(err)
	}
	b := backends["gateway-admin"]
	if b == nil || b.RunAs != "root" || b.Privileged || b.Network || b.SELinuxType != "mcpsrv_admin_t" ||
		b.Sandbox.ProtectHome != "yes" || strings.Join(b.Command, " ") != "/usr/bin/mcp-gateway admin-server" {
		t.Fatalf("%+v", b)
	}
	if findCommand(b.Command[1]) == nil {
		t.Errorf("%s is not a command", b.Command[1])
	}
}

// No role of the default role data but admin allows a tool of
// gateway-admin without approval through a pattern meant for other
// servers (viewer allows read_* on every server).
func TestAdminToolsOutsideDefaultRoles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "policy", "mcp", "rbac", "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rbac struct {
		Roles map[string]struct {
			Permissions []struct {
				Server          string `json:"server"`
				Tool            string `json:"tool"`
				Effect          string `json:"effect"`
				RequireApproval bool   `json:"require_approval"`
			} `json:"permissions"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(data, &rbac); err != nil {
		t.Fatal(err)
	}
	for name, role := range rbac.Roles {
		if name == "admin" {
			continue
		}
		for _, p := range role.Permissions {
			if p.Tool == "" || p.Effect == "deny" || p.RequireApproval {
				continue
			}
			if ok, _ := path.Match(p.Server, "gateway-admin"); !ok {
				continue
			}
			for _, tool := range adminTools {
				if ok, _ := path.Match(p.Tool, tool["name"].(string)); ok {
					t.Errorf("role %s allows %s (server %q, tool %q)", name, tool["name"], p.Server, p.Tool)
				}
			}
		}
	}
}
