package e2e

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// renderRoles renders the role data below src to out, as
// mcp-policy-render.service does, and returns out.
func renderRoles(t *testing.T, src, out string) string {
	t.Helper()
	p, err := policydata.PlanRender(src, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Render(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRenderedRoleData runs OPA as mcp-opa.service does (its ExecStart=,
// --ignore rbac and the rendered role data) with data.yaml and data.json
// in the role data's directory, and mcp-policy-render between them: the
// YAML is in force and OPA never has both; a change to data.yaml is in
// force once rendered (OPA --watch); data.yaml that does not parse leaves
// the role data in force as it was.
func TestRenderedRoleData(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "hello.txt"), "hello yaml")
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	reader := "  reader:\n    permissions:\n      - {server: fs, tool: 'read_*'}\n"
	writer := "  writer:\n    permissions:\n      - {server: fs, tool: write_file}\n"
	// data.json binds the writer, data.yaml the reader: the YAML is in force.
	rbac := `{"roles": {"writer": {"permissions": [{"server": "fs", "tool": "write_file"}]}},
	  "bindings": {"users": {"` + me.Username + `": ["writer"]}}}`
	var yml, render, rendered string
	e := setupWith(t, rbac, map[string]string{"fs": home}, "", func(tmp, opaSock string) []string {
		vendor := filepath.Join(tmp, "vendor")
		modules, _ := filepath.Glob(filepath.Join("..", "policy", "mcp", "*.rego"))
		for _, m := range modules {
			if strings.HasSuffix(m, "_test.rego") {
				continue
			}
			b, err := os.ReadFile(m)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(vendor, "mcp", filepath.Base(m)), string(b))
		}
		yml = filepath.Join(tmp, "data", "rbac", "data.yaml")
		writeFile(t, yml, "# the YAML is in force\nroles:\n"+reader+"bindings:\n  users:\n    "+me.Username+": [reader]\n")
		render = build(t, filepath.Join(tmp, "bin"), "./cmd/mcp-policy-render")
		rendered = filepath.Join(tmp, "run", "rbac")
		renderWith(t, render, filepath.Join(tmp, "data", "rbac"), rendered, 0)
		return unitArgs(t, filepath.Join("..", "systemd", "mcp-opa.service"), nil,
			"/run/mcp-gateway/opa.sock", opaSock,
			"/usr/share/mcp-gateway/policy", vendor,
			"/etc/mcp-gateway/policy", filepath.Join(tmp, "data"),
			"/run/mcp-opa/rbac", rendered)
	})
	src := filepath.Dir(yml)

	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(nil)
	id := 1
	// Policy changes reach the client as list_changed notifications
	// between the answers: skipped.
	call := func(tool string, args map[string]any) (string, bool) {
		t.Helper()
		id++
		c.request(id, "tools/call", map[string]any{"name": tool, "arguments": args})
		for {
			if m := c.read(); m.Method == "" {
				return toolResult(t, m)
			}
		}
	}
	read := func() (string, bool) {
		return call("read_file", map[string]any{"path": filepath.Join(home, "hello.txt")})
	}
	write := func() (string, bool) {
		return call("write_file", map[string]any{"path": filepath.Join(home, "new.txt"), "content": "x"})
	}
	if text, isErr := read(); isErr || text != "hello yaml" {
		t.Fatalf("read with the YAML's role: %q %v", text, isErr)
	}
	if text, isErr := write(); !isErr || !strings.Contains(text, "no matching permission") {
		t.Fatalf("write with the ignored JSON's role: %q %v", text, isErr)
	}

	// A change to data.yaml, rendered: in force within seconds.
	writeFile(t, yml, "roles:\n"+reader+writer+"bindings:\n  users:\n    "+me.Username+": [reader, writer]\n")
	renderWith(t, render, src, rendered, 0)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, isErr := write(); !isErr {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the changed data.yaml is not in force")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// data.yaml that does not parse: not rendered, the role data stays.
	writeFile(t, yml, "roles:\n"+reader+"roles: {}\n")
	renderWith(t, render, src, rendered, 1)
	time.Sleep(time.Second)
	if text, isErr := write(); isErr {
		t.Fatalf("after broken data.yaml: %q", text)
	}
	if text, isErr := read(); isErr || text != "hello yaml" {
		t.Fatalf("after broken data.yaml, read: %q %v", text, isErr)
	}
}

// renderWith runs mcp-policy-render and checks its exit status.
func renderWith(t *testing.T, render, src, out string, want int) {
	t.Helper()
	cmd := exec.Command(render, "-source", src, "-out", out, "-shipped", "", "-default", "")
	b, err := cmd.CombinedOutput()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if rc != want {
		t.Fatalf("mcp-policy-render: exit status %d, want %d:\n%s", rc, want, b)
	}
}
