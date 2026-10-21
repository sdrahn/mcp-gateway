package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// fakeGateway answers GET /v1/status as the gateway would: it counts a
// reload whenever the configuration files changed since it last looked,
// reports a configuration that does not load, and keys bound to the
// start (socket_group) as needing a restart.
type fakeGateway struct {
	sock, base, dir string
	mu              sync.Mutex
	last            string
	reloads         int
	configErr       string
	started         *config.Gateway
	noReloads       bool // a gateway before 1.3
}

func newFakeGateway(t *testing.T, base string) *fakeGateway {
	t.Helper()
	root := t.TempDir()
	g := &fakeGateway{sock: filepath.Join(root, "control.sock"), base: base, dir: filepath.Join(root, "gateway.d")}
	if err := os.Mkdir(g.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	saved := []any{configBases, configDropInDir, reloadPoll}
	t.Cleanup(func() {
		configBases, configDropInDir, reloadPoll = saved[0].([]string), saved[1].(string), saved[2].(time.Duration)
	})
	configBases, configDropInDir, reloadPoll = []string{base}, g.dir, 10*time.Millisecond
	started, _, err := config.ResolveWith([]string{base}, g.dir)
	if err != nil {
		t.Fatal(err)
	}
	g.started, g.last = started, g.digest()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if d := g.digest(); d != g.last {
			g.last = d
			g.reloads++
			g.configErr = ""
			if next, _, err := config.ResolveWith([]string{base}, g.dir); err != nil {
				g.configErr = err.Error()
			} else {
				g.started.Limits = next.Limits // reloadable
			}
		}
		st := map[string]any{"version": "test", "config_error": g.configErr}
		if !g.noReloads {
			st["config_reloads"] = g.reloads
		}
		if next, _, err := config.ResolveWith([]string{base}, g.dir); err == nil && next.SocketGroup != g.started.SocketGroup {
			st["restart_needed"] = []string{"socket_group"}
		}
		_ = json.NewEncoder(w).Encode(st)
	})
	l, err := net.Listen("unix", g.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return g
}

// digest is the names and contents of the drop-ins.
func (g *fakeGateway) digest() string {
	var b strings.Builder
	paths, _ := config.DropIns(g.dir)
	for _, p := range paths {
		data, _ := os.ReadFile(p)
		b.WriteString(p + "\n" + string(data) + "\x00")
	}
	return b.String()
}

func (g *fakeGateway) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rc := run(append([]string{"config", "--socket", g.sock}, args...), &stdout, &stderr)
	return rc, stdout.String(), stderr.String()
}

func baseFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const configBase = "version: 1\nsocket_group: mcp-users\nlimits:\n  sessions_per_principal: 10\n"

func TestConfigSetGetUnset(t *testing.T) {
	base := baseFile(t, configBase)
	g := newFakeGateway(t, base)
	target := filepath.Join(g.dir, adminDropIn)

	rc, out, errs := g.run(t, "set", "limits.tasks_per_principal", "64")
	if rc != 0 || !strings.Contains(out, "limits.tasks_per_principal is in force") {
		t.Fatalf("set: rc %d\n%s%s", rc, out, errs)
	}
	data, _ := os.ReadFile(target)
	if !strings.HasPrefix(string(data), "# Written by mcp-gateway-admin config set") ||
		!strings.Contains(string(data), "limits:\n  tasks_per_principal: 64\n") {
		t.Fatalf("drop-in:\n%s", data)
	}
	if leftover, _ := filepath.Glob(filepath.Join(g.dir, ".*")); len(leftover) != 0 {
		t.Fatalf("left behind: %v", leftover)
	}

	// get names the drop-in and the line; a key of the base names the base;
	// a key no file sets is a default.
	rc, out, _ = g.run(t, "get", "limits.tasks_per_principal")
	if rc != 0 || out != "limits.tasks_per_principal: 64  # "+target+", line 5\n" {
		t.Fatalf("get: rc %d %q", rc, out)
	}
	rc, out, _ = g.run(t, "get", "limits.sessions_per_principal")
	if rc != 0 || out != "limits.sessions_per_principal: 10  # "+base+", line 4\n" {
		t.Fatalf("get: rc %d %q", rc, out)
	}
	rc, out, _ = g.run(t, "get", "approval_timeout")
	if rc != 0 || out != "approval_timeout: 2m0s  # default\n" {
		t.Fatalf("get default: rc %d %q", rc, out)
	}

	// The same value again changes nothing.
	if rc, out, _ = g.run(t, "set", "limits.tasks_per_principal", "64"); rc != 0 || !strings.Contains(out, "nothing to change") {
		t.Fatalf("set again: rc %d %q", rc, out)
	}

	// A second key goes into the same file; a key bound to the start says so.
	rc, out, errs = g.run(t, "set", "socket_group", "wheel")
	if rc != 0 || !strings.Contains(out, "socket_group takes effect at the next start") {
		t.Fatalf("set socket_group: rc %d\n%s%s", rc, out, errs)
	}
	if rc, out, _ = g.run(t, "get", "socket_group"); rc != 0 || !strings.HasSuffix(out, "; takes effect at the next start\n") {
		t.Fatalf("get socket_group: rc %d %q", rc, out)
	}

	// unset returns to the value below; the last key removes the file.
	if rc, out, errs = g.run(t, "unset", "socket_group"); rc != 0 || !strings.Contains(out, "socket_group is in force") {
		t.Fatalf("unset: rc %d\n%s%s", rc, out, errs)
	}
	if rc, out, _ = g.run(t, "get", "socket_group"); rc != 0 || !strings.HasPrefix(out, "socket_group: mcp-users  # "+base) {
		t.Fatalf("get after unset: %q", out)
	}
	if rc, out, _ = g.run(t, "unset", "socket_group"); rc != 0 || !strings.Contains(out, "nothing to unset") {
		t.Fatalf("unset again: rc %d %q", rc, out)
	}
	if rc, _, errs = g.run(t, "unset", "limits.tasks_per_principal"); rc != 0 {
		t.Fatalf("unset last: rc %d %s", rc, errs)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("drop-in still there: %v", err)
	}
}

// What the check refuses writes nothing.
func TestConfigSetRefused(t *testing.T) {
	g := newFakeGateway(t, baseFile(t, configBase))
	target := filepath.Join(g.dir, adminDropIn)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"set", "limits.task_per_principal", "1"}, "no such key in gateway.yaml"},
		{[]string{"set", "limits", "{}"}, "limits is a section"},
		{[]string{"set", "socket_group.x", "1"}, "socket_group is a key, not a section"},
		{[]string{"set", "limits.tasks_per_principal", "many"}, "not changed: " + target},
		{[]string{"set", "policy.timeout", "--", "-1s"}, "policy.timeout: must not be negative"},
		{[]string{"set", "limits.tasks_per_principal", "[1"}, "not YAML"},
		{[]string{"get", "limits"}, "limits is a section"},
	} {
		rc, _, errs := g.run(t, tc.args...)
		if rc != exitRefused || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: rc %d %q, want %q", tc.args, rc, errs, tc.want)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%v: wrote %s", tc.args, target)
		}
	}
	if leftover, _ := filepath.Glob(filepath.Join(g.dir, ".*")); len(leftover) != 0 {
		t.Fatalf("left behind: %v", leftover)
	}
	// A later drop-in that sets the key would win: refused.
	later := filepath.Join(g.dir, "90-site.yaml")
	if err := os.WriteFile(later, []byte("limits:\n  tasks_per_principal: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, _, errs := g.run(t, "set", "limits.tasks_per_principal", "64")
	if rc != exitRefused || !strings.Contains(errs, later+" sets limits.tasks_per_principal too (line 2)") {
		t.Fatalf("shadowed: rc %d %q", rc, errs)
	}
	// Another key of the same section is fine: sections merge.
	if rc, _, errs = g.run(t, "set", "limits.instances", "3"); rc != 0 {
		t.Fatalf("other key: rc %d %s", rc, errs)
	}
}

// Comments in the drop-in stay; values are YAML.
func TestConfigSetKeepsComments(t *testing.T) {
	g := newFakeGateway(t, baseFile(t, configBase))
	target := filepath.Join(g.dir, adminDropIn)
	if err := os.WriteFile(target, []byte("# mine\nlimits:\n  instances: 3 # three\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc, _, errs := g.run(t, "set", "agents.no_request_timeout", "[kit, other]"); rc != 0 {
		t.Fatalf("rc %d %s", rc, errs)
	}
	if rc, _, errs := g.run(t, "set", "limits.instances", "4"); rc != 0 {
		t.Fatalf("rc %d %s", rc, errs)
	}
	data, _ := os.ReadFile(target)
	for _, want := range []string{"# mine\n", "instances: 4 # three\n", "no_request_timeout: [kit, other]"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("drop-in lacks %q:\n%s", want, data)
		}
	}
	if rc, out, _ := g.run(t, "get", "agents.no_request_timeout"); rc != 0 || !strings.HasPrefix(out, "agents.no_request_timeout: [kit, other]  # ") {
		t.Fatalf("get: %q", out)
	}
}

func TestConfigShow(t *testing.T) {
	g := newFakeGateway(t, baseFile(t, configBase))
	rc, out, errs := g.run(t, "show")
	if rc != 0 {
		t.Fatalf("rc %d %s", rc, errs)
	}
	if lines := strings.Count(out, "\n"); lines != len(config.Keys()) {
		t.Errorf("%d lines for %d keys", lines, len(config.Keys()))
	}
	if !strings.Contains(out, "\nlimits.sessions_per_principal: 10  # ") || !strings.Contains(out, "\nlimits.instances: 0  # default\n") {
		t.Errorf("show:\n%s", out)
	}
	rc, out, _ = g.run(t, "show", "--json")
	var list []setting
	if rc != 0 || json.Unmarshal([]byte(out), &list) != nil || len(list) != len(config.Keys()) {
		t.Fatalf("json: rc %d %q", rc, out)
	}
	for _, s := range list {
		if s.Key == "limits.sessions_per_principal" && (s.Value != "10" || s.From == nil || s.From.Line != 4) {
			t.Errorf("json entry %+v", s)
		}
	}
}

// Without a gateway the file is written all the same: exit status 3. A
// gateway that does not count reloads gets the file without a wait.
func TestConfigSetWithoutGateway(t *testing.T) {
	g := newFakeGateway(t, baseFile(t, configBase))
	var stdout, stderr bytes.Buffer
	rc := run([]string{"config", "set", "limits.instances", "2", "--socket", filepath.Join(t.TempDir(), "none.sock")}, &stdout, &stderr)
	if rc != exitUnreachable || !strings.Contains(stderr.String(), "written; the gateway reads it when it runs") {
		t.Fatalf("rc %d %q", rc, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(g.dir, adminDropIn)); err != nil {
		t.Fatal(err)
	}
	g.noReloads = true
	rc, out, _ := g.run(t, "set", "limits.instances", "3")
	if rc != 0 || !strings.Contains(out, "does not report its reloads") {
		t.Fatalf("old gateway: rc %d %q", rc, out)
	}
}

func TestConfigUsage(t *testing.T) {
	g := newFakeGateway(t, baseFile(t, configBase))
	for _, args := range [][]string{{}, {"get"}, {"set", "a"}, {"unset"}, {"show", "x"}, {"frob", "x"}} {
		if rc, _, _ := g.run(t, args...); rc != exitUsage {
			t.Errorf("%v: rc %d", args, rc)
		}
	}
}
