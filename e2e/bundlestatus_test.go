package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Roadmap step 45: OPA polls a bundle server (the shipped bundle-server
// drop-in and opa-config.yaml.example) and reports each bundle it
// activates to the gateway's policy.status_listen. With
// policy.watch_interval an hour, a new revision is noticed within
// seconds: only the report can tell the gateway.
func TestBundleStatusReported(t *testing.T) {
	opa := opaBinary(t)
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	keys := t.TempDir()
	key, pub := signingKey(t, keys)
	pubPEM, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	statusPort := freePort(t)

	// The bundle server serves the bundle at bundles/mcp-gateway.tar.gz
	// (the example configuration's resource), its revision as ETag.
	var served atomic.Pointer[[2]string] // path, revision
	bundles := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := served.Load()
		if cur == nil || r.URL.Path != "/bundles/mcp-gateway.tar.gz" {
			http.NotFound(w, r)
			return
		}
		etag := `"` + cur[1] + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		http.ServeFile(w, r, cur[0])
	}))
	t.Cleanup(bundles.Close)

	build := func(tmp, rev, rbac string) string {
		t.Helper()
		data := filepath.Join(tmp, "bundle-data-"+rev)
		writeFile(t, filepath.Join(data, "rbac", "data.yaml"), rbac)
		out := filepath.Join(tmp, "bundle-"+rev+".tar.gz")
		cmd := exec.Command("sh", filepath.Join("..", "tools", "mcp-policy-bundle"),
			"-k", key, "-r", rev, "-n", "-o", out, "-V", filepath.Join("..", "policy"), "-L", data)
		cmd.Env = append(os.Environ(), "OPA="+opa)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("mcp-policy-bundle: %v\n%s", err, b)
		}
		return out
	}
	rbac := func(tools string) string {
		return `{"roles": {"reader": {"permissions": [{"server": "fs", "tool": "` + tools + `"}]}},
		  "bindings": {"groups": {}, "users": {"` + me.Username + `": ["reader"]}}}`
	}
	var tmpDir string
	e := setupWith(t, rbac("read_*"), nil, "", func(tmp, opaSock string) []string {
		tmpDir = tmp
		served.Store(&[2]string{build(tmp, "e2e-1", rbac("read_*")), "e2e-1"})
		example, err := os.ReadFile(filepath.Join("..", "packaging", "opa", "opa-config.yaml.example"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := strings.NewReplacer(
			"https://bundles.example.com", bundles.URL,
			"http://127.0.0.1:9465", fmt.Sprintf("http://127.0.0.1:%d", statusPort),
			"min_delay_seconds: 60", "min_delay_seconds: 1",
			"max_delay_seconds: 120", "max_delay_seconds: 1",
			"      -----BEGIN PUBLIC KEY-----\n      ...\n      -----END PUBLIC KEY-----\n",
			"      "+strings.ReplaceAll(strings.TrimSpace(string(pubPEM)), "\n", "\n      ")+"\n",
		).Replace(string(example))
		if strings.Contains(cfg, "...") || !strings.Contains(cfg, "status:") {
			t.Fatalf("example configuration not as expected:\n%s", cfg)
		}
		cfgPath := filepath.Join(tmp, "opa-config.yaml")
		writeFile(t, cfgPath, cfg)
		return dropInArgs(t, filepath.Join("..", "packaging", "opa", "bundle-server.conf"),
			"/run/mcp-gateway/opa.sock", opaSock, "/etc/mcp-gateway/opa-config.yaml", cfgPath)
	})
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s\nopa:\n%s", e.gwLogs.String(), e.opaLogs.String())
		}
	}()

	// The gateway as configured for it: checks once an hour, and takes
	// OPA's reports.
	conf, err := os.ReadFile(e.gwConfig)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(string(conf), "  watch_interval: 1s\n",
		fmt.Sprintf("  watch_interval: 1h\n  status_listen: 127.0.0.1:%d\n", statusPort), 1)
	if next == string(conf) {
		t.Fatal("no watch_interval in the test configuration")
	}
	writeFile(t, e.gwConfig, next)
	e.restartGateway(t)
	sock := filepath.Join(tmpDir, "opa.sock")
	revision := func() string {
		var resp struct {
			Result map[string]struct {
				Manifest struct {
					Revision string `json:"revision"`
				} `json:"manifest"`
			} `json:"result"`
		}
		opaGet(t, sock, "/v1/data/system/bundles", &resp)
		return resp.Result["mcp"].Manifest.Revision
	}
	deadline := time.Now().Add(30 * time.Second)
	for revision() != "e2e-1" {
		if time.Now().After(deadline) {
			t.Fatal("OPA did not activate the first bundle")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The gateway's first check sees e2e-1; let it.
	time.Sleep(2 * time.Second)

	served.Store(&[2]string{build(tmpDir, "e2e-2", rbac("list_*")), "e2e-2"})
	deadline = time.Now().Add(20 * time.Second)
	for !strings.Contains(e.gwLogs.String(), `"event":"mcp-policy-change"`) || !strings.Contains(e.gwLogs.String(), "e2e-2") {
		if time.Now().After(deadline) {
			t.Fatalf("the new revision was not noticed (OPA has %q)", revision())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
