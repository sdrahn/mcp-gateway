package e2e

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDecisionLogShipping runs OPA as mcp-opa.service does, with the
// decision-logs.conf drop-in, against a collector: decisions arrive with
// the arguments masked and the gateway's decision ids.
func TestDecisionLogShipping(t *testing.T) {
	opaBinary(t)
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "secret-name.txt"), "hello")
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}

	var mu sync.Mutex
	var received []map[string]any
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/logs" {
			http.NotFound(w, r)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var batch []map[string]any
		if err := json.NewDecoder(zr).Decode(&batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, batch...)
		mu.Unlock()
	}))
	defer collector.Close()

	rbac := `{"roles": {"reader": {"permissions": [{"server": "fs", "tool": "read_*"}]}},
	  "bindings": {"groups": {}, "users": {"` + me.Username + `": ["reader"]}}}`
	e := setupWith(t, rbac, map[string]string{"fs": home}, "", func(tmp, opaSock string) []string {
		// The installed layout: the policy logic without the default role
		// data, and the configuration from decision-logs.yaml.example with
		// the collector's URL and short delays.
		vendor := filepath.Join(tmp, "vendor")
		modules, _ := filepath.Glob(filepath.Join("..", "policy", "mcp", "*.rego"))
		for _, m := range modules {
			b, err := os.ReadFile(m)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(vendor, "mcp", filepath.Base(m)), string(b))
		}
		example, err := os.ReadFile(filepath.Join("..", "packaging", "opa", "decision-logs.yaml.example"))
		if err != nil {
			t.Fatal(err)
		}
		config := strings.NewReplacer(
			"https://opa-logs.example.com", collector.URL,
			"min_delay_seconds: 10", "min_delay_seconds: 1",
			"max_delay_seconds: 30", "max_delay_seconds: 1",
		).Replace(string(example))
		configFile := filepath.Join(tmp, "opa-config.yaml")
		writeFile(t, configFile, config)
		env := unitEnv(t, filepath.Join("..", "packaging", "opa", "decision-logs.conf"),
			"/etc/mcp-gateway/opa-config.yaml", configFile)
		return unitArgs(t, filepath.Join("..", "systemd", "mcp-opa.service"), env,
			"/run/mcp-gateway/opa.sock", opaSock,
			"/usr/share/mcp-gateway/policy", vendor,
			"/etc/mcp-gateway/policy", filepath.Join(tmp, "data"))
	})

	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(nil)
	if text, isErr := toolResult(t, c.call(2, "read_file", map[string]any{"path": filepath.Join(home, "secret-name.txt")})); isErr {
		t.Fatalf("read_file: %s", text)
	}
	if _, isErr := toolResult(t, c.call(3, "write_file", map[string]any{"path": filepath.Join(home, "x"), "content": "x"})); !isErr {
		t.Fatal("write_file was allowed")
	}

	ids := regexp.MustCompile(`"decision_id":"([0-9a-f]{32})"`).FindAllStringSubmatch(e.gwLogs.String(), -1)
	if len(ids) < 2 {
		t.Fatalf("gateway audit records lack decision ids: %s", e.gwLogs.String())
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		mu.Lock()
		body, _ := json.Marshal(received)
		mu.Unlock()
		shipped := string(body)
		missing := ""
		for _, id := range ids {
			if !strings.Contains(shipped, id[1]) {
				missing = id[1]
			}
		}
		if missing == "" {
			if strings.Contains(shipped, "secret-name") || !strings.Contains(shipped, `"/input/args"`) {
				t.Fatalf("arguments not masked: %s", shipped)
			}
			if !strings.Contains(shipped, `"mcp/authz/decision"`) {
				t.Fatalf("no authorization decisions: %s", shipped)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("decision %s not shipped; received %s\nOPA: %s", missing, shipped, e.opaLogs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
