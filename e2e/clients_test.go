package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A compatClient is an MCP client library driven by a program in
// test/clients that implements the scenarios of TestClients.
type compatClient struct {
	name string
	cmd  []string
	env  func(caFile string) []string // extra environment, e.g. to trust the gateway's certificate
}

// compatClients returns the client programs named in $MCPGW_CLIENTS
// (comma-separated: ts, py, go), set up as test/clients/README.md
// describes; the test fails if one cannot run.
func compatClients(t *testing.T, bin string) []compatClient {
	t.Helper()
	required := map[string]bool{}
	for _, n := range strings.Split(os.Getenv("MCPGW_CLIENTS"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			required[n] = true
		}
	}
	var out []compatClient
	missing := func(name, why string) { t.Fatalf("client %s: %s", name, why) }

	ts, _ := filepath.Abs(filepath.Join("..", "test", "clients", "ts"))
	if !required["ts"] {
		// not asked for
	} else if node, err := exec.LookPath("node"); err != nil {
		missing("ts", "node not found")
	} else if _, err := os.Stat(filepath.Join(ts, "node_modules")); err != nil {
		missing("ts", "run npm ci in test/clients/ts")
	} else {
		out = append(out, compatClient{"ts", []string{node, filepath.Join(ts, "client.mjs")},
			func(ca string) []string { return []string{"NODE_EXTRA_CA_CERTS=" + ca} }})
	}

	py, _ := filepath.Abs(filepath.Join("..", "test", "clients", "py"))
	python := os.Getenv("MCPGW_PYTHON")
	if python == "" {
		python = "python3"
	}
	if !required["py"] {
		// not asked for
	} else if b, err := exec.Command(python, "-c", "import mcp").CombinedOutput(); err != nil {
		missing("py", fmt.Sprintf("%s cannot import mcp (pip install -r test/clients/py/requirements.txt): %s", python, bytes.TrimSpace(b)))
	} else {
		out = append(out, compatClient{"py", []string{python, filepath.Join(py, "client.py")},
			func(ca string) []string { return []string{"SSL_CERT_FILE=" + ca} }})
	}

	if required["go"] {
		goClient := filepath.Join(bin, "compat-go")
		build := exec.Command("go", "build", "-o", goClient, ".")
		build.Dir = filepath.Join("..", "test", "clients", "go")
		if b, err := build.CombinedOutput(); err != nil {
			missing("go", fmt.Sprintf("building test/clients/go: %v\n%s", err, b))
		}
		out = append(out, compatClient{"go", []string{goClient},
			func(ca string) []string { return []string{"MCPGW_CA=" + ca} }})
	}
	for name := range required {
		if name != "ts" && name != "py" && name != "go" {
			t.Fatalf("unknown client %q in MCPGW_CLIENTS", name)
		}
	}
	return out
}

// runClient runs one scenario and returns the JSON object the client
// prints last. When the client prints {"ready": true}, onReady runs (the
// client waits for what onReady does, such as a policy change).
func runClient(t *testing.T, c compatClient, scenario string, env []string, onReady func()) map[string]any {
	t.Helper()
	cmd := exec.Command(c.cmd[0], append(c.cmd[1:], scenario)...)
	cmd.Env = append(os.Environ(), env...)
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(90*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	var last map[string]any
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			t.Logf("%s: %s", c.name, sc.Text())
			continue
		}
		if m["ready"] == true {
			if onReady != nil {
				onReady()
			}
			continue
		}
		last = m
	}
	err = cmd.Wait()
	if last == nil || last["fatal"] != nil || err != nil {
		t.Fatalf("%s %s: %v\nresult: %v\nstderr:\n%s", c.name, scenario, err, last, stderr.String())
	}
	return last
}

// gatewayVersions are the MCP versions the gateway accepts from clients.
var gatewayVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true, "2025-11-25": true}

func strs(v any) string {
	l, _ := v.([]any)
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = fmt.Sprint(s)
	}
	return strings.Join(out, ",")
}

// opaPut replaces a document in OPA's data API (over its socket), as an
// administrator's edit of the role data would.
func opaPut(t *testing.T, sock, path, body string) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest(http.MethodPut, "http://opa/v1/data/"+path, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("PUT %s: %d", path, resp.StatusCode)
	}
}

// TestClients runs MCP client libraries, as agents use them, against the
// gateway over the local socket (mcp-connect) and over HTTPS: the
// official TypeScript and Python SDKs and mcp-go (which Kit uses). Each
// scenario checks behaviour an agent depends on: discovery and calls
// filtered by policy, approval out of band and through the client's
// dialog, list_changed after a policy change, and cancellation.
func TestClients(t *testing.T) {
	if os.Getenv("MCPGW_CLIENTS") == "" {
		t.Skip("set MCPGW_CLIENTS (ts,py,go) to run the client libraries; see test/clients/README.md")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-clients")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello clients")

	provider := newIdP(t)
	certFile, keyFile, _ := selfSigned(t, home)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)

	// fs: writes approved out of band; fsform: in the client's dialog.
	// The local user and the remote token subject hold the same role.
	inHome := "^" + regexp.QuoteMeta(home) + "/"
	rbac := func(extra string) string {
		return fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs*", "tool": "read_*"},
	    {"server": "fs*", "tool": "list_*"},
	    {"server": "fs*", "resource": "file://*"},
	    {"server": "fs*", "prompt": "*"},
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "oob", "args": {"path": %q}},
	    {"server": "fsform", "tool": "write_file", "require_approval": true, "approval_channel": "form", "args": {"path": %q}}%s
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"], "u-remote": ["developer"]}}
	}`, inHome, inHome, extra, me.Username)
	}
	e := setup(t, rbac(""), map[string]string{"fs": home, "fsform": home}, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
  scopes: [mcp]
`, port, certFile, keyFile, provider.srv.URL, audience))
	waitHTTPS(t, port)
	ctl := controlClient(e.ctlSock)
	opaSock := filepath.Join(e.tmp, "opa.sock")

	clients := compatClients(t, filepath.Join(e.tmp, "bin"))

	// pending waits for an approval of server/tool and returns its id.
	pending := func(t *testing.T, server string) string {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			var list []map[string]any
			controlDo(t, ctl, "GET", "/v1/approvals", "", &list)
			for _, p := range list {
				if p["server"] == server && p["name"] == "write_file" {
					return p["id"].(string)
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no pending approval for %s/write_file", server)
		return ""
	}

	for _, transport := range []string{"stdio", "http"} {
		for _, c := range clients {
			envFor := func(server string) []string {
				env := append(c.env(certFile), "MCPGW_TRANSPORT="+transport, "MCPGW_HOME="+home,
					"MCPGW_CONNECT="+e.connect, "MCPGW_SOCKET="+e.gwSock, "MCPGW_SERVER="+server, "MCPGW_TIMEOUT_MS=2500")
				if transport == "http" {
					env = append(env, "MCPGW_URL="+audience+"/"+server, "MCPGW_TOKEN="+provider.token(t, "u-remote", audience))
				}
				return env
			}
			t.Run(transport+"/"+c.name, func(t *testing.T) {
				t.Run("basic", func(t *testing.T) {
					r := runClient(t, c, "basic", envFor("fs"), nil)
					if r["server"] != "mcp-fs-demo" || strs(r["tools"]) != "list_dir,read_file,write_file" || r["read"] != "hello clients" {
						t.Fatalf("discovery or call: %v", r)
					}
					// Clients that try a newer protocol first (the Python SDK
					// probes server/discover of MCP 2026-07-28) must fall back
					// to one the gateway speaks.
					if v, ok := r["protocolVersion"]; ok && !gatewayVersions[fmt.Sprint(v)] {
						t.Fatalf("protocol version %v", v)
					}
					denied, _ := r["denied"].(map[string]any)
					if denied["isError"] != true && denied["error"] == nil {
						t.Fatalf("delete_file not refused: %v", r)
					}
					if !strings.Contains(strs(r["resources"]), "hello.txt") || r["resource"] != "hello clients" || strs(r["prompts"]) != "summarize_file" {
						t.Fatalf("resources or prompts: %v", r)
					}
				})

				t.Run("approval out of band", func(t *testing.T) {
					done := make(chan string, 1)
					go func() { done <- pending(t, "fs") }()
					approved := make(chan struct{})
					go func() {
						id := <-done
						// Longer than the client's request timeout
						// (MCPGW_TIMEOUT_MS): progress must keep the call alive.
						time.Sleep(4 * time.Second)
						controlDo(t, ctl, "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"once"}`, nil)
						close(approved)
					}()
					r := runClient(t, c, "approval", envFor("fs"), nil)
					<-approved
					if r["isError"] == true || !strings.HasPrefix(fmt.Sprint(r["text"]), "wrote") {
						t.Fatalf("approved write: %v", r)
					}
					if !strings.Contains(strs(r["logs"]), "Waiting for approval") {
						t.Errorf("no waiting notice: %v", r)
					}
					if n, _ := r["progress"].(float64); n < 3 {
						t.Errorf("progress notifications while waiting: %v", r["progress"])
					}
				})

				t.Run("approval in the client", func(t *testing.T) {
					r := runClient(t, c, "elicit", envFor("fsform"), nil)
					if r["isError"] == true || !strings.HasPrefix(fmt.Sprint(r["text"]), "wrote") || !strings.Contains(strs(r["asked"]), "write_file") {
						t.Fatalf("elicited write: %v", r)
					}
				})

				t.Run("list_changed", func(t *testing.T) {
					r := runClient(t, c, "listchanged", envFor("fs"), func() {
						opaPut(t, opaSock, "mcp/rbac", rbac(`,
	    {"server": "fs", "tool": "delete_file"}`))
					})
					opaPut(t, opaSock, "mcp/rbac", rbac(""))
					if r["notified"] != true || strs(r["after"]) != "delete_file,list_dir,read_file,write_file" {
						t.Fatalf("list_changed: %v", r)
					}
					// Let the gateway notice the change back before the next
					// client lists tools.
					time.Sleep(2 * time.Second)
				})

				t.Run("cancel", func(t *testing.T) {
					r := runClient(t, c, "cancel", envFor("fs"), func() {
						// The agent gave up: the request leaves the inbox.
						deadline := time.Now().Add(5 * time.Second)
						for {
							var list []map[string]any
							controlDo(t, ctl, "GET", "/v1/approvals", "", &list)
							if len(list) == 0 {
								return
							}
							if time.Now().After(deadline) {
								t.Errorf("approval still pending after cancel: %v", list)
								return
							}
							time.Sleep(100 * time.Millisecond)
						}
					})
					if r["cancelled"] != true {
						t.Fatalf("cancel: %v", r)
					}
					if _, err := os.Stat(filepath.Join(home, "cancelled.txt")); err == nil {
						t.Fatal("cancelled write happened")
					}
				})
			})
		}
	}
}

// waitHTTPS waits until the gateway accepts connections on port.
func waitHTTPS(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway HTTPS not up: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
