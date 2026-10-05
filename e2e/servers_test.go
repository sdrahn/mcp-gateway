package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// modernServer is a test server built with an official SDK that speaks
// only MCP 2026-07-28 (test/servers): the command that runs it, over
// stdio or, with httpFlag and an address, Streamable HTTP at /mcp.
type modernServer struct {
	sdk     string
	command []string
}

// modernServers returns the servers $MCPGW_SERVERS names (go, py, ts).
func modernServers(t *testing.T, bin string) []modernServer {
	t.Helper()
	repo, _ := filepath.Abs("..")
	var out []modernServer
	for _, sdk := range strings.Split(os.Getenv("MCPGW_SERVERS"), ",") {
		switch sdk {
		case "go":
			exe := filepath.Join(bin, "go-sdk-server")
			cmd := exec.Command("go", "build", "-o", exe, ".")
			cmd.Dir = filepath.Join(repo, "test", "servers", "go")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("building the Go SDK server: %v\n%s", err, b)
			}
			out = append(out, modernServer{"go", []string{exe}})
		case "py":
			python := os.Getenv("MCPGW_PYTHON")
			if python == "" {
				python = "python3"
			}
			out = append(out, modernServer{"py", []string{python, filepath.Join(repo, "test", "servers", "py", "server.py")}})
		case "ts":
			out = append(out, modernServer{"ts", []string{"node", filepath.Join(repo, "test", "servers", "ts", "server.mjs")}})
		default:
			t.Fatalf("MCPGW_SERVERS: unknown server %q", sdk)
		}
		// A definition's command starts with an absolute path.
		s := &out[len(out)-1]
		exe, err := exec.LookPath(s.command[0])
		if err != nil {
			t.Fatal(err)
		}
		s.command[0], _ = filepath.Abs(exe)
	}
	return out
}

// waitTCP waits until something listens on addr.
func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listens on %s", addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Servers of MCP 2026-07-28 built with the official SDKs, run by the
// gateway over stdio and reached over Streamable HTTP through the
// connector, serve a legacy client: calls, a form the server asks for
// with a multi round-trip result, and a parameter the server mirrors
// into a header (x-mcp-header). Each server's tool protocol says which
// version the request was of.
func TestModernServers(t *testing.T) {
	if os.Getenv("MCPGW_SERVERS") == "" {
		t.Skip("MCPGW_SERVERS names the SDK servers to test (go,py,ts)")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	rbac := fmt.Sprintf(`{
	  "roles": {"tester": {"permissions": [{"server": "*", "tool": "*"}, {"server": "*", "client": "elicitation/create"}]}},
	  "bindings": {"groups": {}, "users": {%q: ["tester"]}}
	}`, me.Username)
	e := setup(t, rbac, nil, "")
	build(t, filepath.Join(e.tmp, "libexec", "mcp-gateway"), "./cmd/mcp-http-connector")

	var names []string
	for _, s := range modernServers(t, filepath.Join(e.tmp, "bin")) {
		cmd, _ := json.Marshal(s.command)
		writeFile(t, filepath.Join(e.tmp, "servers.d", s.sdk+"-stdio.yaml"),
			fmt.Sprintf("name: %s-stdio\ncommand: %s\nrun_as: gateway\n", s.sdk, cmd))
		addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		srv, logs := start(t, s.command[0], append(s.command[1:], "--http", addr)...)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("%s server (HTTP):\n%s", s.sdk, logs.String())
			}
			_ = srv.Process.Kill()
		})
		waitTCP(t, addr)
		writeFile(t, filepath.Join(e.tmp, "servers.d", s.sdk+"-http.yaml"),
			fmt.Sprintf("name: %s-http\nurl: http://%s/mcp\n", s.sdk, addr))
		names = append(names, s.sdk+"-stdio", s.sdk+"-http")
	}

	// The definitions were added while the gateway runs: it loads them.
	ctl := controlClient(e.ctlSock)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var servers []struct{ Name string }
		controlDo(t, ctl, "GET", "/v1/servers", "", &servers)
		if len(servers) == len(names) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("servers not loaded (%d of %d):\n%s", len(servers), len(names), e.gwLogs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					t.Logf("gateway:\n%s", e.gwLogs.String())
				}
			}()
			sdk, _, _ := strings.Cut(name, "-")
			c := newClient(t, e.connect, e.gwSock, name)
			c.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})

			c.request(2, "tools/list", map[string]any{})
			if got := listNames(t, readResponse(t, c, 2), "tools", "name"); !sameSet(got, "echo,protocol,ask_name,region") {
				t.Fatalf("tools: %s", got)
			}

			c.request(3, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{"text": "hi"}})
			if text, isErr := toolResult(t, readResponse(t, c, 3)); isErr || text != sdk+" echo: hi" {
				t.Fatalf("echo: %q %v", text, isErr)
			}

			// The server saw a request of MCP 2026-07-28.
			c.request(9, "tools/call", map[string]any{"name": "protocol", "arguments": map[string]any{}})
			if text, isErr := toolResult(t, readResponse(t, c, 9)); isErr || text != "2026-07-28" {
				t.Fatalf("protocol: %q %v", text, isErr)
			}

			// The server asks for a name with its result; the gateway asks
			// the client and calls again with the answer.
			c.request(4, "tools/call", map[string]any{"name": "ask_name", "arguments": map[string]any{}})
			ask := c.read()
			if ask.Method != "elicitation/create" || !strings.Contains(string(ask.Params), "Your name?") {
				t.Fatalf("want the server's form, got %+v", ask)
			}
			c.send(map[string]any{"jsonrpc": "2.0", "id": ask.ID, "result": map[string]any{
				"action": "accept", "content": map[string]any{"name": "Alice"}}})
			if text, isErr := toolResult(t, readResponse(t, c, 4)); isErr || text != sdk+": hello Alice" {
				t.Fatalf("ask_name: %q %v", text, isErr)
			}

			// region is mirrored into Mcp-Param-Region over HTTP, Base64
			// encoded when it is not plain ASCII; the server checks it.
			for i, region := range []string{"eu-west 1", "zürich"} {
				c.request(5+i, "tools/call", map[string]any{"name": "region", "arguments": map[string]any{"region": region, "query": "q"}})
				if text, isErr := toolResult(t, readResponse(t, c, 5+i)); isErr || text != sdk+" region "+region+": q" {
					t.Fatalf("region %q: %q %v", region, text, isErr)
				}
			}
		})
	}
}

// sameSet reports whether the comma-separated lists a and b have the same
// elements.
func sameSet(a, b string) bool {
	as, bs := strings.Split(a, ","), strings.Split(b, ",")
	if len(as) != len(bs) {
		return false
	}
	seen := map[string]int{}
	for _, s := range as {
		seen[s]++
	}
	for _, s := range bs {
		if seen[s]--; seen[s] < 0 {
			return false
		}
	}
	return true
}
