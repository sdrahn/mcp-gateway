package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// loggingServer is an MCP server that speaks Streamable HTTP and answers
// tools/call of "logged" on an event stream: once two calls are in
// flight, a log message with the call's tag, then the result.
func loggingServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	inFlight := 0
	both := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Arguments struct{ Tag string } `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(body, &m) != nil || len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		answer := func(res any) []byte {
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": res})
			return b
		}
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "logsrv")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(answer(map[string]any{"protocolVersion": "2025-06-18",
				"capabilities": map[string]any{"tools": map[string]any{}, "logging": map[string]any{}},
				"serverInfo":   map[string]any{"name": "logsrv"}}))
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(answer(map[string]any{"tools": []any{map[string]any{"name": "logged",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"tag": map[string]any{"type": "string"}}}}}}))
		case "tools/call":
			mu.Lock()
			inFlight++
			if inFlight == 2 {
				close(both)
			}
			mu.Unlock()
			select {
			case <-both:
			case <-time.After(10 * time.Second):
			}
			tag := m.Params.Arguments.Tag
			note, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/message",
				"params": map[string]any{"level": "info", "data": tag}})
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "data: %s\n\n", note)
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
			res := answer(map[string]any{"content": []any{map[string]any{"type": "text", "text": "logged " + tag}}})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", res)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(answer(map[string]any{}))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Roadmap step 44: a legacy agent over HTTPS with two calls in flight on
// an HTTP server gets each call's log message on that call's stream, as
// the server sent it, not both on one.
func TestHTTPStreamsKeepTheirMessages(t *testing.T) {
	dir, err := os.MkdirTemp("", "mcpgw-streams")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, dir)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)
	rbac := `{
	  "roles": {"logger": {"permissions": [{"server": "logsrv", "tool": "*"}]}},
	  "bindings": {"groups": {}, "users": {"u-streams": ["logger"]}}
	}`
	e := setup(t, rbac, nil, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
`, port, certFile, keyFile, provider.srv.URL, audience))
	build(t, filepath.Join(e.tmp, "libexec", "mcp-gateway"), "./cmd/mcp-http-connector")
	backend := loggingServer(t)
	writeFile(t, filepath.Join(e.tmp, "servers.d", "logsrv.yaml"), "name: logsrv\nurl: "+backend.URL+"/mcp\n")
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	c := &remote{t: t, client: client, url: audience + "/logsrv", token: provider.token(t, "u-streams", audience)}
	// The listener, and the definition added while the gateway runs.
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/.well-known/oauth-protected-resource/mcp", port))
		if err == nil {
			_ = resp.Body.Close()
			probe := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
				"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "streams-e2e"}}}, false)
			ok := probe.StatusCode == http.StatusOK
			if ok {
				c.session = probe.Header.Get("Mcp-Session-Id")
			}
			_ = probe.Body.Close()
			if ok && c.session != "" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session on logsrv: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	resp := c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false)
	_ = resp.Body.Close()
	if m := c.call(2, "logging/setLevel", map[string]any{"level": "debug"}); m.Error != nil {
		t.Fatalf("setLevel: %+v", m.Error)
	}

	// Both calls at once; each stream is read to its answer.
	streams := map[string][]msg{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, tag := range []string{"first", "second"} {
		wg.Add(1)
		go func(id int, tag string) {
			defer wg.Done()
			resp := c.post(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
				"params": map[string]any{"name": "logged", "arguments": map[string]any{"tag": tag}}}, true)
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				_ = resp.Body.Close()
				t.Errorf("%s: %s", tag, resp.Header.Get("Content-Type"))
				return
			}
			ch := sse(t, resp)
			deadline := time.After(20 * time.Second)
			for {
				select {
				case m, ok := <-ch:
					if !ok {
						return
					}
					mu.Lock()
					streams[tag] = append(streams[tag], m)
					mu.Unlock()
					if len(m.ID) > 0 && m.Method == "" {
						return
					}
				case <-deadline:
					t.Errorf("%s: no answer", tag)
					return
				}
			}
		}(10+i, tag)
	}
	wg.Wait()
	for _, tag := range []string{"first", "second"} {
		var logs []string
		answered := false
		for _, m := range streams[tag] {
			if m.Method == "notifications/message" {
				var p struct{ Data string }
				_ = json.Unmarshal(m.Params, &p)
				logs = append(logs, p.Data)
				if strings.Contains(string(m.Params), "relatedRequest") {
					t.Errorf("the connector's name reached the agent: %s", m.Params)
				}
			}
			if strings.Contains(string(m.Result), "logged "+tag) {
				answered = true
			}
		}
		if !answered || len(logs) != 1 || logs[0] != tag {
			t.Errorf("stream of %s: answered %v, log messages %q", tag, answered, logs)
		}
	}
}
