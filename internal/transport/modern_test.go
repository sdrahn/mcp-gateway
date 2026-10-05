package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// modernServe answers modern requests: "notify" sends progress first,
// "slow" waits until the client goes away (cancel), "missing" answers
// method not found, others echo the endpoint, principal and the
// Mcp-Param-Region header.
type modernServe struct {
	mu        sync.Mutex
	cancelled bool
}

func (f *modernServe) serve(ctx context.Context, out jsonrpc.MessageConn, p principal.Principal, server string, m *jsonrpc.Message, h http.Header) {
	switch m.Method {
	case "notify":
		n, _ := jsonrpc.NewNotification("notifications/progress", map[string]any{"progress": 1})
		_ = jsonrpc.WriteRelated(out, n, m.ID)
	case "subscriptions/listen":
		n, _ := jsonrpc.NewNotification("notifications/subscriptions/acknowledged", map[string]any{"notifications": map[string]any{}})
		_ = out.Write(n)
		<-ctx.Done()
		f.mu.Lock()
		f.cancelled = true
		f.mu.Unlock()
		return
	case "slow":
		<-ctx.Done()
		f.mu.Lock()
		f.cancelled = true
		f.mu.Unlock()
		return
	case "missing":
		_ = out.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not found"))
		return
	}
	r, _ := jsonrpc.NewResult(m.ID, map[string]any{"server": server, "sub": p.Sub, "session": p.SessionID, "region": h.Get("Mcp-Param-Region")})
	_ = out.Write(r)
}

const modernMetaJSON = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

func modernPost(t *testing.T, url, method, params string, hdr map[string]string) *http.Response {
	t.Helper()
	return modernPostAs(t, "alice", url, method, params, hdr)
}

func modernPostAs(t *testing.T, token, url, method, params string, hdr map[string]string) *http.Response {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params + modernMetaJSON + `}}`
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// A modern request needs no session: it is answered on its own POST, as
// JSON, with no Mcp-Session-Id; progress first makes it an SSE stream.
func TestModernRequest(t *testing.T) {
	f := &modernServe{}
	srv, _ := newTestServer(t, func(c *HTTPConfig) { c.Request = f.serve })

	resp := modernPost(t, srv.URL+"/mcp/fs", "tools/call", `"name":"read","arguments":{"region":"zürich"},`,
		map[string]string{"Mcp-Name": "read", "Mcp-Param-Region": "=?base64?esO8cmljaA==?="})
	body := readAll(t, resp)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get(sessionHeader) != "" ||
		!strings.Contains(body, `"server":"fs"`) || !strings.Contains(body, `"sub":"alice"`) || !strings.Contains(body, `"region":"=?base64?esO8cmljaA==?="`) {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}

	resp = modernPost(t, srv.URL+"/mcp", "notify", "", nil)
	body = readAll(t, resp)
	if resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("X-Accel-Buffering") != "no" ||
		strings.Index(body, "notifications/progress") > strings.Index(body, `"id":1`) || !strings.Contains(body, `"server":"all"`) {
		t.Fatalf("%v %s", resp.Header, body)
	}

	resp = modernPost(t, srv.URL+"/mcp", "missing", "", nil)
	if body := readAll(t, resp); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "-32601") {
		t.Fatalf("unknown method: %d %s", resp.StatusCode, body)
	}
}

// The required headers are checked against the body first.
func TestModernHeaders(t *testing.T) {
	f := &modernServe{}
	srv, _ := newTestServer(t, func(c *HTTPConfig) { c.Request = f.serve })
	for name, hdr := range map[string]map[string]string{
		"version header missing": {"MCP-Protocol-Version": ""},
		"method mismatch":        {"Mcp-Method": "tools/list"},
		"name missing":           {},
		"name mismatch":          {"Mcp-Name": "write"},
		"bad base64":             {"Mcp-Name": "=?base64?!!?="},
	} {
		resp := modernPost(t, srv.URL+"/mcp", "tools/call", `"name":"read",`, hdr)
		if body := readAll(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "-32020") {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	// A name in the Base64 sentinel form matches.
	resp := modernPost(t, srv.URL+"/mcp", "tools/call", `"name":"grüße",`, map[string]string{"Mcp-Name": "=?base64?Z3LDvMOfZQ==?="})
	if body := readAll(t, resp); resp.StatusCode != 200 {
		t.Fatalf("sentinel name: %d %s", resp.StatusCode, body)
	}
}

// An unsupported version names those the gateway speaks; missing
// capabilities are invalid params; both 400.
func TestModernVersionAndMeta(t *testing.T) {
	f := &modernServe{}
	srv, _ := newTestServer(t, func(c *HTTPConfig) { c.Request = f.serve })
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2027-03-01","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2027-03-01")
	req.Header.Set("Mcp-Method", "tools/list")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var m jsonrpc.Message
	_ = json.Unmarshal([]byte(readAll(t, resp)), &m)
	if resp.StatusCode != 400 || m.Error == nil || m.Error.Code != -32022 || !strings.Contains(string(m.Error.Data), `"2025-11-25"`) {
		t.Fatalf("%d %+v", resp.StatusCode, m.Error)
	}

	body = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/list")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := readAll(t, resp); resp.StatusCode != 400 || !strings.Contains(b, "-32602") {
		t.Fatalf("no capabilities: %d %s", resp.StatusCode, b)
	}
}

// Closing the response cancels the request.
func TestModernCancel(t *testing.T) {
	f := &modernServe{}
	srv, _ := newTestServer(t, func(c *HTTPConfig) { c.Request = f.serve })
	ctx, cancel := context.WithCancel(context.Background())
	body := `{"jsonrpc":"2.0","id":1,"method":"slow","params":{` + modernMetaJSON + `}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "slow")
	done := make(chan struct{})
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		c := f.cancelled
		f.mu.Unlock()
		if c {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("not cancelled")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Without Request, a modern request is served as before: without a
// session it is refused in a way that makes the agent fall back to
// initialize (no JSON-RPC error a modern client would act on).
func TestModernOff(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := modernPost(t, srv.URL+"/mcp", "server/discover", "", nil)
	if body := readAll(t, resp); resp.StatusCode != 400 || strings.Contains(body, "jsonrpc") {
		t.Fatalf("without Request: %d %s", resp.StatusCode, body)
	}
}

// subscriptions/listen is a stream: it needs SSE, and it ends when the
// token is no longer accepted.
func TestModernListen(t *testing.T) {
	f := &modernServe{}
	expired := make(chan struct{}, 1)
	srv, _ := newTestServer(t, func(c *HTTPConfig) {
		c.Request = f.serve
		c.TokenExpired = func(principal.Principal) { expired <- struct{}{} }
	})
	resp := modernPost(t, srv.URL+"/mcp", "subscriptions/listen", "", map[string]string{"Accept": "application/json"})
	if body := readAll(t, resp); resp.StatusCode != 400 || !strings.Contains(body, "text/event-stream") {
		t.Fatalf("without SSE: %d %s", resp.StatusCode, body)
	}
	start := time.Now()
	resp = modernPostAs(t, "alice-brief", srv.URL+"/mcp", "subscriptions/listen", `"notifications":{"toolsListChanged":true},`, nil)
	body := readAll(t, resp)
	if resp.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(body, "subscriptions/acknowledged") {
		t.Fatalf("%v %s", resp.Header, body)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the stream outlived the token by %v", d)
	}
	select {
	case <-expired:
	case <-time.After(2 * time.Second):
		t.Fatal("TokenExpired not called")
	}
}
