package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// meta is the gateway's per-request metadata for MCP 2026-07-28.
const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"mcp-gateway","version":"t"},"io.modelcontextprotocol/clientCapabilities":{}}`

// modernServer is a Streamable HTTP server of MCP 2026-07-28 for the
// tests: no session, no GET stream, headers checked against the body.
type modernServer struct {
	t         *testing.T
	mu        sync.Mutex
	posts     []http.Header // by request
	methods   []string
	other     []string // what the connector should not send
	annotated bool     // query's region is mirrored into a header
	cancelled chan struct{}
}

func (f *modernServer) seen() ([]string, []http.Header, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...), append([]http.Header(nil), f.posts...), append([]string(nil), f.other...)
}

func (f *modernServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if r.Method != http.MethodPost {
		f.other = append(f.other, r.Method)
	}
	if r.Header.Get("Mcp-Session-Id") != "" {
		f.other = append(f.other, "Mcp-Session-Id")
	}
	f.mu.Unlock()
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string `json:"name"`
			URI       string `json:"uri"`
			Cursor    string `json:"cursor"`
			Arguments struct {
				Region *string `json:"region"`
			} `json:"arguments"`
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &m)
	f.mu.Lock()
	f.posts = append(f.posts, r.Header.Clone())
	f.methods = append(f.methods, m.Method)
	annotated := f.annotated
	f.mu.Unlock()
	fail := func(code int, msg string, data string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if data == "" {
			data = "null"
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q,"data":%s}}`, m.ID, code, msg, data)
	}
	version := string(m.Params.Meta[metaProtocolVersion])
	switch {
	case version != `"2026-07-28"`:
		fail(-32022, "Unsupported protocol version", `{"supported":["2026-07-28"],"requested":`+version+`}`)
		return
	case r.Header.Get("MCP-Protocol-Version") != "2026-07-28" || r.Header.Get("Mcp-Method") != m.Method:
		fail(codeHeaderMismatch, "Header mismatch: version or method", "")
		return
	}
	answer := func(result string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, m.ID, result)
	}
	switch m.Method {
	case "server/discover":
		answer(`{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}}}`)
	case "tools/list":
		// Two pages: the second has tools whose annotations are invalid.
		if m.Params.Cursor == "" {
			region := `{"type":"string"}`
			if annotated {
				region = `{"type":"string","x-mcp-header":"Region"}`
			}
			answer(`{"tools":[{"name":"query","inputSchema":{"type":"object","properties":{"region":` + region +
				`,"opts":{"type":"object","properties":{"limit":{"type":"integer","x-mcp-header":"Limit"},"dry":{"type":"boolean","x-mcp-header":"Dry-Run"}}}}}},` +
				`{"name":"wait","inputSchema":{"type":"object"}}],"nextCursor":"2"}`)
			return
		}
		answer(`{"tools":[{"name":"bad","inputSchema":{"type":"object","properties":{"list":{"type":"array","items":{"type":"string","x-mcp-header":"Item"}}}}},` +
			`{"name":"dup","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"string","x-mcp-header":"x"}}}},` +
			`{"name":"float","inputSchema":{"type":"object","properties":{"n":{"type":"number","x-mcp-header":"N"}}}},` +
			`{"name":"plain","inputSchema":{"type":"object","properties":{"s":{"type":"string"}}}}]}`)
	case "tools/call":
		if r.Header.Get("Mcp-Name") != m.Params.Name {
			fail(codeHeaderMismatch, "Header mismatch: Mcp-Name", "")
			return
		}
		if m.Params.Name == "wait" {
			// Progress, then nothing until the stream closes.
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"p\",\"progress\":1}}\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(f.cancelled)
			return
		}
		if annotated && m.Params.Arguments.Region != nil && r.Header.Get("Mcp-Param-Region") != *m.Params.Arguments.Region {
			fail(codeHeaderMismatch, "Header mismatch: Mcp-Param-Region", "")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"resultType\":\"complete\",\"content\":[]}}\n\n", m.ID)
	default:
		answer(`{"resultType":"complete"}`)
	}
}

func newModernServer(t *testing.T) (*modernServer, *httptest.Server) {
	f := &modernServer{t: t, annotated: true, cancelled: make(chan struct{})}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// A modern server gets the request metadata headers and no session; the
// parameters a tool marks with x-mcp-header go into Mcp-Param headers,
// and tools with invalid annotations are left out of tools/list.
func TestModernConnector(t *testing.T) {
	f, srv := newModernServer(t)
	in, out, wait := pipe(t, srv, nil, "")

	send(t, in, `{"jsonrpc":"2.0","id":"probe-1","method":"server/discover","params":{`+meta+`}}`)
	if l := next(t, out); !strings.Contains(l, `"id":"probe-1"`) || !strings.Contains(l, `"supportedVersions":["2026-07-28"]`) {
		t.Fatalf("discover: %s", l)
	}
	// A call before the tools were listed: the connector lists them for
	// their headers.
	send(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"region":"eu west","opts":{"limit":5,"dry":false},"text":"x"},`+meta+`}}`)
	if l := next(t, out); l != `{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}` {
		t.Fatalf("call: %s", l)
	}
	send(t, in, `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"2",`+meta+`}}`)
	if l := next(t, out); l != `{"id":3,"jsonrpc":"2.0","result":{"tools":[{"name":"plain","inputSchema":{"type":"object","properties":{"s":{"type":"string"}}}}]}}` {
		t.Fatalf("tools/list: %s", l)
	}
	send(t, in, `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"grüße",`+meta+`}}`)
	next(t, out)
	send(t, in, `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///a b.txt",`+meta+`}}`)
	next(t, out)

	methods, posts, other := f.seen()
	if got := strings.Join(methods, " "); got != "server/discover tools/list tools/list tools/call tools/list prompts/get resources/read" {
		t.Fatalf("requests %s", got)
	}
	for i, h := range posts {
		if h.Get("MCP-Protocol-Version") != "2026-07-28" || h.Get("Mcp-Method") != methods[i] {
			t.Errorf("%s: headers %v", methods[i], h)
		}
	}
	if h := posts[0]; h.Get("Mcp-Name") != "" {
		t.Errorf("discover: Mcp-Name %q", h.Get("Mcp-Name"))
	}
	call := posts[3]
	if call.Get("Mcp-Name") != "query" || call.Get("Mcp-Param-Region") != "eu west" || call.Get("Mcp-Param-Limit") != "5" || call.Get("Mcp-Param-Dry-Run") != "false" {
		t.Errorf("tools/call: headers %v", call)
	}
	if got, want := posts[5].Get("Mcp-Name"), "=?base64?"+base64.StdEncoding.EncodeToString([]byte("grüße"))+"?="; got != want {
		t.Errorf("prompts/get: Mcp-Name %q, want %q", got, want)
	}
	if got := posts[6].Get("Mcp-Name"); got != "file:///a b.txt" {
		t.Errorf("resources/read: Mcp-Name %q", got)
	}
	if len(other) > 0 {
		t.Errorf("not of MCP 2026-07-28: %v", other)
	}
	_ = in.Close()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
}

// What a modern server answers with an HTTP error status reaches the
// gateway as its JSON-RPC error, for the gateway's probe to tell the
// versions.
func TestModernConnectorErrors(t *testing.T) {
	_, srv := newModernServer(t)
	in, out, wait := pipe(t, srv, nil, "")
	later := strings.Replace(meta, "2026-07-28", "2027-03-01", 1)
	send(t, in, `{"jsonrpc":"2.0","id":"probe-1","method":"server/discover","params":{`+later+`}}`)
	l := next(t, out)
	var m struct {
		ID    string `json:"id"`
		Error struct {
			Code int             `json:"code"`
			Data json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(l), &m); err != nil || m.ID != "probe-1" || m.Error.Code != -32022 || !strings.Contains(string(m.Error.Data), `"supported":["2026-07-28"]`) {
		t.Fatalf("got %s", l)
	}
	_ = in.Close()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
}

// The gateway's notifications/cancelled closes the request's stream,
// which is the cancellation for a modern server; no answer follows.
func TestModernConnectorCancel(t *testing.T) {
	f, srv := newModernServer(t)
	in, out, wait := pipe(t, srv, nil, "")
	send(t, in, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"wait",`+meta+`}}`)
	if l := next(t, out); !strings.Contains(l, "notifications/progress") {
		t.Fatalf("progress: %s", l)
	}
	send(t, in, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"client cancelled"}}`)
	select {
	case <-f.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream was not closed")
	}
	send(t, in, `{"jsonrpc":"2.0","id":8,"method":"ping","params":{`+meta+`}}`)
	if l := next(t, out); !strings.Contains(l, `"id":8`) {
		t.Fatalf("after the cancellation: %s", l)
	}
	if methods, _, _ := f.seen(); strings.Contains(strings.Join(methods, " "), "notifications/cancelled") {
		t.Fatalf("the notification was posted: %v", methods)
	}
	_ = in.Close()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
}

// After HeaderMismatch the connector lists the tools again (an
// annotation may be new) and retries once.
func TestModernConnectorHeaderMismatch(t *testing.T) {
	f, srv := newModernServer(t)
	f.annotated = false
	in, out, wait := pipe(t, srv, nil, "")
	send(t, in, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+meta+`}}`)
	next(t, out)
	f.mu.Lock()
	f.annotated = true
	f.mu.Unlock()
	send(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"region":"eu"},`+meta+`}}`)
	if l := next(t, out); l != `{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}` {
		t.Fatalf("call: %s", l)
	}
	methods, posts, _ := f.seen()
	if got := strings.Join(methods, " "); got != "tools/list tools/call tools/list tools/list tools/call" {
		t.Fatalf("requests %s", got)
	}
	if posts[1].Get("Mcp-Param-Region") != "" || posts[4].Get("Mcp-Param-Region") != "eu" {
		t.Fatalf("Mcp-Param-Region %q, then %q", posts[1].Get("Mcp-Param-Region"), posts[4].Get("Mcp-Param-Region"))
	}
	_ = in.Close()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
}

func TestHeaderValue(t *testing.T) {
	for in, want := range map[string]string{
		"us-west1":            "us-west1",
		"a b":                 "a b",
		"":                    "",
		"Hello, 世界":           "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":            "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":        "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=":  "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"=?base64?unfinished": "=?base64?unfinished",
	} {
		if got := headerValue(in); got != want {
			t.Errorf("headerValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToolHeaders(t *testing.T) {
	for _, tc := range []struct {
		schema string
		want   string // the headers, or the error
	}{
		{`{"type":"object","properties":{"r":{"type":"string","x-mcp-header":"Region"}}}`, "Region=r"},
		{`{"type":"object","properties":{"o":{"type":"object","properties":{"n":{"type":"integer","x-mcp-header":"N"}}}}}`, "N=o.n"},
		{`{"type":"object","properties":{"x-mcp-header":{"type":"string"}}}`, ""},
		{`{"type":"object","properties":{"e":{"type":"string","enum":[{"x-mcp-header":"E"}]}}}`, ""},
		{`{"type":"object","x-mcp-header":"Root"}`, "not on a property"},
		{`{"type":"object","properties":{"l":{"type":"array","items":{"type":"string","x-mcp-header":"I"}}}}`, "not on a property"},
		{`{"type":"object","properties":{"o":{"anyOf":[{"type":"object","properties":{"s":{"type":"string","x-mcp-header":"S"}}}]}}}`, "not on a property"},
		{`{"type":"object","$defs":{"d":{"type":"string","x-mcp-header":"D"}}}`, "not on a property"},
		{`{"type":"object","properties":{"f":{"type":"number","x-mcp-header":"F"}}}`, "type number"},
		{`{"type":"object","properties":{"s":{"type":"string","x-mcp-header":"A B"}}}`, "not a header name"},
		{`{"type":"object","properties":{"s":{"type":"string","x-mcp-header":""}}}`, "not a header name"},
		{`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"boolean","x-mcp-header":"x"}}}`, "used twice"},
	} {
		headers, err := toolHeaders(json.RawMessage(tc.schema))
		var got []string
		for _, h := range headers {
			got = append(got, h.name+"="+strings.Join(h.path, "."))
		}
		if err != nil {
			got = []string{err.Error()}
		}
		if s := strings.Join(got, ","); (tc.want == "" && s != "") || !strings.Contains(s, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.schema, s, tc.want)
		}
	}
}
