package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is a Streamable HTTP MCP server for the tests.
type fakeServer struct {
	t       *testing.T
	mu      sync.Mutex
	headers []http.Header // of each POST after initialize
	deleted bool
	expired bool // answer 404 to the session
	get     chan string
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	expired := f.expired
	f.mu.Unlock()
	if r.Header.Get("Mcp-Session-Id") != "" && (expired || r.Header.Get("Mcp-Session-Id") != "s1") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		f.mu.Lock()
		f.deleted = true
		f.mu.Unlock()
		return
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/event-stream")
		if last := r.Header.Get("Last-Event-ID"); last == "c3-1" {
			// The rest of the dropped stream of request 3.
			_, _ = fmt.Fprint(w, "id: c3-2\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resumed\":true}}\n\n")
			return
		}
		w.(http.Flusher).Flush()
		for {
			select {
			case msg := <-f.get:
				_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &m)
	if m.Method != "initialize" {
		f.mu.Lock()
		f.headers = append(f.headers, r.Header.Clone())
		f.mu.Unlock()
	}
	switch m.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "s1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}`, m.ID)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/call":
		// Progress, then the answer, on the request's event stream.
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, ": comment\n\nid: c2-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\n")
		_, _ = fmt.Fprint(w, "data: \"params\":{\"progressToken\":\"p\",\"progress\":1}}\n\n")
		_, _ = fmt.Fprintf(w, "id: c2-2\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n\n", m.ID)
	case "slow/dropped":
		// The stream breaks after the first event: resumed with GET.
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "id: c3-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
	case "broken":
		http.Error(w, "upstream trouble", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

// pipe runs a connector against srv and returns a writer for the
// gateway's side, a reader of the lines the connector writes, and a wait
// for its end.
func pipe(t *testing.T, srv *httptest.Server, headers []string, credDir string) (io.WriteCloser, *bufio.Scanner, func() error) {
	t.Helper()
	c, err := newConnector(srv.URL, options{headers: headers, credDir: credDir})
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := c.serve(context.Background(), inR, outW)
		_ = outW.Close()
		done <- err
	}()
	sc := bufio.NewScanner(outR)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	return inW, sc, func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("connector did not end")
			return nil
		}
	}
}

func next(t *testing.T, sc *bufio.Scanner) string {
	t.Helper()
	line := make(chan string, 1)
	go func() {
		if sc.Scan() {
			line <- sc.Text()
		} else {
			line <- "EOF " + fmt.Sprint(sc.Err())
		}
	}()
	select {
	case l := <-line:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("no line from the connector")
		return ""
	}
}

func send(t *testing.T, w io.Writer, msg string) {
	t.Helper()
	if _, err := io.WriteString(w, msg+"\n"); err != nil {
		t.Fatal(err)
	}
}

func TestConnector(t *testing.T) {
	f := &fakeServer{t: t, get: make(chan string, 1)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cred := t.TempDir()
	if err := os.WriteFile(filepath.Join(cred, "token"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, out, wait := pipe(t, srv, []string{"Authorization: Bearer ${CREDENTIAL:token}"}, cred)

	send(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if l := next(t, out); !strings.Contains(l, `"protocolVersion":"2025-06-18"`) || strings.Contains(l, "\n") {
		t.Fatalf("initialize: %s", l)
	}
	send(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	// A request answered on an event stream: the progress, then the answer.
	send(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}`)
	if l := next(t, out); l != `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1}}` {
		t.Fatalf("progress: %s", l)
	}
	if l := next(t, out); l != `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}` {
		t.Fatalf("answer: %s", l)
	}

	// What the server sends outside a request comes on the GET stream.
	f.get <- `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`
	if l := next(t, out); l != `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` {
		t.Fatalf("GET stream: %s", l)
	}

	// A stream that breaks before the answer is resumed after its last event.
	send(t, in, `{"jsonrpc":"2.0","id":3,"method":"slow/dropped"}`)
	if l := next(t, out); !strings.Contains(l, "notifications/message") {
		t.Fatalf("before the break: %s", l)
	}
	if l := next(t, out); l != `{"jsonrpc":"2.0","id":3,"result":{"resumed":true}}` {
		t.Fatalf("resumed: %s", l)
	}

	// An HTTP error answers the call with a JSON-RPC error.
	send(t, in, `{"jsonrpc":"2.0","id":4,"method":"broken"}`)
	if l := next(t, out); !strings.Contains(l, `"id":4`) || !strings.Contains(l, "500") || !strings.Contains(l, "upstream trouble") {
		t.Fatalf("error: %s", l)
	}

	_ = in.Close()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.deleted {
		t.Error("the session was not ended (DELETE)")
	}
	for _, h := range f.headers {
		if h.Get("Mcp-Session-Id") != "s1" || h.Get("MCP-Protocol-Version") != "2025-06-18" || h.Get("Authorization") != "Bearer s3cret" {
			t.Errorf("headers %v", h)
		}
	}
}

// When the server ends the session (404), the call fails and the
// connector ends, so that the gateway starts a new instance.
func TestConnectorSessionGone(t *testing.T) {
	f := &fakeServer{t: t, get: make(chan string)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	in, out, wait := pipe(t, srv, nil, "")
	send(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	next(t, out)
	f.mu.Lock()
	f.expired = true
	f.mu.Unlock()
	send(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	// The POST or the GET stream notices first: the call fails, or the
	// connector ends before answering it (the gateway fails the call when
	// the instance ends).
	if l := next(t, out); !strings.HasPrefix(l, "EOF") && (!strings.Contains(l, `"id":2`) || !strings.Contains(l, "ended the session")) {
		t.Fatalf("got %s", l)
	}
	if err := wait(); err == nil || !strings.Contains(err.Error(), "ended the session") {
		t.Fatalf("connector ended with %v", err)
	}
}

func TestNewConnector(t *testing.T) {
	for _, c := range []struct {
		url     string
		headers []string
		resolve []string
		proxy   string
		// proxyHeaders are -proxy-header values.
		proxyHeaders []string
		err          string
	}{
		{url: "https://mcp.example.com/mcp"},
		{url: "http://127.0.0.1:8080/mcp"},
		{url: "http://localhost/mcp"},
		{url: "http://mcp.example.com/mcp", err: "only to a local address"},
		{url: "ftp://x/", err: "scheme"},
		{url: "/mcp", err: "absolute"},
		{url: "https://x/", headers: []string{"NoColon"}, err: "Name: value"},
		{url: "https://x/", headers: []string{"X-Key: ${CREDENTIAL:k}"}, err: "no $CREDENTIALS_DIRECTORY"},
		{url: "https://x/", resolve: []string{"x:443:192.0.2.1", "x:443:[2001:db8::1]"}},
		{url: "https://x/", resolve: []string{"x:443:not-an-ip"}, err: "host:port:address"},
		{url: "https://x/", proxy: "http://proxy:3128", proxyHeaders: []string{"Proxy-Authorization: Basic eDp5"}},
		{url: "https://x/", proxy: "https://proxy:3128"},
		{url: "http://127.0.0.1:8080/mcp", proxy: "http://proxy:3128", err: "only for an https:// -url"},
		{url: "https://x/", proxy: "socks5://proxy:1080", err: "-proxy: want"},
		{url: "https://x/", proxy: "http://u:p@proxy:3128", err: "-proxy: want"},
		{url: "https://x/", proxyHeaders: []string{"A: b"}, err: "only with -proxy"},
		{url: "https://x/", proxy: "http://proxy:3128", proxyHeaders: []string{"NoColon"}, err: "-proxy-header: want"},
	} {
		_, err := newConnector(c.url, options{headers: c.headers, resolve: c.resolve, proxy: c.proxy, proxyHeaders: c.proxyHeaders})
		if (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// -resolve sends the connection to the address given, whatever the name
// resolves to.
func TestResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	c, err := newConnector("http://localhost:"+port+"/mcp", options{resolve: []string{"localhost:" + port + ":127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.client.Post(c.endpoint, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

// -proxy tunnels to the server with CONNECT, sending -proxy-header (with
// its credential) to the proxy only; -resolve applies to the proxy's
// name, and TLS ends at the server.
func TestProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("the server got Proxy-Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer srv.Close()
	var connects []string
	var mu sync.Mutex
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic c2VjcmV0" {
			http.Error(w, "no", http.StatusProxyAuthRequired)
			return
		}
		mu.Lock()
		connects = append(connects, r.Host)
		mu.Unlock()
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		go func() { _, _ = io.Copy(up, rw); _ = up.Close() }()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
	}))
	defer proxy.Close()

	credDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(credDir, "proxy"), []byte("c2VjcmV0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := proxy.URL[strings.LastIndex(proxy.URL, ":")+1:]
	c, err := newConnector(srv.URL+"/mcp", options{
		proxy:        "http://proxy.invalid:" + port,
		proxyHeaders: []string{"Proxy-Authorization: Basic ${CREDENTIAL:proxy}"},
		resolve:      []string{"proxy.invalid:" + port + ":127.0.0.1"},
		credDir:      credDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	resp, err := c.client.Post(c.endpoint, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(connects) != 1 || connects[0] != strings.TrimPrefix(srv.URL, "https://") {
		t.Errorf("CONNECTs %v", connects)
	}
}

func TestRunUsage(t *testing.T) {
	var out, errb strings.Builder
	if rc := run(context.Background(), []string{"-version"}, strings.NewReader(""), &out, &errb); rc != 0 || !strings.HasPrefix(out.String(), name) {
		t.Errorf("-version: %d %q", rc, out.String())
	}
	if rc := run(context.Background(), []string{"-url", "ftp://x"}, strings.NewReader(""), &out, &errb); rc != 2 {
		t.Errorf("bad url: %d", rc)
	}
}

// With -sign-in, a 401 ends the connector with status 77 (the gateway
// refreshes the token); without, the call fails and the connector goes on.
func TestConnectorUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	var out, errb strings.Builder
	if rc := run(context.Background(), []string{"-url", srv.URL, "-sign-in"}, strings.NewReader(in), &out, &errb); rc != exitUnauthorized {
		t.Errorf("-sign-in: rc %d, %s", rc, errb.String())
	}
	out.Reset()
	if rc := run(context.Background(), []string{"-url", srv.URL}, strings.NewReader(in), &out, &errb); rc == exitUnauthorized || !strings.Contains(out.String(), "401") {
		t.Errorf("without -sign-in: rc %d, %q", rc, out.String())
	}
}
