package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/egress"
	"github.com/sdrahn/mcp-gateway/internal/mcpheader"
)

// maxLine bounds a message from the gateway or the server (as the
// gateway's own limit for servers).
const maxLine = 16 << 20

// resumeAttempts bounds how often a request's event stream is resumed
// (GET with Last-Event-ID) before its call fails.
const resumeAttempts = 5

// errSessionGone means the server ended the session (404 for its id):
// the instance ends, and the gateway's next call starts a new one.
var errSessionGone = errors.New("the server ended the session (HTTP 404)")

// errUnauthorized means the server refused the principal's access token
// (HTTP 401, with -sign-in) and the gateway had no new one, or the server
// refused that too: the connector exits with exitUnauthorized, and the
// gateway, seeing the error (signin.RejectedMarker), has the principal
// sign in again.
var errUnauthorized = errors.New("the server refused the access token (HTTP 401)")

// exitUnauthorized is the exit status for errUnauthorized.
const exitUnauthorized = 77

// connector relays between the gateway (stdio) and one MCP server
// (Streamable HTTP).
type connector struct {
	endpoint string
	headers  http.Header
	signIn   bool
	client   *http.Client
	log      *slog.Logger

	outMu sync.Mutex
	out   io.Writer

	mu       sync.Mutex
	session  string // Mcp-Session-Id
	protocol string // MCP-Protocol-Version, from the initialize result
	initID   string // the initialize request's id
	getOnce  sync.Once

	// Modern servers (modern.go).
	inflight map[string]context.CancelFunc // requests, by id
	lists    map[string]bool               // tools/list requests, by id
	schemas  map[string][]mcpheader.Param  // x-mcp-header parameters, by tool
	listSeq  int
	listMu   sync.Mutex // one listing of the tools at a time

	// The requests for a new access token (token.go).
	tokMu    sync.Mutex
	tokSeq   int
	renewing *renewal
	tokWait  map[string]chan tokenAnswer

	fatal     chan error
	fatalOnce sync.Once
	stopped   chan struct{} // closed when the connector stops
	stopOnce  sync.Once
	// stdinDone is closed when stdin ended: no answer can come.
	stdinDone chan struct{}
}

// options are the connector's flags besides -url.
type options struct {
	headers      []string // -header "Name: value"
	resolve      []string // -resolve host:port:address
	proxy        string   // -proxy URL
	proxyHeaders []string // -proxy-header "Name: value", sent with CONNECT
	credDir      string   // $CREDENTIALS_DIRECTORY
	signIn       bool     // -sign-in: Authorization is a principal's token
}

func newConnector(endpoint string, o options) (*connector, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("-url: not an absolute URL: %q", endpoint)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !egress.Loopback(u.Hostname()) {
			return nil, fmt.Errorf("-url: http:// only to a local address (localhost, 127.0.0.0/8, ::1), not %s", u.Hostname())
		}
	default:
		return nil, fmt.Errorf("-url: scheme must be https or http, not %q", u.Scheme)
	}
	h, err := egress.ParseHeaders("-header", o.headers, o.credDir)
	if err != nil {
		return nil, err
	}
	eo := egress.Options{Resolve: o.resolve}
	if o.proxy != "" {
		if eo.Proxy, err = egress.ParseProxy(o.proxy); err != nil {
			return nil, err
		}
		if u.Scheme != "https" {
			return nil, errors.New("-proxy: only for an https:// -url (the tunnel carries TLS to the server)")
		}
		if eo.ProxyHeader, err = egress.ParseHeaders("-proxy-header", o.proxyHeaders, o.credDir); err != nil {
			return nil, err
		}
	} else if len(o.proxyHeaders) > 0 {
		return nil, errors.New("-proxy-header: only with -proxy")
	}
	transport, err := egress.Transport(eo)
	if err != nil {
		return nil, err
	}
	return &connector{
		signIn:    o.signIn,
		endpoint:  endpoint,
		headers:   h,
		client:    &http.Client{Transport: transport},
		log:       slog.New(slog.DiscardHandler),
		fatal:     make(chan error, 1),
		stopped:   make(chan struct{}),
		stdinDone: make(chan struct{}),
	}, nil
}

// serve relays until stdin ends, ctx ends, or the session is gone.
func (c *connector) serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	c.out = stdout
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		r := bufio.NewReaderSize(stdin, 64<<10)
		for {
			line, err := readLine(r)
			// The gateway's answers about tokens go to the request
			// waiting for them, also while initialize is being posted.
			if c.signIn && c.tokenReply(line) {
				continue
			}
			if len(bytes.TrimSpace(line)) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				close(c.stdinDone)
				readErr <- err
				return
			}
		}
	}()
	var result error
loop:
	for {
		select {
		case line := <-lines:
			if isInitialize(line) {
				// Before anything else: its answer brings the session id
				// the other messages need.
				c.post(ctx, line)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.post(ctx, line)
			}()
		case err := <-readErr:
			if !errors.Is(err, io.EOF) {
				result = err
			}
			select {
			case err := <-c.fatal: // what ended it before stdin did
				result = err
			default:
			}
			break loop
		case err := <-c.fatal:
			result = err
			break loop
		case <-ctx.Done():
			break loop
		}
	}
	cancel()
	wg.Wait()
	c.closeSession()
	return result
}

func isInitialize(line []byte) bool {
	var m message
	return json.Unmarshal(line, &m) == nil && m.Method == "initialize"
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLine {
			return nil, fmt.Errorf("a message from the gateway exceeds %d bytes", maxLine)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

func (c *connector) fail(err error) {
	c.fatalOnce.Do(func() { c.fatal <- err })
}

// message is what the connector looks at in a JSON-RPC message.
type message struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result *struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"result"`
}

func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		return string(id)
	}
	return b.String()
}

// post sends one message from the gateway to the server and relays the
// server's answer.
func (c *connector) post(ctx context.Context, body []byte) {
	var m message
	if err := json.Unmarshal(body, &m); err != nil {
		c.log.Warn("not a JSON-RPC message from the gateway; dropped", "err", err)
		return
	}
	var p params
	_ = json.Unmarshal(m.Params, &p)
	isRequest := len(m.ID) > 0 && m.Method != ""
	if v := p.modernVersion(); v != "" && isRequest {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer c.track(idKey(m.ID), cancel)()
		c.postOnce(ctx, body, m, newModernRequest(m.Method, p, v))
		return
	}
	c.mu.Lock()
	modern := c.initID == ""
	c.mu.Unlock()
	if modern && !isRequest && m.Method != "" {
		// A modern server takes no notifications over HTTP; a request is
		// cancelled by closing its stream.
		if m.Method == "notifications/cancelled" {
			c.cancelled(p)
		}
		return
	}
	c.postOnce(ctx, body, m, nil)
}

// postOnce posts the message m (body) and relays the answer; mod is set
// for a request to a modern server.
func (c *connector) postOnce(ctx context.Context, body []byte, m message, mod *modernRequest) {
	isRequest := len(m.ID) > 0 && m.Method != ""
	id := ""
	if isRequest {
		id = idKey(m.ID)
		if m.Method == "initialize" {
			c.mu.Lock()
			c.initID = id
			c.mu.Unlock()
		}
	}
	var header http.Header
	if mod != nil {
		header = mod.header
		switch m.Method {
		case "tools/call":
			mcpheader.Set(header, c.toolHeadersFor(ctx, mod), mod.params.Arguments)
		case "tools/list":
			c.mu.Lock()
			if c.lists == nil {
				c.lists = map[string]bool{}
			}
			c.lists[id] = true
			c.mu.Unlock()
			defer func() {
				c.mu.Lock()
				delete(c.lists, id)
				c.mu.Unlock()
			}()
		}
	}
	resp, err := c.do(ctx, body, header)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			c.answerError(m.ID, isRequest, err)
			c.fail(err)
		} else if ctx.Err() == nil {
			c.answerError(m.ID, isRequest, err)
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && m.Method == "initialize" {
		c.mu.Lock()
		c.session = sid
		c.mu.Unlock()
	}
	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		return
	case resp.StatusCode == http.StatusNotFound && mod == nil && c.sessionID() != "":
		c.answerError(m.ID, isRequest, errSessionGone)
		c.fail(errSessionGone)
		return
	case resp.StatusCode == http.StatusUnauthorized && c.signIn:
		c.answerError(m.ID, isRequest, errUnauthorized)
		c.fail(errUnauthorized)
		return
	case resp.StatusCode/100 != 2:
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxLine+1))
		if mod != nil && isRequest {
			// A modern server says what is wrong in a JSON-RPC error (an
			// unsupported version, an unknown method, headers that do
			// not match): the gateway's to see.
			if answer, code := errorAnswer(data, m.ID); answer != nil {
				if code == codeHeaderMismatch && m.Method == "tools/call" && !mod.retried {
					// The tool's parameters may have changed: list the
					// tools again and retry once.
					_ = resp.Body.Close()
					c.listMu.Lock()
					if err := c.listTools(ctx, mod); err != nil {
						c.log.Warn("listing the server's tools for their x-mcp-header parameters", "err", err)
					}
					c.listMu.Unlock()
					retry := newModernRequest(m.Method, mod.params, mod.version)
					retry.retried = true
					c.postOnce(ctx, body, m, retry)
					return
				}
				c.write(answer)
				return
			}
		}
		snippet := data[:min(len(data), 512)]
		c.answerError(m.ID, isRequest, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(snippet))))
		return
	}
	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		answered, lastID := c.relayEvents(resp.Body, id)
		// A modern server's streams are not resumed: closing one cancels
		// the request.
		for attempt := 0; mod == nil && isRequest && !answered && lastID != "" && attempt < resumeAttempts && ctx.Err() == nil; attempt++ {
			answered, lastID = c.resume(ctx, id, lastID)
		}
		if isRequest && !answered && ctx.Err() == nil {
			c.answerError(m.ID, true, errors.New("the server's event stream ended before its answer"))
		}
	case strings.HasPrefix(ct, "application/json"):
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxLine+1))
		if err != nil || len(data) > maxLine {
			c.answerError(m.ID, isRequest, fmt.Errorf("reading the answer: %v", err))
			return
		}
		c.relay(data, id)
	default:
		if isRequest {
			c.answerError(m.ID, true, fmt.Errorf("unexpected Content-Type %q", ct))
		}
	}
}

// do posts body with the headers of a modern request (header), or of the
// legacy session (nil); after a 401, it gets a new access token from the
// gateway (-sign-in) and posts once more, and when there is none it
// returns errUnauthorized.
func (c *connector) do(ctx context.Context, body []byte, header http.Header) (*http.Response, error) {
	for retry := true; ; retry = false {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		used := c.setHeaders(req, header)
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && c.signIn && retry {
			_ = resp.Body.Close()
			if c.renew(ctx, used) {
				continue
			}
			return nil, errUnauthorized
		}
		return resp, nil
	}
}

// resume continues a request's event stream after lastID (GET with
// Last-Event-ID); it reports whether the answer to id came, and the last
// event id seen.
func (c *connector) resume(ctx context.Context, id, lastID string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", lastID)
	c.setHeaders(req, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return false, lastID
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return false, ""
	}
	answered, last := c.relayEvents(resp.Body, id)
	if last == "" {
		last = lastID
	}
	return answered, last
}

// listen keeps the GET stream open for what the server sends outside a
// request, until ctx ends: reconnecting with backoff, resuming after the
// last event. A server without one (405) is fine.
func (c *connector) listen(ctx context.Context) {
	lastID := ""
	backoff := time.Second
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		used := c.setHeaders(req, nil)
		resp, err := c.client.Do(req)
		switch {
		case err != nil:
		case resp.StatusCode == http.StatusUnauthorized && c.signIn && c.renew(ctx, used):
			_ = resp.Body.Close()
			continue // at once, with the new token
		case resp.StatusCode == http.StatusMethodNotAllowed:
			_ = resp.Body.Close()
			return
		case resp.StatusCode == http.StatusNotFound && c.sessionID() != "":
			_ = resp.Body.Close()
			c.fail(errSessionGone)
			return
		case resp.StatusCode == http.StatusUnauthorized && c.signIn:
			_ = resp.Body.Close()
			c.fail(errUnauthorized)
			return
		case resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream"):
			backoff = time.Second
			if _, last := c.relayEvents(resp.Body, ""); last != "" {
				lastID = last
			}
			_ = resp.Body.Close()
		default:
			_ = resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

// relayEvents writes the messages of an event stream to the gateway; it
// reports whether the answer to id came (then it stops reading: the
// server closes the stream), and the last event id.
func (c *connector) relayEvents(body io.Reader, id string) (bool, string) {
	return readEvents(body, func(data []byte) bool { return c.relay(data, id) })
}

// readEvents passes the messages of an event stream to message until it
// reports true (then readEvents does too); it returns the last event id.
func readEvents(body io.Reader, message func(data []byte) bool) (bool, string) {
	r := bufio.NewReaderSize(body, 64<<10)
	var data bytes.Buffer
	event, lastID := "", ""
	for {
		line, err := readLine(r)
		line = bytes.TrimRight(line, "\r\n")
		switch {
		case len(line) == 0 && err == nil:
			if data.Len() > 0 && (event == "" || event == "message") {
				if message(bytes.TrimSuffix(data.Bytes(), []byte("\n"))) {
					return true, lastID
				}
			}
			data.Reset()
			event = ""
		case bytes.HasPrefix(line, []byte(":")):
		default:
			field, value, _ := bytes.Cut(line, []byte(":"))
			value = bytes.TrimPrefix(value, []byte(" "))
			switch string(field) {
			case "data":
				data.Write(value)
				data.WriteByte('\n')
			case "event":
				event = string(value)
			case "id":
				lastID = string(value)
			}
		}
		if err != nil {
			return false, lastID
		}
	}
}

// relay writes a message (or a batch) from the server to the gateway, one
// per line; it reports whether it is the answer to id.
func (c *connector) relay(data []byte, id string) bool {
	data = bytes.TrimSpace(data)
	var batch []json.RawMessage
	if len(data) > 0 && data[0] == '[' {
		if err := json.Unmarshal(data, &batch); err != nil {
			c.log.Warn("not JSON from the server; dropped", "err", err)
			return false
		}
	} else {
		batch = []json.RawMessage{data}
	}
	answered := false
	for _, raw := range batch {
		var m message
		if err := json.Unmarshal(raw, &m); err != nil {
			c.log.Warn("not a JSON-RPC message from the server; dropped", "err", err)
			continue
		}
		if m.Method == "" && len(m.ID) > 0 {
			key := idKey(m.ID)
			answered = answered || key == id
			c.mu.Lock()
			isInit := key == c.initID && c.initID != ""
			if isInit && m.Result != nil {
				c.protocol = m.Result.ProtocolVersion
			}
			isList := c.lists[key]
			c.mu.Unlock()
			if isList {
				raw = c.toolsAnswer(raw)
			}
			if isInit && m.Result != nil {
				c.getOnce.Do(func() { go c.listen(c.listenCtx()) })
			}
		}
		c.write(raw)
	}
	return answered
}

// listenCtx is the context of the GET stream: it ends when the
// connector stops.
func (c *connector) listenCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-c.stopped
		cancel()
	}()
	return ctx
}

func (c *connector) write(raw json.RawMessage) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return
	}
	b.WriteByte('\n')
	c.outMu.Lock()
	defer c.outMu.Unlock()
	if _, err := c.out.Write(b.Bytes()); err != nil {
		c.fail(fmt.Errorf("writing to the gateway: %w", err))
	}
}

// answerError answers a request whose relay failed, so that the call
// fails instead of waiting; for a notification or a response it logs.
func (c *connector) answerError(id json.RawMessage, isRequest bool, err error) {
	if !isRequest {
		c.log.Warn("message to the server not delivered", "err", err)
		return
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": -32603, "message": "MCP server over HTTP: " + err.Error()},
	})
	c.write(b)
}

// setHeaders sets the request's headers, those of a modern request
// (header) or of the legacy session (nil), and returns the access token
// it carries (-sign-in).
func (c *connector) setHeaders(req *http.Request, header http.Header) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if header != nil {
		for k, vs := range header {
			req.Header[k] = vs
		}
		return strings.TrimPrefix(c.headers.Get("Authorization"), "Bearer ")
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", c.protocol)
	}
	return strings.TrimPrefix(c.headers.Get("Authorization"), "Bearer ")
}

func (c *connector) sessionID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// closeSession stops the GET stream and ends the session on the server
// (DELETE), as the specification asks of a client that leaves.
func (c *connector) closeSession() {
	c.stopOnce.Do(func() { close(c.stopped) })
	if c.sessionID() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.endpoint, nil)
	if err != nil {
		return
	}
	c.setHeaders(req, nil)
	if resp, err := c.client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}
