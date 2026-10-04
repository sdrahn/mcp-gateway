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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
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

// connector relays between the gateway (stdio) and one MCP server
// (Streamable HTTP).
type connector struct {
	endpoint string
	headers  http.Header
	client   *http.Client
	log      *slog.Logger

	outMu sync.Mutex
	out   io.Writer

	mu       sync.Mutex
	session  string // Mcp-Session-Id
	protocol string // MCP-Protocol-Version, from the initialize result
	initID   string // the initialize request's id
	getOnce  sync.Once

	fatal     chan error
	fatalOnce sync.Once
	stopped   chan struct{} // closed when the connector stops
	stopOnce  sync.Once
}

var credentialRef = regexp.MustCompile(`\$\{CREDENTIAL:([A-Za-z0-9_][A-Za-z0-9_.-]{0,63})\}`)

func newConnector(endpoint string, headers, resolve []string, credDir string) (*connector, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("-url: not an absolute URL: %q", endpoint)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, fmt.Errorf("-url: http:// only to a local address (localhost, 127.0.0.0/8, ::1), not %s", u.Hostname())
		}
	default:
		return nil, fmt.Errorf("-url: scheme must be https or http, not %q", u.Scheme)
	}
	h := http.Header{}
	for _, line := range headers {
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return nil, fmt.Errorf("-header: want \"Name: value\", got %q", line)
		}
		var credErr error
		v = credentialRef.ReplaceAllStringFunc(v, func(ref string) string {
			name := credentialRef.FindStringSubmatch(ref)[1]
			if credDir == "" {
				credErr = fmt.Errorf("-header %s: credential %s: no $CREDENTIALS_DIRECTORY", k, name)
				return ""
			}
			b, err := os.ReadFile(filepath.Join(credDir, name))
			if err != nil {
				credErr = fmt.Errorf("-header %s: credential %s: %w", k, name, err)
				return ""
			}
			return strings.TrimRight(string(b), "\r\n")
		})
		if credErr != nil {
			return nil, credErr
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("-header %s: the value has a line break", k)
		}
		h.Add(k, v)
	}
	dialTo := map[string]string{} // host:port to address:port
	for _, r := range resolve {
		parts := strings.SplitN(r, ":", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || net.ParseIP(strings.Trim(parts[2], "[]")) == nil {
			return nil, fmt.Errorf("-resolve: want host:port:address, got %q", r)
		}
		dialTo[net.JoinHostPort(parts[0], parts[1])] = net.JoinHostPort(strings.Trim(parts[2], "[]"), parts[1])
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, // the instance reaches the server's addresses only
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if to, ok := dialTo[address]; ok {
				address = to
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   8,
	}
	return &connector{
		endpoint: endpoint,
		headers:  h,
		client:   &http.Client{Transport: transport},
		log:      slog.New(slog.DiscardHandler),
		fatal:    make(chan error, 1),
		stopped:  make(chan struct{}),
	}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
			if len(bytes.TrimSpace(line)) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		c.answerError(m.ID, isRequest, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	c.setHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
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
	case resp.StatusCode == http.StatusNotFound && c.sessionID() != "":
		c.answerError(m.ID, isRequest, errSessionGone)
		c.fail(errSessionGone)
		return
	case resp.StatusCode/100 != 2:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.answerError(m.ID, isRequest, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(snippet))))
		return
	}
	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		answered, lastID := c.relayEvents(resp.Body, id)
		for attempt := 0; isRequest && !answered && lastID != "" && attempt < resumeAttempts && ctx.Err() == nil; attempt++ {
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
		c.relay(data, "")
	default:
		if isRequest {
			c.answerError(m.ID, true, fmt.Errorf("unexpected Content-Type %q", ct))
		}
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
	c.setHeaders(req)
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
		c.setHeaders(req)
		resp, err := c.client.Do(req)
		switch {
		case err != nil:
		case resp.StatusCode == http.StatusMethodNotAllowed:
			_ = resp.Body.Close()
			return
		case resp.StatusCode == http.StatusNotFound && c.sessionID() != "":
			_ = resp.Body.Close()
			c.fail(errSessionGone)
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
	r := bufio.NewReaderSize(body, 64<<10)
	var data bytes.Buffer
	event, lastID := "", ""
	for {
		line, err := readLine(r)
		line = bytes.TrimRight(line, "\r\n")
		switch {
		case len(line) == 0 && err == nil:
			if data.Len() > 0 && (event == "" || event == "message") {
				if c.relay(bytes.TrimSuffix(data.Bytes(), []byte("\n")), id) {
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
			c.mu.Unlock()
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

func (c *connector) setHeaders(req *http.Request) {
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", c.protocol)
	}
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
	c.setHeaders(req)
	if resp, err := c.client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}
