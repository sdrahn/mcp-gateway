package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/mcpheader"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Requests of agents of MCP 2026-07-28 ("modern") carry their protocol
// version in _meta and need no session: each POST is answered on its own
// (docs/architecture.md, section 5.11.1), as JSON, or as an SSE stream
// when progress or log messages come before the response. The required
// headers are checked against the body first.

// modernVersion is the protocol version of modern requests.
const modernVersion = "2026-07-28"

// agentVersions are all the versions the gateway speaks to agents, for
// UnsupportedProtocolVersion.
var agentVersions = []string{modernVersion, "2025-11-25", "2025-06-18", "2025-03-26"}

// MCP 2026-07-28 error codes.
const (
	codeHeaderMismatch     = -32020
	codeMissingCapability  = -32021
	codeUnsupportedVersion = -32022
)

const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// RequestFunc serves one modern request on the endpoint server ("all"
// for the aggregated one), writing what belongs to it and then its
// response to out; it returns when the response is written or ctx ends
// (the client went away). header is the request's (for Mcp-Param-*).
type RequestFunc func(ctx context.Context, out jsonrpc.MessageConn, p principal.Principal, server string, m *jsonrpc.Message, header http.Header)

// modernMeta returns the protocol version in a request's _meta, and
// whether the request has one (then it is a modern request).
func modernMeta(m *jsonrpc.Message) (version string, caps json.RawMessage, ok bool) {
	if !m.IsRequest() {
		return "", nil, false
	}
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	_ = json.Unmarshal(m.Params, &p)
	raw, ok := p.Meta[metaProtocolVersion]
	if !ok {
		return "", nil, false
	}
	_ = json.Unmarshal(raw, &version)
	return version, p.Meta[metaClientCapabilities], true
}

// postModern serves the modern request m.
func (h *HTTPHandler) postModern(w http.ResponseWriter, r *http.Request, p principal.Principal, server string, m *jsonrpc.Message, version string, caps json.RawMessage) {
	if err := checkHeaders(r.Header, m, version); err != nil {
		writeRPCError(w, http.StatusBadRequest, m.ID, codeHeaderMismatch, err.Error(), nil)
		return
	}
	if version != modernVersion {
		writeRPCError(w, http.StatusBadRequest, m.ID, codeUnsupportedVersion, fmt.Sprintf("unsupported protocol version %q", version), versionsData(version))
		return
	}
	var c map[string]json.RawMessage
	if json.Unmarshal(caps, &c) != nil || c == nil {
		writeRPCError(w, http.StatusBadRequest, m.ID, jsonrpc.CodeInvalidParams, "invalid params: _meta lacks "+metaClientCapabilities, nil)
		return
	}
	out := &modernWriter{w: w, id: m.Key(), sse: acceptsSSE(r),
		challenge: func(scope string, body []byte) { h.scopeChallenge(w, p, scope, body) }}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if m.Method == "subscriptions/listen" {
		// A stream: SSE, kept alive, and only as long as the token is
		// accepted (as the GET stream of a session).
		if !out.sse {
			writeRPCError(w, http.StatusBadRequest, m.ID, jsonrpc.CodeInvalidRequest, "subscriptions/listen needs Accept: text/event-stream", nil)
			return
		}
		if !p.Expires.IsZero() {
			t := time.AfterFunc(time.Until(p.Expires), func() {
				cancel()
				if h.cfg.TokenExpired != nil {
					h.cfg.TokenExpired(p)
				}
			})
			defer t.Stop()
		}
	}
	stop := out.keepAlive(keepAlive)
	defer stop()
	h.cfg.Request(ctx, out, p, server, m, r.Header)
	out.finish()
}

func versionsData(requested string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"supported": agentVersions, "requested": requested})
	return b
}

// checkHeaders checks the headers MCP 2026-07-28 requires against the
// body: MCP-Protocol-Version, Mcp-Method and, for the methods that name
// something, Mcp-Name (Base64 sentinel values decoded). The Mcp-Param
// headers of tools are checked by the router, which knows the schemas.
func checkHeaders(h http.Header, m *jsonrpc.Message, version string) error {
	if got := h.Get(versionHeader); got != version {
		return fmt.Errorf("header mismatch: %s %q, _meta says %q", versionHeader, got, version)
	}
	if got := h.Get("Mcp-Method"); got != m.Method {
		return fmt.Errorf("header mismatch: Mcp-Method %q, the method is %q", got, m.Method)
	}
	var p struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	_ = json.Unmarshal(m.Params, &p)
	want, named := "", false
	switch m.Method {
	case "tools/call", "prompts/get":
		want, named = p.Name, true
	case "resources/read":
		want, named = p.URI, true
	}
	if !named {
		return nil
	}
	vals := h.Values("Mcp-Name")
	if len(vals) != 1 {
		return fmt.Errorf("header mismatch: Mcp-Name missing or repeated")
	}
	got, err := mcpheader.Decode(vals[0])
	if err != nil {
		return fmt.Errorf("header mismatch: Mcp-Name: %v", err)
	}
	if got != want {
		return fmt.Errorf("header mismatch: Mcp-Name does not match the body")
	}
	return nil
}

// statusOf is the HTTP status of a modern response: errors about the
// request's form are 400, an unknown method 404.
func statusOf(m *jsonrpc.Message) int {
	if m.Error == nil {
		return http.StatusOK
	}
	switch m.Error.Code {
	case codeHeaderMismatch, codeMissingCapability, codeUnsupportedVersion:
		return http.StatusBadRequest
	case jsonrpc.CodeMethodNotFound:
		return http.StatusNotFound
	}
	return http.StatusOK
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string, data json.RawMessage) {
	m := jsonrpc.NewError(id, code, msg)
	m.Error.Data = data
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(m)
}

// modernWriter is the response of one modern request: a JSON body, or an
// SSE stream once a message other than the response comes first (if the
// client accepts SSE; else such messages are dropped).
type modernWriter struct {
	w   http.ResponseWriter
	id  string
	sse bool
	// challenge answers a response with a scope challenge (403).
	challenge func(scope string, body []byte)

	mu       sync.Mutex
	streamed bool // the SSE stream started
	done     bool // the response was written
}

func (o *modernWriter) Read() (*jsonrpc.Message, error) { select {} }
func (o *modernWriter) Close() error                    { return nil }

// WriteRelated implements jsonrpc.RelatedWriter: everything written here
// belongs to the request.
func (o *modernWriter) WriteRelated(m *jsonrpc.Message, _ json.RawMessage) error { return o.Write(m) }

func (o *modernWriter) Write(m *jsonrpc.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	response := m.IsResponse() && m.Key() == o.id
	if !o.streamed {
		if response {
			o.done = true
			if m.ScopeChallenge != "" && o.challenge != nil {
				o.challenge(m.ScopeChallenge, b)
				return nil
			}
			o.w.Header().Set("Content-Type", "application/json")
			o.w.WriteHeader(statusOf(m))
			_, err = o.w.Write(append(b, '\n'))
			return err
		}
		if !o.sse || m.IsRequest() {
			return nil // nowhere to send it
		}
		o.streamed = true
		o.w.Header().Set("Content-Type", "text/event-stream")
		o.w.Header().Set("Cache-Control", "no-cache")
		o.w.Header().Set("X-Accel-Buffering", "no")
		o.w.WriteHeader(http.StatusOK)
	}
	if m.IsRequest() {
		return nil
	}
	if _, err = fmt.Fprintf(o.w, "event: message\ndata: %s\n\n", b); err != nil {
		return err
	}
	if f, ok := o.w.(http.Flusher); ok {
		f.Flush()
	}
	o.done = response
	return nil
}

// keepAlive writes an SSE comment every interval while the response is a
// stream; the returned function stops it.
func (o *modernWriter) keepAlive(interval time.Duration) func() {
	t := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-t.C:
				o.mu.Lock()
				if o.streamed && !o.done {
					_, _ = fmt.Fprint(o.w, ": keep-alive\n\n")
					if f, ok := o.w.(http.Flusher); ok {
						f.Flush()
					}
				}
				o.mu.Unlock()
			}
		}
	}()
	return func() {
		t.Stop()
		close(done)
	}
}

// finish ends a response the handler did not write (the client went
// away): nothing more to send.
func (o *modernWriter) finish() {
	o.mu.Lock()
	o.done = true
	o.mu.Unlock()
}

func acceptsSSE(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}
