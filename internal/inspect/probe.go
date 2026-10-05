// Package inspect asks an MCP server what it offers (tools, prompts,
// resource templates) and drafts what the gateway needs to run it: a
// server definition and roles. It also checks role data against the tools
// a server really has. Drafts are proposals for an administrator; what a
// server says about its tools is not trusted.
//
// See docs/architecture.md, section 11, step 11.
package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// protocolVersion is the legacy MCP version offered to a server that
// needs the initialize handshake, modernVersion the one used with a
// server that answers server/discover (the versions the gateway speaks to
// servers, internal/router).
const (
	protocolVersion = "2025-11-25"
	modernVersion   = "2026-07-28"
)

// ErrProbeEnded is returned when the server exited on server/discover, as
// some legacy servers do on a request before initialize; Start then
// starts it again and initializes it.
var ErrProbeEnded = errors.New("the server exited when probed with server/discover")

// maxPages bounds paginated lists, as the router does.
const maxPages = 100

// Result is what a server reports about itself.
type Result struct {
	Server            ServerInfo                 `json:"server"`
	ProtocolVersion   string                     `json:"protocolVersion"`
	Capabilities      map[string]json.RawMessage `json:"capabilities"`
	Instructions      string                     `json:"instructions,omitempty"`
	Tools             []Tool                     `json:"tools"`
	Prompts           []Item                     `json:"prompts,omitempty"`
	ResourceTemplates []Item                     `json:"resourceTemplates,omitempty"`
}

// ServerInfo is the server's self-description from initialize.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Tool is a tool as the server lists it.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations *Annotations    `json:"annotations,omitempty"`
}

// Annotations are the MCP tool annotations: hints from the server, not
// guarantees.
type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Item is a prompt or resource template.
type Item struct {
	Name        string `json:"name"`
	URITemplate string `json:"uriTemplate,omitempty"`
	Description string `json:"description,omitempty"`
}

// Probe initializes the server on rw and lists its tools, prompts and
// resource templates (those its capabilities announce). Requests from the
// server are answered (ping) or refused; notifications are ignored. rw is
// closed when ctx ends, which ends a probe that hangs.
func Probe(ctx context.Context, rw io.ReadWriteCloser) (*Result, error) {
	s, res, err := Open(ctx, rw)
	if err != nil {
		return nil, err
	}
	s.Close()
	return res, nil
}

// Session is an initialized server, open for tool calls.
type Session struct {
	ctx  context.Context
	c    *client
	stop chan struct{}
}

// Open initializes the server on rw and lists what it offers, like Probe,
// and keeps the session open for calls. rw is closed when ctx ends; Close
// ends the session without closing rw.
func Open(ctx context.Context, rw io.ReadWriteCloser) (*Session, *Result, error) {
	return open(ctx, rw, false)
}

// open is Open; legacy skips the server/discover probe.
func open(ctx context.Context, rw io.ReadWriteCloser, legacy bool) (*Session, *Result, error) {
	s := &Session{ctx: ctx, c: &client{conn: jsonrpc.NewConn(rw), legacy: legacy}, stop: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = rw.Close()
		case <-s.stop:
		}
	}()
	res, err := s.c.probe()
	if errors.Is(err, ErrProbeEnded) {
		s.Close()
		return nil, nil, err
	}
	if err != nil {
		s.Close()
		return nil, nil, s.explain(err)
	}
	return s, res, nil
}

// Close ends the session.
func (s *Session) Close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// explain words an error that came from the session ending.
func (s *Session) explain(err error) error {
	switch {
	case s.ctx.Err() != nil:
		return fmt.Errorf("no answer from the server: %w", s.ctx.Err())
	case errors.Is(err, io.EOF):
		return fmt.Errorf("%w: the server exited or closed its output (see its messages above)", err)
	}
	return err
}

// CallResult is the outcome of a tool call that the server answered.
type CallResult struct {
	// IsError: the tool reported an error (isError), or the server
	// answered with a JSON-RPC error.
	IsError bool `json:"is_error"`
	// Text is the text content of the result (or the error message).
	Text string `json:"text"`
}

// Call calls a tool. An error means the session failed (the server
// exited or did not answer in time); a tool error is a CallResult.
func (s *Session) Call(tool string, args map[string]any) (CallResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	raw, err := s.c.call("tools/call", map[string]any{"name": tool, "arguments": args})
	var rpcErr *jsonrpc.Error
	if errors.As(err, &rpcErr) {
		return CallResult{IsError: true, Text: rpcErr.Message}, nil
	}
	if err != nil {
		return CallResult{}, s.explain(err)
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return CallResult{}, fmt.Errorf("tools/call %s: %w", tool, err)
	}
	var texts []string
	for _, c := range res.Content {
		if c.Type == "text" {
			texts = append(texts, c.Text)
		}
	}
	return CallResult{IsError: res.IsError, Text: strings.Join(texts, "\n")}, nil
}

type client struct {
	conn   *jsonrpc.Conn
	nextID int
	// legacy skips the server/discover probe; modern is set for a server
	// that answered it (requests then carry the protocol fields in
	// _meta).
	legacy, modern bool
}

// discover probes the server with server/discover (MCP 2026-07-28). It
// returns its result in the form of an initialize result for a server
// that speaks modernVersion, nil for a legacy server (any other error).
func (c *client) discover() (*Result, error) {
	raw, err := c.call("server/discover", map[string]any{})
	var rpcErr *jsonrpc.Error
	switch {
	case errors.As(err, &rpcErr):
		if rpcErr.Code == -32022 || rpcErr.Code == -32021 || rpcErr.Code == -32020 {
			return nil, fmt.Errorf("server/discover: %s %s", rpcErr.Message, rpcErr.Data)
		}
		return nil, nil
	case errors.Is(err, io.EOF):
		return nil, ErrProbeEnded
	case err != nil:
		return nil, err
	}
	var d struct {
		SupportedVersions []string                   `json:"supportedVersions"`
		Capabilities      map[string]json.RawMessage `json:"capabilities"`
		Instructions      string                     `json:"instructions"`
		Meta              struct {
			ServerInfo ServerInfo `json:"io.modelcontextprotocol/serverInfo"`
		} `json:"_meta"`
	}
	if json.Unmarshal(raw, &d) != nil || len(d.SupportedVersions) == 0 {
		return nil, nil
	}
	if !slices.Contains(d.SupportedVersions, modernVersion) {
		return nil, fmt.Errorf("the server speaks MCP %s, the gateway %s and earlier", strings.Join(d.SupportedVersions, ", "), modernVersion)
	}
	c.modern = true
	return &Result{Server: d.Meta.ServerInfo, ProtocolVersion: modernVersion, Capabilities: d.Capabilities,
		Instructions: d.Instructions, Tools: []Tool{}}, nil
}

func (c *client) probe() (*Result, error) {
	if !c.legacy {
		res, err := c.discover()
		if err != nil {
			return nil, err
		}
		if res != nil {
			return c.lists(res)
		}
	}
	raw, err := c.call("initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp-gateway-inspect", "version": version.Version},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var init struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ServerInfo      ServerInfo                 `json:"serverInfo"`
		Instructions    string                     `json:"instructions"`
	}
	if err := json.Unmarshal(raw, &init); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	n, err := jsonrpc.NewNotification("notifications/initialized", map[string]any{})
	if err != nil {
		return nil, err
	}
	if err := c.conn.Write(n); err != nil {
		return nil, err
	}
	return c.lists(&Result{
		Server:          init.ServerInfo,
		ProtocolVersion: init.ProtocolVersion,
		Capabilities:    init.Capabilities,
		Instructions:    init.Instructions,
		Tools:           []Tool{},
	})
}

// lists adds what the server's capabilities announce to res.
func (c *client) lists(res *Result) (*Result, error) {
	init := res
	if _, ok := init.Capabilities["tools"]; ok {
		if err := c.list("tools/list", "tools", &res.Tools); err != nil {
			return nil, err
		}
	}
	if _, ok := init.Capabilities["prompts"]; ok {
		if err := c.list("prompts/list", "prompts", &res.Prompts); err != nil {
			return nil, err
		}
	}
	if _, ok := init.Capabilities["resources"]; ok {
		if err := c.list("resources/templates/list", "resourceTemplates", &res.ResourceTemplates); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// list fetches all pages of a list method, appending the items under
// field to out (a pointer to a slice).
func (c *client) list(method, field string, out any) error {
	var all []json.RawMessage
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.call(method, params)
		if err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		var res map[string]json.RawMessage
		if err := json.Unmarshal(raw, &res); err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		var items []json.RawMessage
		if len(res[field]) > 0 {
			if err := json.Unmarshal(res[field], &items); err != nil {
				return fmt.Errorf("%s: %w", method, err)
			}
		}
		all = append(all, items...)
		cursor = ""
		_ = json.Unmarshal(res["nextCursor"], &cursor)
		if cursor == "" {
			break
		}
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// call sends a request and waits for its response.
func (c *client) call(method string, params map[string]any) (json.RawMessage, error) {
	if c.modern || method == "server/discover" {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    modernVersion,
			"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "mcp-gateway-inspect", "version": version.Version},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}
	}
	c.nextID++
	id := json.RawMessage(strconv.Itoa(c.nextID))
	req, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	if err := c.conn.Write(req); err != nil {
		return nil, err
	}
	for {
		m, err := c.conn.Read()
		if err != nil {
			return nil, err
		}
		switch {
		case m.IsResponse() && m.Key() == string(id):
			if m.Error != nil {
				return nil, m.Error
			}
			return m.Result, nil
		case m.IsRequest():
			if err := c.answer(m); err != nil {
				return nil, err
			}
		}
	}
}

// answer replies to a request from the server: ping succeeds, anything
// else (sampling, elicitation, roots) is refused.
func (c *client) answer(m *jsonrpc.Message) error {
	if m.Method == "ping" {
		r, err := jsonrpc.NewResult(m.ID, map[string]any{})
		if err != nil {
			return err
		}
		return c.conn.Write(r)
	}
	return c.conn.Write(jsonrpc.NewError(m.ID, -32601, "not supported while inspecting"))
}
