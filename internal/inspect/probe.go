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
	"strconv"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// protocolVersion is the MCP version offered to the server (the one the
// gateway speaks to backends).
const protocolVersion = "2025-06-18"

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
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = rw.Close()
		case <-stop:
		}
	}()
	c := &client{conn: jsonrpc.NewConn(rw)}
	res, err := c.probe()
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("no answer from the server: %w", ctx.Err())
	case errors.Is(err, io.EOF):
		return nil, fmt.Errorf("%w: the server exited or closed its output (see its messages above)", err)
	}
	return res, err
}

type client struct {
	conn   *jsonrpc.Conn
	nextID int
}

func (c *client) probe() (*Result, error) {
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
	res := &Result{
		Server:          init.ServerInfo,
		ProtocolVersion: init.ProtocolVersion,
		Capabilities:    init.Capabilities,
		Instructions:    init.Instructions,
		Tools:           []Tool{},
	}
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
func (c *client) call(method string, params any) (json.RawMessage, error) {
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
