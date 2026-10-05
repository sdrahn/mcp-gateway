package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/mcpheader"
)

// Modern servers (MCP 2026-07-28) have no initialize and no session: the
// gateway puts the protocol version into each request's _meta, and the
// connector mirrors it, the method, the name and the parameters a tool
// marks with x-mcp-header into HTTP headers.

const (
	metaPrefix          = "io.modelcontextprotocol/"
	metaProtocolVersion = metaPrefix + "protocolVersion"
	codeHeaderMismatch  = -32020
)

// params is what the connector looks at in a request's params.
type params struct {
	Name      string                     `json:"name"`
	URI       string                     `json:"uri"`
	RequestID json.RawMessage            `json:"requestId"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta"`
}

// modernRequest is a request to a modern server: its headers, and what
// is needed to build them again after the server's tools changed.
type modernRequest struct {
	method  string
	params  params
	version string
	header  http.Header
	retried bool // after a HeaderMismatch
}

// modernVersion returns the protocol version in the request's _meta, or
// "" for a request of the legacy protocol.
func (p params) modernVersion() string {
	var v string
	_ = json.Unmarshal(p.Meta[metaProtocolVersion], &v)
	return v
}

func newModernRequest(method string, p params, version string) *modernRequest {
	h := http.Header{}
	h.Set("MCP-Protocol-Version", version)
	h.Set("Mcp-Method", method)
	switch method {
	case "tools/call", "prompts/get":
		h.Set("Mcp-Name", mcpheader.Encode(p.Name))
	case "resources/read":
		h.Set("Mcp-Name", mcpheader.Encode(p.URI))
	}
	return &modernRequest{method: method, params: p, version: version, header: h}
}

// tools checks the tools of a tools/list result: it drops those whose
// x-mcp-header annotations are invalid, as the specification asks, and
// remembers the headers of the others. It returns the result to relay.
func (c *connector) tools(result json.RawMessage) json.RawMessage {
	var r map[string]json.RawMessage
	var list []json.RawMessage
	if json.Unmarshal(result, &r) != nil || json.Unmarshal(r["tools"], &list) != nil {
		return result
	}
	kept := list[:0:0]
	c.mu.Lock()
	if c.schemas == nil {
		c.schemas = map[string][]mcpheader.Param{}
	}
	for _, raw := range list {
		var t struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		_ = json.Unmarshal(raw, &t)
		headers, err := mcpheader.ToolParams(t.InputSchema)
		if err != nil {
			c.log.Warn("tool left out: invalid x-mcp-header", "tool", t.Name, "err", err)
			delete(c.schemas, t.Name)
			continue
		}
		c.schemas[t.Name] = headers
		kept = append(kept, raw)
	}
	c.mu.Unlock()
	if len(kept) == len(list) {
		return result
	}
	r["tools"], _ = json.Marshal(kept)
	out, err := json.Marshal(r)
	if err != nil {
		return result
	}
	return out
}

// toolsAnswer applies tools to the result of a tools/list answer.
func (c *connector) toolsAnswer(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m["result"] == nil {
		return raw
	}
	m["result"] = c.tools(m["result"])
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// toolHeadersFor returns the parameter headers of the tool r calls,
// listing the server's tools first when the tool is not known.
func (c *connector) toolHeadersFor(ctx context.Context, r *modernRequest) []mcpheader.Param {
	known := func() ([]mcpheader.Param, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		headers, ok := c.schemas[r.params.Name]
		return headers, ok
	}
	if headers, ok := known(); ok {
		return headers
	}
	c.listMu.Lock()
	defer c.listMu.Unlock()
	if headers, ok := known(); ok { // listed meanwhile
		return headers
	}
	if err := c.listTools(ctx, r); err != nil {
		c.log.Warn("listing the server's tools for their x-mcp-header parameters", "err", err)
	}
	headers, _ := known()
	return headers
}

// listTools lists the server's tools (all pages) for their headers, with
// the protocol metadata of the request r; the caller holds listMu.
func (c *connector) listTools(ctx context.Context, r *modernRequest) error {
	meta := map[string]json.RawMessage{}
	for k, v := range r.params.Meta {
		if strings.HasPrefix(k, metaPrefix) {
			meta[k] = v
		}
	}
	cursor := ""
	for range 100 {
		p := map[string]any{"_meta": meta}
		if cursor != "" {
			p["cursor"] = cursor
		}
		c.mu.Lock()
		c.listSeq++
		id := "connector-tools-" + strconv.Itoa(c.listSeq)
		c.mu.Unlock()
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": p})
		if err != nil {
			return err
		}
		answer, err := c.ask(ctx, body, strconv.Quote(id), newModernRequest("tools/list", params{}, r.version).header)
		if err != nil {
			return err
		}
		var a struct {
			Result *struct {
				NextCursor string `json:"nextCursor"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(answer, &a); err != nil {
			return err
		}
		if a.Error != nil {
			return errors.New(a.Error.Message)
		}
		c.toolsAnswer(answer)
		if a.Result == nil || a.Result.NextCursor == "" {
			return nil
		}
		cursor = a.Result.NextCursor
	}
	return errors.New("more than 100 pages of tools")
}

// ask posts a request of the connector's own and returns the answer.
func (c *connector) ask(ctx context.Context, body []byte, id string, header http.Header) (json.RawMessage, error) {
	resp, err := c.do(ctx, body, header)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var answer json.RawMessage
	switch ct := resp.Header.Get("Content-Type"); {
	case resp.StatusCode/100 != 2:
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %s: %s", resp.Status, bytes.TrimSpace(data))
	case strings.HasPrefix(ct, "text/event-stream"):
		readEvents(resp.Body, func(data []byte) bool {
			var m message
			if json.Unmarshal(data, &m) == nil && m.Method == "" && idKey(m.ID) == id {
				answer = append(json.RawMessage(nil), data...)
				return true
			}
			return false
		})
	case strings.HasPrefix(ct, "application/json"):
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxLine+1))
		if err != nil || len(data) > maxLine {
			return nil, fmt.Errorf("reading the answer: %v", err)
		}
		answer = data
	default:
		return nil, fmt.Errorf("unexpected Content-Type %q", ct)
	}
	if answer == nil {
		return nil, errors.New("no answer")
	}
	return answer, nil
}

// errorAnswer returns the JSON-RPC error in the body of an HTTP error
// status, with the request's id, and its code; nil if there is none.
func errorAnswer(body []byte, id json.RawMessage) (json.RawMessage, int) {
	var m struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	var all map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil || m.Error == nil || json.Unmarshal(body, &all) != nil {
		return nil, 0
	}
	all["id"] = id
	out, err := json.Marshal(all)
	if err != nil {
		return nil, 0
	}
	return out, m.Error.Code
}

// track registers the cancellation of a request to a modern server: the
// gateway's notifications/cancelled closes its stream.
func (c *connector) track(id string, cancel context.CancelFunc) func() {
	c.mu.Lock()
	if c.inflight == nil {
		c.inflight = map[string]context.CancelFunc{}
	}
	c.inflight[id] = cancel
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.inflight, id)
		c.mu.Unlock()
	}
}

// cancelled handles the gateway's notifications/cancelled for a request
// to a modern server: closing the request's stream is the cancellation.
func (c *connector) cancelled(p params) {
	c.mu.Lock()
	cancel := c.inflight[idKey(p.RequestID)]
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
