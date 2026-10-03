package main

import (
	"context"
	"encoding/json"

	"github.com/sdrahn/mcp-gateway/internal/mcpserver"
)

// handle answers an MCP request (the protocol around it is
// internal/mcpserver's).
func (s *fileServer) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{
			"protocolVersion": mcpserver.Negotiate(p.ProtocolVersion),
			"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "title": "Files", "version": serverVersion},
			"instructions":    s.instructions(),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.toolList()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "invalid params"}
		}
		return s.call(ctx, p.Name, p.Arguments)
	case "resources/list":
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(params, &p)
		return s.resourceList(p.Cursor)
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": s.resourceTemplates()}, nil
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.URI == "" {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "invalid params"}
		}
		return s.readResource(p.URI)
	case "prompts/list":
		return map[string]any{"prompts": []map[string]any{{
			"name": "summarize_file", "title": "Summarize a file", "description": "Summarize a file",
			"arguments": []map[string]any{{"name": "path", "description": "the file", "required": true}},
		}}}, nil
	case "prompts/get":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name != "summarize_file" {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "unknown prompt"}
		}
		if p.Arguments["path"] == "" {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "argument path is required"}
		}
		return map[string]any{"messages": []map[string]any{{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": "Summarize the file at " + p.Arguments["path"] + "."},
		}}}, nil
	}
	return nil, &mcpserver.Error{Code: mcpserver.CodeMethodNotFound, Message: "method not found"}
}
