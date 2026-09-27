// Command mcp-fs-demo is a minimal stdio MCP server used to demonstrate and
// test mcp-gateway. Below --root it offers the tools list_dir, read_file,
// write_file and delete_file, the files in the root as resources (plus a
// file:// template), and a summarize_file prompt. It does no access
// control of its own beyond staying inside the root: that is the gateway's
// job.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var root string

func main() {
	flag.StringVar(&root, "root", ".", "directory the tools operate in")
	flag.Parse()
	var err error
	if root, err = filepath.Abs(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 16<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var m message
		if json.Unmarshal(in.Bytes(), &m) != nil || m.Method == "" || len(m.ID) == 0 {
			continue // notifications and junk
		}
		res, rerr := handle(m.Method, m.Params)
		resp := message{JSONRPC: "2.0", ID: m.ID, Result: res, Error: rerr}
		if rerr != nil {
			resp.Result = nil
		}
		_ = out.Encode(resp)
	}
}

func schema(props ...string) map[string]any {
	p := map[string]any{}
	for _, name := range props {
		p[name] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": p, "required": props}
}

func handle(method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = "2025-06-18"
		}
		return map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
			"serverInfo":      map[string]any{"name": "mcp-fs-demo", "version": "0.1.0"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": []map[string]any{
			{"name": "list_dir", "description": "List a directory", "inputSchema": schema("path"),
				"annotations": map[string]any{"readOnlyHint": true}},
			{"name": "read_file", "description": "Read a file", "inputSchema": schema("path"),
				"annotations": map[string]any{"readOnlyHint": true}},
			{"name": "write_file", "description": "Write a file", "inputSchema": schema("path", "content"),
				"annotations": map[string]any{"destructiveHint": true}},
			{"name": "delete_file", "description": "Delete a file", "inputSchema": schema("path"),
				"annotations": map[string]any{"destructiveHint": true}},
		}}, nil
	case "tools/call":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		text, err := call(p.Name, p.Arguments)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		return toolResult(text, false), nil
	case "resources/list":
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, &rpcError{-32603, err.Error()}
		}
		resources := []map[string]any{}
		for _, e := range entries {
			if e.Type().IsRegular() {
				resources = append(resources, map[string]any{
					"uri": "file://" + filepath.Join(root, e.Name()), "name": e.Name(), "mimeType": "text/plain",
				})
			}
		}
		return map[string]any{"resources": resources}, nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": []map[string]any{
			{"uriTemplate": "file://" + root + "/{path}", "name": "file", "mimeType": "text/plain"},
		}}, nil
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(params, &p); err != nil || !strings.HasPrefix(p.URI, "file://") {
			return nil, &rpcError{-32602, "invalid params"}
		}
		path, err := resolve(strings.TrimPrefix(p.URI, "file://"))
		if err != nil {
			return nil, &rpcError{-32002, "resource not found"}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, &rpcError{-32002, "resource not found"}
		}
		return map[string]any{"contents": []map[string]any{{"uri": p.URI, "mimeType": "text/plain", "text": string(b)}}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []map[string]any{{
			"name": "summarize_file", "description": "Summarize a file",
			"arguments": []map[string]any{{"name": "path", "required": true}},
		}}}, nil
	case "prompts/get":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name != "summarize_file" {
			return nil, &rpcError{-32602, "unknown prompt"}
		}
		return map[string]any{"messages": []map[string]any{{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": "Summarize the file at " + p.Arguments["path"] + "."},
		}}}, nil
	}
	return nil, &rpcError{-32601, "method not found"}
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
}

// resolve maps a path argument (absolute, or relative to the root) to a
// path inside the root.
func resolve(p string) (string, error) {
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	p = filepath.Clean(p)
	if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return "", errors.New("path outside root")
	}
	return p, nil
}

func call(name string, args map[string]string) (string, error) {
	path, err := resolve(args["path"])
	if err != nil {
		return "", err
	}
	switch name {
	case "list_dir":
		entries, err := os.ReadDir(path)
		if err != nil {
			return "", err
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		return strings.Join(names, "\n"), nil
	case "read_file":
		b, err := os.ReadFile(path)
		return string(b), err
	case "write_file":
		if err := os.WriteFile(path, []byte(args["content"]), 0o644); err != nil {
			return "", err
		}
		return "wrote " + path, nil
	case "delete_file":
		if err := os.Remove(path); err != nil {
			return "", err
		}
		return "deleted " + path, nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}
