package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// serveHTTP is privsrv's other mode (privsrv -http ADDR): an MCP server
// that speaks Streamable HTTP, for the VM test of servers defined with
// url (cmd/mcp-http-connector). Its one tool, whoami, answers with the
// Authorization header it got, so the test sees the credential arrive;
// tools/call answers on an event stream, the rest as JSON.
func serveHTTP(addr string) error {
	return http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m message
		if json.Unmarshal(body, &m) != nil || len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var res any
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "vmtest")
			res = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "privsrv-http"}}
		case "tools/list":
			res = map[string]any{"tools": []any{map[string]any{"name": "whoami", "inputSchema": schema()}}}
		case "tools/call":
			if r.Header.Get("Mcp-Session-Id") != "vmtest" {
				http.Error(w, "no session", http.StatusBadRequest)
				return
			}
			out, _ := json.Marshal(message{JSONRPC: "2.0", ID: m.ID, Result: map[string]any{
				"content": []any{map[string]any{"type": "text", "text": "authorization: " + r.Header.Get("Authorization")}}}})
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "id: 1\ndata: %s\n\n", out)
			return
		default:
			res = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(message{JSONRPC: "2.0", ID: m.ID, Result: res})
	}))
}
