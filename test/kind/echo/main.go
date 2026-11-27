// Command echo is a server that speaks Streamable HTTP (JSON responses)
// with one tool, echo, for the kind test of the container image
// (test/kind/run.sh). It counts the calls it answers, so the test sees
// that a call ran once.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

func main() {
	var calls atomic.Int64
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if m.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any = map[string]any{}
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "echo", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "echo", "inputSchema": map[string]any{
				"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}}}}}
		case "tools/call":
			n := calls.Add(1)
			result = map[string]any{"content": []any{map[string]any{"type": "text",
				"text": fmt.Sprintf("echo: %v (call %d)", m.Params.Arguments["text"], n)}}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
