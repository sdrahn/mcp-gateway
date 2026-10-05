// Command server is a test MCP server built with the official Go SDK
// that speaks only MCP 2026-07-28, for e2e/servers_test.go: over stdio,
// or Streamable HTTP with -http.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "go-sdk-test", Version: "1"},
		&mcp.ServerOptions{SupportedProtocolVersions: []string{"2026-07-28"}})

	type echoArgs struct {
		Text string `json:"text"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echo the text"},
		func(_ context.Context, _ *mcp.CallToolRequest, a echoArgs) (*mcp.CallToolResult, any, error) {
			return text("go echo: " + a.Text), nil, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "protocol", Description: "the protocol version of this request"},
		func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			v, _ := req.Params.GetMeta()["io.modelcontextprotocol/protocolVersion"].(string)
			return text(v), nil, nil
		})

	// Input from the client (multi round-trip): a form asking for a name.
	mcp.AddTool(s, &mcp.Tool{Name: "ask_name", Description: "ask the user for their name"},
		func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			resp, ok := req.Params.InputResponses["name"].(*mcp.ElicitResult)
			if !ok {
				return &mcp.CallToolResult{
					InputRequests: mcp.InputRequestMap{"name": &mcp.ElicitParams{
						Message: "Your name?",
						RequestedSchema: map[string]any{"type": "object",
							"properties": map[string]any{"name": map[string]any{"type": "string"}}, "required": []string{"name"}},
					}},
					RequestState: "asked",
				}, nil, nil
			}
			if resp.Action != "accept" || req.Params.RequestState != "asked" {
				return text("go: no name (" + resp.Action + ")"), nil, nil
			}
			return text("go: hello " + resp.Content["name"].(string)), nil, nil
		})

	// A parameter mirrored into a header (Mcp-Param-Region over HTTP).
	s.AddTool(&mcp.Tool{Name: "region", Description: "query a region", InputSchema: json.RawMessage(
		`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"query":{"type":"string"}},"required":["region"]}`)},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct{ Region, Query string }
			_ = json.Unmarshal(req.Params.Arguments, &a)
			return text("go region " + a.Region + ": " + a.Query), nil
		})
	return s
}

func main() {
	addr := flag.String("http", "", "serve Streamable HTTP at this address (path /mcp) instead of stdio")
	flag.Parse()
	s := newServer()
	if *addr == "" {
		if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
		return
	}
	mux := http.NewServeMux()
	// The SDK serves 2026-07-28 over HTTP only without sessions.
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true}))
	log.Fatal(http.ListenAndServe(*addr, mux))
}
