// Command compat-go is a compatibility test client: mcp-go, the library
// Kit uses, against the gateway, set up the way Kit sets it up (it asks
// for the newest protocol and declares task support). e2e/clients_test.go
// runs it once per scenario and checks the JSON it prints on stdout;
// test/clients/ts/client.mjs describes the scenarios and the environment
// (MCPGW_*; MCPGW_CA is the gateway's certificate).
//
// It is a module of its own so that the gateway does not depend on
// mcp-go.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

var (
	home       = os.Getenv("MCPGW_HOME")
	serverName string // from the initialize result
)

// listen opens the GET stream for notifications outside requests over
// HTTP (mcp-go's continuous listening; Kit does not turn it on, so over
// HTTP it learns of list changes only when it connects again).
var listen bool

func connect(ctx context.Context, opts ...client.ClientOption) (*client.Client, error) {
	var c *client.Client
	if os.Getenv("MCPGW_TRANSPORT") == "http" {
		pem, err := os.ReadFile(os.Getenv("MCPGW_CA"))
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		trOpts := []transport.StreamableHTTPCOption{
			transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + os.Getenv("MCPGW_TOKEN")}),
			transport.WithHTTPBasicClient(httpClient),
		}
		if listen {
			// Deprecated for 2026-07-28; the gateway speaks 2025-11-25, where
			// the GET stream carries notifications outside requests.
			trOpts = append(trOpts, transport.WithContinuousListening()) //nolint:staticcheck
		}
		tr, err := transport.NewStreamableHTTP(os.Getenv("MCPGW_URL"), trOpts...)
		if err != nil {
			return nil, err
		}
		c = client.NewClient(tr, opts...)
	} else {
		c = client.NewClient(transport.NewStdio(os.Getenv("MCPGW_CONNECT"), nil,
			"--socket", os.Getenv("MCPGW_SOCKET"), "--server", os.Getenv("MCPGW_SERVER")), opts...)
	}
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	// As Kit does (internal/tools/connection_pool.go).
	req := mcp.InitializeRequest{}
	req.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	name := os.Getenv("MCPGW_CLIENT_NAME")
	if name == "" {
		name = "compat-go"
	}
	req.Params.ClientInfo = mcp.Implementation{Name: name, Version: "1"}
	req.Params.Capabilities = mcp.ClientCapabilities{Tasks: mcp.NewTasksCapability()}
	res, err := c.Initialize(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	serverName = res.ServerInfo.Name
	return c, nil
}

func call(ctx context.Context, c *client.Client, name string, args map[string]any, meta *mcp.Meta) (*mcp.CallToolResult, error) {
	return c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args, Meta: meta}})
}

func text(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if t, ok := mcp.AsTextContent(c); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

func toolNames(ctx context.Context, c *client.Client) ([]string, error) {
	res, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range res.Tools {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out, nil
}

func ready() { fmt.Println(`{"ready":true}`) }

func basic(ctx context.Context) (map[string]any, error) {
	c, err := connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	out := map[string]any{"protocolVersion": c.ProtocolVersion()}
	if out["tools"], err = toolNames(ctx, c); err != nil {
		return nil, err
	}
	out["server"] = serverName
	// Kit sends task-augmented calls to servers that offer tasks; the
	// gateway does not.
	out["tasksOffered"] = c.GetServerCapabilities().Tasks != nil
	r, err := call(ctx, c, "read_file", map[string]any{"path": filepath.Join(home, "hello.txt")}, nil)
	if err != nil {
		return nil, err
	}
	out["read"] = text(r)
	if r, err := call(ctx, c, "delete_file", map[string]any{"path": filepath.Join(home, "hello.txt")}, nil); err != nil {
		out["denied"] = map[string]any{"error": err.Error()}
	} else {
		out["denied"] = map[string]any{"isError": r.IsError, "text": text(r)}
	}
	resources, err := c.ListResources(ctx, mcp.ListResourcesRequest{})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, res := range resources.Resources {
		names = append(names, res.Name)
		if res.Name == "hello.txt" {
			rr, err := c.ReadResource(ctx, mcp.ReadResourceRequest{Params: mcp.ReadResourceParams{URI: res.URI}})
			if err != nil {
				return nil, err
			}
			for _, ct := range rr.Contents {
				if t, ok := ct.(mcp.TextResourceContents); ok {
					out["resource"] = t.Text
				}
			}
		}
	}
	sort.Strings(names)
	out["resources"] = names
	prompts, err := c.ListPrompts(ctx, mcp.ListPromptsRequest{})
	if err != nil {
		return nil, err
	}
	var pnames []string
	for _, p := range prompts.Prompts {
		pnames = append(pnames, p.Name)
	}
	out["prompts"] = pnames
	return out, nil
}

func approval(ctx context.Context) (map[string]any, error) {
	c, err := connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	var mu sync.Mutex
	var logs []string
	progress := 0
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		mu.Lock()
		defer mu.Unlock()
		switch n.Method {
		case "notifications/message":
			b, _ := json.Marshal(n.Params.AdditionalFields["data"])
			var s string
			if json.Unmarshal(b, &s) != nil {
				s = string(b)
			}
			logs = append(logs, s)
		case "notifications/progress":
			progress++
		}
	})
	// On MCP 2026-07-28 log messages come only to requests that ask for
	// them (mcp-go then puts the level into each request).
	if err := c.SetLevel(ctx, mcp.SetLevelRequest{Params: mcp.SetLevelParams{Level: mcp.LoggingLevelInfo}}); err != nil {
		return nil, err
	}
	r, err := call(ctx, c, "write_file", map[string]any{"path": filepath.Join(home, "approved.txt"), "content": "ok"},
		&mcp.Meta{ProgressToken: "p-1"})
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	return map[string]any{"isError": r.IsError, "text": text(r), "logs": logs, "progress": progress}, nil
}

type acceptElicitation struct {
	mu    sync.Mutex
	asked []string
}

func (a *acceptElicitation) Elicit(_ context.Context, req mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	a.mu.Lock()
	a.asked = append(a.asked, req.Params.Message)
	a.mu.Unlock()
	scope := "once"
	var schema struct {
		Properties struct {
			Scope struct {
				Default string   `json:"default"`
				Enum    []string `json:"enum"`
			} `json:"scope"`
		} `json:"properties"`
	}
	if b, err := json.Marshal(req.Params.RequestedSchema); err == nil && json.Unmarshal(b, &schema) == nil {
		if s := schema.Properties.Scope; s.Default != "" {
			scope = s.Default
		} else if len(s.Enum) > 0 {
			scope = s.Enum[0]
		}
	}
	return &mcp.ElicitationResult{ElicitationResponse: mcp.ElicitationResponse{
		Action: mcp.ElicitationResponseActionAccept, Content: map[string]any{"scope": scope}}}, nil
}

func elicit(ctx context.Context) (map[string]any, error) {
	h := &acceptElicitation{}
	c, err := connect(ctx, client.WithElicitationHandler(h))
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	r, err := call(ctx, c, "write_file", map[string]any{"path": filepath.Join(home, "elicited.txt"), "content": "ok"}, nil)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return map[string]any{"isError": r.IsError, "text": text(r), "asked": h.asked}, nil
}

func listchanged(ctx context.Context) (map[string]any, error) {
	listen = true
	c, err := connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	changed, acked := make(chan struct{}, 1), make(chan struct{}, 1)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		ch := map[string]chan struct{}{"notifications/tools/list_changed": changed, "notifications/subscriptions/acknowledged": acked}[n.Method]
		if ch != nil {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	})
	if c.ProtocolVersion() == mcp.ProtocolVersion20260728 {
		// MCP 2026-07-28: changes come on a stream the client opens.
		stop, err := c.ListenAsync(ctx, mcp.SubscriptionFilter{ToolsListChanged: true}, nil)
		if err != nil {
			return nil, err
		}
		defer stop()
		select {
		case <-acked:
		case <-time.After(10 * time.Second):
			return nil, errors.New("subscriptions/listen not acknowledged")
		}
	}
	before, err := toolNames(ctx, c)
	if err != nil {
		return nil, err
	}
	ready()
	notified := false
	select {
	case <-changed:
		notified = true
	case <-time.After(20 * time.Second):
	}
	after, err := toolNames(ctx, c)
	if err != nil {
		return nil, err
	}
	return map[string]any{"before": before, "after": after, "notified": notified}, nil
}

func cancel(ctx context.Context) (map[string]any, error) {
	c, err := connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	callCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	_, err = call(callCtx, c, "write_file", map[string]any{"path": filepath.Join(home, "cancelled.txt"), "content": "no"}, nil)
	ready()
	time.Sleep(3 * time.Second)
	out := map[string]any{"cancelled": errors.Is(err, context.DeadlineExceeded)}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func main() {
	scenarios := map[string]func(context.Context) (map[string]any, error){
		"basic": basic, "approval": approval, "elicit": elicit, "listchanged": listchanged, "cancel": cancel,
	}
	if len(os.Args) != 2 || scenarios[os.Args[1]] == nil {
		fmt.Fprintln(os.Stderr, "usage: compat-go basic|approval|elicit|listchanged|cancel")
		os.Exit(2)
	}
	ctx, stop := context.WithTimeout(context.Background(), 80*time.Second)
	defer stop()
	out, err := scenarios[os.Args[1]](ctx)
	if err != nil {
		out = map[string]any{"fatal": err.Error()}
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	if err != nil {
		os.Exit(1)
	}
}
