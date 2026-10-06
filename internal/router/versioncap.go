package router

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

// The MCP version per client (agents.max_version, roadmap step 26): a
// client named there is spoken to in that version at most. One capped
// below the modern version is answered as by a gateway without it, so
// that it falls back to initialize: server/discover is unknown, other
// modern requests name the versions it may use. The name is
// self-asserted (clientInfo); it chooses the protocol, never what is
// allowed.

// lowerKeys returns caps with its client names in lower case.
func lowerKeys(caps map[string]string) map[string]string {
	if len(caps) == 0 {
		return nil
	}
	out := make(map[string]string, len(caps))
	for name, v := range caps {
		out[strings.ToLower(strings.TrimSpace(name))] = v
	}
	return out
}

// versionCap returns the newest version the gateway speaks with the
// client named name, or "" if it is not capped.
func (r *Router) versionCap(name string) string {
	caps := r.settings().MaxVersion
	if len(caps) == 0 || name == "" {
		return ""
	}
	return caps[strings.ToLower(name)]
}

// cappedRequest refuses the modern request m of a client capped below
// the modern version, as a gateway without it would; nil if m may be
// served.
func (r *Router) cappedRequest(m *jsonrpc.Message) *jsonrpc.Error {
	var p struct {
		Meta struct {
			Client struct {
				Name string `json:"name"`
			} `json:"io.modelcontextprotocol/clientInfo"`
			Version string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	}
	_ = json.Unmarshal(m.Params, &p)
	c := r.versionCap(p.Meta.Client.Name)
	if c == "" || c >= modernVersion {
		return nil
	}
	if m.Method == "server/discover" {
		return &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"}
	}
	var supported []string // newest first, as agentVersions
	for _, v := range slices.Backward(config.AgentVersions) {
		if v <= c {
			supported = append(supported, v)
		}
	}
	data, _ := json.Marshal(map[string]any{"supported": supported, "requested": p.Meta.Version})
	return &jsonrpc.Error{Code: codeUnsupportedVersion, Message: fmt.Sprintf("unsupported protocol version %q", p.Meta.Version), Data: data}
}
