package router

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// The gateway's own tool gateway_capabilities tells the agent of an
// aggregated session what the principal's roles allow
// (docs/architecture.md, roadmap step 29); the session's instructions
// point to it.
// Its name has no "__", so no server's tool can have it.

const capabilitiesTool = "gateway_capabilities"

// capabilitiesResource is the tool as policy sees it (policy/mcp/builtin.rego).
var capabilitiesResource = pep.Resource{Server: "mcp-gateway", Kind: "tool", Name: "capabilities", Builtin: true}

// maxCapabilities bounds the tool's text.
const maxCapabilities = 64 << 10

func capabilitiesItem() map[string]json.RawMessage {
	raw := map[string]json.RawMessage{}
	raw["name"], _ = json.Marshal(capabilitiesTool)
	raw["title"], _ = json.Marshal("What your roles allow")
	raw["description"], _ = json.Marshal("What the gateway lets you do: each server you may use, with its own instructions, " +
		"its tools and the limits your roles set on them (arguments, approvals), and where the gateway's own " +
		"configuration and documentation are. Call it when unsure which tool or server to use.")
	raw["inputSchema"] = json.RawMessage(`{"type":"object","properties":{}}`)
	raw["annotations"] = json.RawMessage(`{"readOnlyHint":true,"idempotentHint":true,"openWorldHint":false}`)
	return raw
}

// capabilities answers a call of gateway_capabilities, as policy decides.
func (s *Session) capabilities(ctx context.Context) (any, *jsonrpc.Error) {
	p := s.snapshotPrincipal()
	decisionID := newDecisionID()
	dec := pep.Evaluate(ctx, s.r.PDP, pep.Input{Principal: p, Action: "tools.call", Resource: capabilitiesResource,
		Context: s.policyContext(decisionID)})
	s.r.Audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: "tools.call", Server: capabilitiesResource.Server,
		Name: capabilitiesResource.Name, Effect: string(dec.Effect), Reason: dec.Reason, DecisionID: decisionID,
		Scopes: p.Scopes, OutsideScopes: dec.OutsideScopes})
	if dec.Effect != pep.Allow {
		if dec.OutsideScopes {
			return s.scopeDenial(ctx, "tools/call", dec)
		}
		return s.denial("tools/call", dec.Reason)
	}
	text, err := s.capabilitiesText(ctx)
	if err != nil {
		return nil, rpcError(jsonrpc.CodeInternalError, "mcp-gateway: "+err.Error())
	}
	return textResult(text), nil
}

// capabilitiesText lists the servers whose tools the principal sees, each
// with its instructions and its tools with their descriptions (which
// carry the limits of the principal's roles), and where the gateway's
// own files are.
func (s *Session) capabilitiesText(ctx context.Context) (string, error) {
	res, rpcErr := s.list(ctx, &jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: "tools/list"})
	if rpcErr != nil {
		return "", fmt.Errorf("listing the tools: %s", rpcErr.Message)
	}
	tools, _ := res.(map[string]any)["tools"].([]map[string]json.RawMessage)
	byServer := map[string][]string{}
	ep := s.endpoint()
	for _, t := range tools {
		var name, desc string
		_ = json.Unmarshal(t["name"], &name)
		_ = json.Unmarshal(t["description"], &desc)
		server, _, ok := ep.resolveName(name)
		if !ok {
			continue
		}
		line := "- " + name
		if desc != "" {
			line += ": " + strings.ReplaceAll(strings.TrimSpace(desc), "\n\n", " ")
		}
		byServer[server] = append(byServer[server], line)
	}
	var b strings.Builder
	b.WriteString("What your roles allow on this gateway. The limits in each tool's description are those of your roles; " +
		"every call is still decided, and some may need an approval.\n")
	for _, server := range ep.order {
		lines := byServer[server]
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s (%d tools)\n", server, len(lines))
		if instr := s.serverInstructions(ctx, ep.backends[server]); instr != "" {
			b.WriteString(strings.TrimSpace(instr) + "\n")
		}
		b.WriteString(strings.Join(lines, "\n") + "\n")
		if b.Len() > maxCapabilities {
			b.WriteString("\n(cut: too long; ask about one server at a time)\n")
			break
		}
	}
	if len(byServer) == 0 {
		b.WriteString("\nYour roles allow no tool of any server here.\n")
	}
	b.WriteString("\n## Not through these tools\n")
	for _, f := range gatewayFiles {
		if s.r.backends()[f.server] != nil && !strings.HasPrefix(f.prefix, "/usr/etc") {
			fmt.Fprintf(&b, "- %s: %s\n", f.prefix, f.advice)
		}
	}
	b.WriteString("- Anything no tool above reaches is not available to you through this gateway; ask its administrator.\n")
	return b.String(), nil
}

// serverInstructions are a server's own instructions, from the shared
// discovery instance where there is one ("" otherwise, or on error).
func (s *Session) serverInstructions(ctx context.Context, b *config.Backend) string {
	if b == nil || b.Discovery != config.DiscoveryShared || s.mustSignIn(b) {
		return ""
	}
	init, err := s.r.sharedInit(ctx, b)
	if err != nil {
		return ""
	}
	return init.Instructions
}
