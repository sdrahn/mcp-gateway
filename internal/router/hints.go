package router

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// Tool descriptions tell the agent what the principal's roles allow
// (policy/mcp/filter.rego, hints) and the administrator's notes on the
// tool (tool_notes in its server definition), so that it does not have
// to find out by trying (docs/architecture.md, roadmap step 29). Advice
// only: every call is still decided.

// itemKey identifies an item of a list.
type itemKey struct{ server, kind, name string }

// toolHints asks the policy for hints on the visible tools; none if the
// policy has none or cannot be asked (the list is shown without them).
func (s *Session) toolHints(ctx context.Context, resources []pep.Resource, visible map[itemKey]bool) map[itemKey]*pep.Hint {
	out := map[itemKey]*pep.Hint{}
	h, ok := s.r.PDP.(pep.Hinter)
	if !ok {
		return out
	}
	var rs []pep.Resource
	for _, r := range resources {
		if visible[itemKey{r.Server, r.Kind, r.Name}] {
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 {
		return out
	}
	hints, err := h.Hints(ctx, s.snapshotPrincipal(), rs)
	if err != nil {
		s.log.Warn("tool hints failed; listing without them", "err", err)
		return out
	}
	for i := range hints {
		out[itemKey{hints[i].Server, "tool", hints[i].Name}] = &hints[i]
	}
	return out
}

// approvalChannels says where each approval channel asks.
var approvalChannels = map[string]string{
	"form": "in a dialog of your client",
	"url":  "on the approval page, which your client offers to open",
	"oob":  "out of band (Cockpit, a desktop notification or mail); the call waits for it",
}

// hintText is the line added to a tool's description, or "" for none.
func hintText(h *pep.Hint, note string) string {
	var parts []string
	if h != nil && len(h.Args) > 0 {
		alts := make([]string, 0, len(h.Args))
		for _, args := range h.Args {
			alts = append(alts, argsText(args))
		}
		parts = append(parts, "According to your roles, calls need "+strings.Join(alts, ", or ")+".")
	}
	if h != nil && h.Approval != "" {
		where := approvalChannels[h.Approval]
		if where == "" {
			where = "(" + h.Approval + ")"
		}
		parts = append(parts, "Each call needs a human approval, "+where+".")
	}
	if note = strings.TrimSpace(note); note != "" {
		parts = append(parts, "Administrator's note: "+note)
	}
	if len(parts) == 0 {
		return ""
	}
	return "[mcp-gateway] " + strings.Join(parts, " ")
}

// argsText describes the constraints of one permission: "path starting
// with /home/alice/ and mode exactly ro".
func argsText(args map[string]string) string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(args)) {
		out = append(out, name+" "+patternText(args[name]))
	}
	return strings.Join(out, " and ")
}

// patternText describes a regular expression in words where it is a
// plain prefix or a plain value, and quotes it otherwise.
func patternText(p string) string {
	if rest, ok := strings.CutPrefix(p, "^"); ok {
		exact := false
		if strings.HasSuffix(rest, "$") && !strings.HasSuffix(rest, `\$`) {
			rest, exact = strings.TrimSuffix(rest, "$"), true
		}
		if lit, ok := literal(rest); ok && lit != "" {
			if exact {
				return "exactly " + lit
			}
			return "starting with " + lit
		}
	}
	return "matching the regular expression " + p
}

// literal returns the text a regular expression without metacharacters
// matches (escapes resolved), and whether it is one.
func literal(re string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(re); i++ {
		c := re[i]
		switch {
		case c == '\\' && i+1 < len(re) && strings.IndexByte(`.+*?()|[]{}^$\/-`, re[i+1]) >= 0:
			i++
			b.WriteByte(re[i])
		case strings.IndexByte(`.+*?()|[]{}^$\`, c) >= 0:
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// describe appends text to a tool description.
func describe(desc, text string) string {
	if text == "" {
		return desc
	}
	if desc == "" {
		return text
	}
	return desc + "\n\n" + text
}

// gatewayFiles are where the gateway's configuration and documentation
// lie; agents try to read them through other servers' file tools.
var gatewayFiles = []struct{ prefix, server, advice string }{
	{"/etc/mcp-gateway", "gateway-admin", "the gateway's configuration is shown by the gateway-admin server's show_config, not by other servers"},
	{"/usr/etc/mcp-gateway", "gateway-admin", "the gateway's configuration is shown by the gateway-admin server's show_config, not by other servers"},
	{"/usr/share/mcp-gateway/docs", "gateway-docs", "the gateway's documentation is on the gateway-docs server (search_text, read_text_file)"},
	{"/usr/share/mcp-gateway", "gateway-admin", "the gateway's configuration is shown by the gateway-admin server's show_config, not by other servers"},
}

// withAdvice adds to a denial's reason where to look instead, when a
// string argument names the gateway's own files and the server for them
// is defined (and is not the one called), whether or not the session
// reaches it.
func withAdvice(reason string, t *callTarget, backends map[string]*config.Backend) string {
	if t == nil || t.action != "tools.call" {
		return reason
	}
	for _, name := range slices.Sorted(maps.Keys(t.args)) {
		v, ok := t.args[name].(string)
		if !ok {
			continue
		}
		for _, f := range gatewayFiles {
			if !strings.HasPrefix(v, f.prefix) || t.server == f.server || backends[f.server] == nil {
				continue
			}
			if reason == "" {
				reason = "denied by policy"
			}
			return reason + "; " + f.advice
		}
	}
	return reason
}
