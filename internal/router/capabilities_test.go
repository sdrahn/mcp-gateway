package router

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

func nobody() principal.Principal {
	p := alice()
	p.Sub = "nobody"
	return p
}

// gateway_capabilities is in an aggregated session's tool list, as
// policy decides, and says per server what the principal may use: the
// server's instructions (from shared discovery) and its tools.
func TestCapabilitiesTool(t *testing.T) {
	r, _ := sharedRouter(t)
	r.Backends["gateway-docs"] = &config.Backend{Name: "gateway-docs", Discovery: config.DiscoveryInstance}
	c := connect(t, r, alice(), "", nil)

	got := names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
	if !slices.Contains(got, capabilitiesTool) {
		t.Fatalf("tools %v", got)
	}
	text, isErr := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": capabilitiesTool}))
	if isErr {
		t.Fatalf("error: %s", text)
	}
	for _, want := range []string{
		// Shared discovery: the discovery instance's instructions.
		"## fs (3 tools)\nThe fs server serves files of mcp-discovery. Paths are absolute.\n- fs__read_file",
		// Instance discovery: those of alice's own instance.
		"## git (3 tools)\nThe git server serves files of alice. Paths are absolute.\n- git__read_file",
		"- /usr/share/mcp-gateway/docs: ", "Anything no tool above reaches",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "## gateway_capabilities") || strings.Contains(text, "/usr/etc") {
		t.Errorf("lists itself or /usr/etc:\n%s", text)
	}
}

// A server whose command names the principal (${HOME}) tells each
// principal about its own files: its instructions come from the
// principal's instance, not from the shared discovery instance, which
// runs for no one (home /).
func TestCapabilitiesPerPrincipal(t *testing.T) {
	r, _ := sharedRouter(t)
	r.Backends["fs"].Command = []string{"/usr/libexec/mcp-servers/mcp-server-fs", "--root", "${HOME}"}
	c := connect(t, r, alice(), "", nil)
	text, isErr := toolText(t, c.roundTrip(1, "tools/call", map[string]any{"name": capabilitiesTool}))
	if isErr || !strings.Contains(text, "## fs (3 tools)\nThe fs server serves files of alice.") || strings.Contains(text, "mcp-discovery") {
		t.Fatalf("got %q", text)
	}
}

// A principal whom policy does not allow it neither sees nor calls it; a
// session with one server has no such tool.
func TestCapabilitiesToolDenied(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, nobody(), "", nil)
	if got := names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name"); slices.Contains(got, capabilitiesTool) {
		t.Fatalf("tools %v", got)
	}
	if text, isErr := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": capabilitiesTool})); !isErr || text != "mcp-gateway: not yours" {
		t.Fatalf("call: %q %v", text, isErr)
	}

	single := connect(t, r, alice(), "fs", nil)
	if got := names(t, single.roundTrip(1, "tools/list", map[string]any{}), "tools", "name"); slices.Contains(got, capabilitiesTool) {
		t.Fatalf("single server tools %v", got)
	}
}

func instructions(t *testing.T, c *client) string {
	t.Helper()
	var res struct{ Instructions string }
	if err := json.Unmarshal(c.init.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res.Instructions
}

// An aggregated session's instructions point to gateway_capabilities, a
// fixed text that asks no server; a server endpoint's are the server's.
func TestInstructionsPointToCapabilities(t *testing.T) {
	r, l := sharedRouter(t)
	if got := instructions(t, connect(t, r, alice(), "", nil)); !strings.Contains(got, "Call "+capabilitiesTool+" to see what your roles allow") {
		t.Errorf("instructions %q", got)
	}
	if n := len(l.started("fs")); n != 0 {
		t.Errorf("initialize started %d fs instances", n)
	}
	if got := instructions(t, connect(t, r, alice(), "fs", nil)); strings.Contains(got, capabilitiesTool) {
		t.Errorf("server endpoint instructions %q", got)
	}
}
