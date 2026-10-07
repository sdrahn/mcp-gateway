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
		"## fs (3 tools)\nThe fs server serves files. Paths are absolute.\n- fs__read_file",
		"## git (3 tools)\n- git__read_file", // instance discovery: no instructions
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

// An aggregated session's instructions name the servers the principal
// may use, with the first sentence of their instructions where shared
// discovery has them, and point to gateway_capabilities.
func TestOverviewInInstructions(t *testing.T) {
	r, _ := sharedRouter(t)
	got := instructions(t, connect(t, r, alice(), "", nil))
	for _, want := range []string{
		"Servers you may use: fs (3 tools: The fs server serves files); git (tools depend on your account); " +
			"tmp (tools depend on your account).",
		capabilitiesTool + " lists what your roles allow",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}

}

func TestOverviewBudget(t *testing.T) {
	r, _ := sharedRouter(t)
	for _, b := range r.Backends {
		b.Discovery = config.DiscoveryInstance
	}
	for i := range 200 {
		name := "server" + strings.Repeat("x", 20) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		r.Backends[name] = &config.Backend{Name: name, Discovery: config.DiscoveryInstance}
	}
	got := instructions(t, connect(t, r, alice(), "", nil))
	if !strings.Contains(got, " more."+" ") || !strings.Contains(got, capabilitiesTool) {
		t.Errorf("not cut: %q", got)
	}
	if len(got) > len(aggregatedInstructions(aggregatedEndpoint(r.Backends)))+overviewBudget {
		t.Errorf("over budget: %d", len(got))
	}
}

func TestFirstSentence(t *testing.T) {
	for in, want := range map[string]string{
		"":                                 "",
		"Reads files.":                     "Reads files",
		"Reads files. Paths are absolute.": "Reads files",
		"Reads\n  files. x":                "Reads files",
		"v1.2 reads files":                 "v1.2 reads files",
		strings.Repeat("é", 200):           strings.Repeat("é", 159) + "…",
	} {
		if got := firstSentence(in); got != want {
			t.Errorf("firstSentence(%q) = %q, want %q", in, got, want)
		}
	}
}
