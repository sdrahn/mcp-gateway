package router

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Constraints in words where they are a plain prefix or value, quoted
// otherwise; approvals with their channel; the administrator's note.
func TestHintText(t *testing.T) {
	for _, c := range []struct {
		h    *pep.Hint
		note string
		want string
	}{
		{nil, "", ""},
		{&pep.Hint{}, "  ", ""},
		{&pep.Hint{Args: []map[string]string{{"path": "^/home/a\\.b/"}}}, "",
			"[mcp-gateway] According to your roles, calls need path starting with /home/a.b/."},
		{&pep.Hint{Args: []map[string]string{{"path": "^/(etc|usr/lib)/systemd/"}, {"path": "^/srv/$", "mode": "^ro$"}}}, "",
			"[mcp-gateway] According to your roles, calls need path matching the regular expression ^/(etc|usr/lib)/systemd/, " +
				"or mode exactly ro and path exactly /srv/."},
		{&pep.Hint{Approval: "oob"}, "",
			"[mcp-gateway] Each call needs a human approval, out of band (Cockpit, a desktop notification or mail); the call waits for it."},
		{&pep.Hint{Approval: "other"}, "from: RFC 3339",
			"[mcp-gateway] Each call needs a human approval, (other). Administrator's note: from: RFC 3339"},
		{nil, "from: RFC 3339", "[mcp-gateway] Administrator's note: from: RFC 3339"},
	} {
		if got := hintText(c.h, c.note); got != c.want {
			t.Errorf("hintText(%+v, %q):\n got %q\nwant %q", c.h, c.note, got, c.want)
		}
	}
	if got := describe("Reads a file.", "[mcp-gateway] x"); got != "Reads a file.\n\n[mcp-gateway] x" {
		t.Errorf("describe: %q", got)
	}
	if got := describe("", "[mcp-gateway] x"); got != "[mcp-gateway] x" {
		t.Errorf("describe without description: %q", got)
	}
}

// hintPDP gives hints for read_file (an argument constraint) and
// write_file (an approval); hintErr makes Hints fail.
type hintPDP struct {
	fakePDP
	asked   *[]pep.Resource
	hintErr bool
}

func (h hintPDP) Hints(_ context.Context, _ principal.Principal, rs []pep.Resource) ([]pep.Hint, error) {
	if h.hintErr {
		return nil, errors.New("no hints")
	}
	*h.asked = rs
	return []pep.Hint{
		{Server: "fs", Name: "read_file", Args: []map[string]string{{"path": "^/home/alice/"}}},
		{Server: "fs", Name: "write_file", Approval: "form"},
	}, nil
}

// tools/list descriptions carry the hints of the visible tools and the
// definition's tool notes; without hints (or when they fail) the list is
// as before.
func TestToolHintsInList(t *testing.T) {
	r, _ := testRouter(t, 0)
	var asked []pep.Resource
	r.PDP = hintPDP{asked: &asked}
	r.Backends["fs"].ToolNotes = map[string]string{"ask_roots": "asks the client for its roots"}
	c := connect(t, r, alice(), "fs", nil)

	desc := descriptions(t, c.roundTrip(1, "tools/list", map[string]any{}))
	if !strings.Contains(desc["read_file"], "calls need path starting with /home/alice/") ||
		!strings.Contains(desc["write_file"], "needs a human approval, in a dialog of your client") ||
		desc["ask_roots"] != "[mcp-gateway] Administrator's note: asks the client for its roots" {
		t.Fatalf("descriptions: %q", desc)
	}
	for _, rs := range asked {
		if rs.Name == "delete_file" {
			t.Errorf("hints asked for a hidden tool: %+v", asked)
		}
	}

	r2, _ := testRouter(t, 0)
	r2.PDP = hintPDP{hintErr: true}
	c2 := connect(t, r2, alice(), "fs", nil)
	for name, d := range descriptions(t, c2.roundTrip(1, "tools/list", map[string]any{})) {
		if d != "" {
			t.Errorf("%s: description %q without hints", name, d)
		}
	}
}

func descriptions(t *testing.T, m *jsonrpc.Message) map[string]string {
	t.Helper()
	out := map[string]string{}
	var res struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatalf("tools/list: %v (%+v)", err, m)
	}
	for _, tl := range res.Tools {
		out[tl.Name] = tl.Description
	}
	return out
}

// A denial of a call naming the gateway's files says where to look
// instead, if that server is defined and is not the one called.
func TestWithAdvice(t *testing.T) {
	backends := map[string]*config.Backend{"fs": {}, "gateway-admin": {}, "gateway-docs": {}}
	call := func(server string, args map[string]any) *callTarget {
		return &callTarget{server: server, action: "tools.call", args: args}
	}
	for _, c := range []struct {
		t        *callTarget
		backends map[string]*config.Backend
		want     string
	}{
		{call("fs", map[string]any{"path": "/etc/mcp-gateway/exec.d/x.yaml"}), backends,
			"no matching permission; the gateway's configuration is shown by the gateway-admin server's show_config, not by other servers"},
		{call("fs", map[string]any{"n": 3, "path": "/usr/share/mcp-gateway/docs/README.md"}), backends,
			"no matching permission; the gateway's documentation is on the gateway-docs server (search_text, read_text_file)"},
		{call("fs", map[string]any{"path": "/etc/passwd"}), backends, "no matching permission"},
		{call("gateway-admin", map[string]any{"file": "/etc/mcp-gateway/gateway.yaml"}), backends, "no matching permission"},
		{call("fs", map[string]any{"path": "/etc/mcp-gateway/x"}), map[string]*config.Backend{"fs": {}}, "no matching permission"},
		{&callTarget{server: "fs", action: "resources.read", args: map[string]any{"uri": "/etc/mcp-gateway/x"}}, backends, "no matching permission"},
	} {
		if got := withAdvice("no matching permission", c.t, c.backends); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.t, got, c.want)
		}
	}
}
