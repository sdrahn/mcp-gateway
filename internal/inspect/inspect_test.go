package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// fakeServer answers on conn like an MCP server with two pages of tools,
// one prompt and one resource template. Before the first tools/list
// result it sends a notification and a ping, and expects the ping
// answered.
func fakeServer(t *testing.T, conn net.Conn) {
	t.Helper()
	c := jsonrpc.NewConn(conn)
	reply := func(id json.RawMessage, v string) {
		var res any
		if err := json.Unmarshal([]byte(v), &res); err != nil {
			t.Error(err)
			return
		}
		m, _ := jsonrpc.NewResult(id, res)
		_ = c.Write(m)
	}
	for {
		m, err := c.Read()
		if err != nil {
			return
		}
		switch m.Method {
		case "initialize":
			reply(m.ID, `{"protocolVersion":"2025-06-18","serverInfo":{"name":"fake","version":"1.2"},
				"capabilities":{"tools":{},"prompts":{},"resources":{}}}`)
		case "tools/list":
			var p struct{ Cursor string }
			_ = json.Unmarshal(m.Params, &p)
			if p.Cursor == "" {
				n, _ := jsonrpc.NewNotification("notifications/message", map[string]any{"level": "info", "data": "hi"})
				_ = c.Write(n)
				ping, _ := jsonrpc.NewRequest(json.RawMessage(`"s1"`), "ping", nil)
				_ = c.Write(ping)
				if a, err := c.Read(); err != nil || a.Key() != `"s1"` || a.Error != nil {
					t.Errorf("ping not answered: %+v %v", a, err)
				}
				reply(m.ID, `{"tools":[
					{"name":"get_status","annotations":{"readOnlyHint":true}},
					{"name":"list_units","inputSchema":{"type":"object","properties":{"unit_path":{"type":"string"},"state":{"type":"string"}}}}
				],"nextCursor":"2"}`)
			} else {
				reply(m.ID, `{"tools":[
					{"name":"DeleteThing","annotations":{"readOnlyHint":false,"destructiveHint":true}},
					{"name":"remove_all","annotations":{"readOnlyHint":true}},
					{"name":"plan_x"}
				]}`)
			}
		case "prompts/list":
			reply(m.ID, `{"prompts":[{"name":"summary"}]}`)
		case "resources/templates/list":
			reply(m.ID, `{"resourceTemplates":[{"name":"file","uriTemplate":"file:///{path}"}]}`)
		case "":
		default:
			if m.IsRequest() {
				_ = c.Write(jsonrpc.NewError(m.ID, -32601, "no"))
			}
		}
	}
}

func probeFake(t *testing.T) *Result {
	t.Helper()
	a, b := net.Pipe()
	go fakeServer(t, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Probe(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	return res
}

func TestProbe(t *testing.T) {
	res := probeFake(t)
	if res.Server.Name != "fake" || res.Server.Version != "1.2" || res.ProtocolVersion != "2025-06-18" {
		t.Errorf("server = %+v %s", res.Server, res.ProtocolVersion)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	if got := strings.Join(names, " "); got != "get_status list_units DeleteThing remove_all plan_x" {
		t.Errorf("tools = %s", got)
	}
	if len(res.Prompts) != 1 || len(res.ResourceTemplates) != 1 || res.ResourceTemplates[0].URITemplate != "file:///{path}" {
		t.Errorf("prompts %v, templates %v", res.Prompts, res.ResourceTemplates)
	}
}

func TestProbeHangs(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	go func() { _, _ = b.Read(make([]byte, 4096)) }() // reads, never answers
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Probe(ctx, a); err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Errorf("err = %v", err)
	}
}

func TestProbeEOF(t *testing.T) {
	a, b := net.Pipe()
	go func() { _, _ = b.Read(make([]byte, 4096)); _ = b.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Probe(ctx, a); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Errorf("err = %v", err)
	}
}

func TestFirstWord(t *testing.T) {
	for in, want := range map[string]string{
		"list_loaded_units":  "list",
		"RegistrationStatus": "registration",
		"getFoo":             "get",
		"check-restart":      "check",
		"_hidden_set":        "hidden",
		"ns.read":            "ns",
	} {
		if got := firstWord(in); got != want {
			t.Errorf("firstWord(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	res := probeFake(t)
	got := map[string]Verdict{}
	for _, v := range Classify(res.Tools, Options{}) {
		got[v.Tool] = v
	}
	for name, want := range map[string]struct {
		class  Class
		reader bool
	}{
		"get_status":  {ClassRead, true},     // annotation and name agree
		"list_units":  {ClassRead, false},    // name only: needs approval
		"DeleteThing": {ClassChange, false},  // annotations and name
		"remove_all":  {ClassUnknown, false}, // says read-only, named like a change
		"plan_x":      {ClassUnknown, false},
	} {
		v := got[name]
		if v.Class != want.class || v.Reader != want.reader {
			t.Errorf("%s: %s reader=%v, want %s reader=%v (%v)", name, v.Class, v.Reader, want.class, want.reader, v.Evidence)
		}
	}
	if pa := got["list_units"].PathArgs; len(pa) != 1 || pa[0] != "unit_path" {
		t.Errorf("path args = %v", pa)
	}
	for _, v := range Classify(res.Tools, Options{ReadByName: true}) {
		if v.Tool == "list_units" && !v.Reader {
			t.Error("ReadByName: list_units not in the reader role")
		}
	}
}

func TestRoles(t *testing.T) {
	vs := []Verdict{{Tool: "get_*x", Class: ClassRead, Reader: true}, {Tool: "set_x", Class: ClassChange}}
	data, _ := json.Marshal(Roles("srv", vs))
	var doc struct {
		Roles map[string]struct {
			Permissions []map[string]any
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Roles["srv-reader"].Permissions
	if len(r) != 1 || r[0]["tool"] != `get_\*x` {
		t.Errorf("reader = %v", r)
	}
	op := doc.Roles["srv-operator"].Permissions
	if len(op) != 2 || op[1]["tool"] != "*" || op[1]["require_approval"] != true {
		t.Errorf("operator = %v", op)
	}
	// The drafted roles name only tools the server has.
	res := &Result{Tools: []Tool{{Name: "get_*x"}, {Name: "set_x"}}}
	f, err := CheckRoles([]RoleFile{{"draft", data}}, "srv", res)
	if err != nil || Errors(f) != 0 {
		t.Errorf("check of the draft: %v %v", f, err)
	}
	// They validate as role data.
	if problems, err := policydata.Check(data); err != nil || len(problems) > 0 {
		t.Errorf("draft roles invalid: %v %v\n%s", problems, err, data)
	}
	// No reader tools: only the operator role.
	data, _ = json.Marshal(Roles("srv", vs[1:]))
	if strings.Contains(string(data), "srv-reader") {
		t.Errorf("reader role without tools: %s", data)
	}
}

func TestCheckRoles(t *testing.T) {
	res := &Result{
		Tools:   []Tool{{Name: "list_loaded_units"}, {Name: "list_unit_files"}, {Name: "list_log"}, {Name: "change_unit_state"}},
		Prompts: []Item{{Name: "summary"}},
	}
	data := []byte(`{"roles":{
		"reader":{"permissions":[
			{"server":"systemd","tool":"list_units"},
			{"server":"systemd","tool":"list_log"},
			{"server":"systemd","tool":"get_*"},
			{"server":"systemd","prompt":"summary"},
			{"server":"systemd","prompt":"other"},
			{"server":"firewalld","tool":"nothing_here"},
			{"server":"sys*","tool":"${sub}_x"}
		]},
		"admin":{"permissions":[{"server":"*","tool":"list_unit*"}]}
	},"bindings":{}}`)
	f, err := CheckRoles([]RoleFile{{"r.json", data}}, "systemd", res)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, x := range f {
		out.WriteString(x.Level + ": " + x.Message + "\n")
	}
	got := out.String()
	for _, want := range []string{
		`error: r.json: role reader, permission 0: systemd has no tool "list_units"`,
		`warning: r.json: role reader, permission 2: tool pattern "get_*" matches no tool of systemd`,
		`error: r.json: role reader, permission 4: systemd has no prompt "other"`,
		`info: r.json: role reader, permission 6: tool "${sub}_x" depends on the user; not checked`,
		`info: tools no permission names: list_loaded_units, change_unit_state`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "nothing_here") {
		t.Errorf("checked another server's permission:\n%s", got)
	}
	if Errors(f) != 2 {
		t.Errorf("errors = %d", Errors(f))
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		pat, name string
		want      bool
	}{
		{"*", "list_log", true},
		{"*", "ns.tool", false}, // "*" stays within a "." segment
		{"**", "ns.tool", true},
		{"list_?og", "list_log", true},
		{"{get,list}_*", "list_x", true},
		{"{get,list}_*", "set_x", false},
		{"[!s]et_x", "get_x", true},
		{"[!s]et_x", "set_x", false},
		{`get_\*x`, "get_*x", true},
		{`get_\*x`, "get_ax", false},
		{"a{b", "a{b", false}, // does not compile: matches nothing
	} {
		if got := globMatch(c.pat, c.name); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.pat, c.name, got)
		}
	}
	if hasGlob(`get_\*x`) || !hasGlob("get_*") {
		t.Error("hasGlob")
	}
}

func TestDefinition(t *testing.T) {
	res := &Result{Server: ServerInfo{Name: "fake", Version: "1"}}
	y := Definition("my-srv", []string{"/usr/bin/my-srv", "--stdio"}, res)
	var b config.Backend
	dec := yaml.NewDecoder(strings.NewReader(y))
	dec.KnownFields(true)
	if err := dec.Decode(&b); err != nil {
		t.Fatalf("%v\n%s", err, y)
	}
	b.ApplyDefaults()
	if err := b.Validate(); err != nil || b.Name != "my-srv" || len(b.Command) != 2 {
		t.Errorf("definition %+v: %v\n%s", b, err, y)
	}
	if !strings.Contains(y, "mcp_gateway_backend_template(my_srv)") {
		t.Errorf("no module hint:\n%s", y)
	}
}

func TestReport(t *testing.T) {
	res := probeFake(t)
	vs := Classify(res.Tools, Options{})
	var w bytes.Buffer
	if err := Report(&w, "fake", res, vs, []Finding{}); err != nil {
		t.Fatal(err)
	}
	out := w.String()
	for _, want := range []string{
		"Server fake: fake 1.2 (MCP 2025-06-18)",
		"R get_status",
		"Read by their name only, so they need approval in the draft: list_units.",
		"path arguments: unit_path",
		"Role check:\n  no problems",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
