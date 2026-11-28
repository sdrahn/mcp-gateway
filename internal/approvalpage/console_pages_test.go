package approvalpage

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// jackOnly lets the approver jack manage everything, no one else.
type jackOnly struct{}

func (jackOnly) Bool(_ context.Context, _ string, input any) (bool, error) {
	in, ok := input.(broker.ApproverInput)
	return ok && in.Approver != nil && in.Approver.Name == "jack" && in.Approver.Remote, nil
}

// gateway is what the control API reports of a gateway in the console's
// tests: an instance, a session, a task; it records what was stopped.
type gateway struct {
	mu      sync.Mutex
	stopped []string
	ended   []string
	// replica, if set, runs the instance: another of several, as the
	// merged views (internal/cluster) name it.
	replica string
}

func (g *gateway) Instances() []router.InstanceInfo {
	in := router.InstanceInfo{ID: "fs-ivy-1", Server: "fs", Sub: "ivy", Isolation: "principal", Started: time.Now().Add(-time.Hour), Sessions: 1, Definition: "current"}
	if g.replica != "" {
		in.ID, in.Replica = g.replica+"~"+in.ID, g.replica
	}
	return []router.InstanceInfo{in}
}

func (g *gateway) StopInstance(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = append(g.stopped, id)
	return true
}

func (g *gateway) Sessions() []router.SessionInfo {
	return []router.SessionInfo{{ID: "s-1", Kind: "session", Sub: "ivy", Endpoint: "fs", Protocol: "2025-11-25",
		Started: time.Now().Add(-time.Hour), LastActive: time.Now()}}
}

func (g *gateway) EndSession(id, by string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ended = append(g.ended, id+" by "+by)
	return nil
}

func (g *gateway) Tasks() []router.TaskInfo {
	return []router.TaskInfo{{ID: "t-1", Server: "fs", Tool: "index", Sub: "ivy", Status: "working", Created: time.Now(), Updated: time.Now()}}
}

func (g *gateway) CancelTask(string, string) error { return nil }

func (g *gateway) Bundles(context.Context) (map[string]string, error) {
	return map[string]string{"mcp": "rev-42"}, nil
}

func consolePagesFixture(t *testing.T) (*fixture, *gateway) {
	t.Helper()
	b, err := broker.New(broker.Options{Timeout: time.Minute, Policy: jackOnly{}})
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{}
	cs := &control.Server{Broker: b, Instances: g, Sessions: g, Tasks: g, Policy: g,
		Backends: func() map[string]*config.Backend {
			return map[string]*config.Backend{"fs": {Name: "fs", Isolation: "principal"}}
		},
		ConfigError: func() string { return "gateway.yaml: line 3: unknown key" }}
	f := newFixture(t, func(pg *Page) { pg.Control = cs.Handler() })
	return f, g
}

func TestConsolePages(t *testing.T) {
	f, g := consolePagesFixture(t)
	c := f.browser(t)
	// The sign-in comes back to the console's page.
	code, body, hdr := get(t, c, f.srv.URL+"/console/servers")
	if code != 200 || !strings.Contains(body, "MCP Gateway console") || !strings.Contains(body, "fs-ivy-1") ||
		!strings.Contains(body, `aria-current="page">Servers`) {
		t.Fatalf("servers: %d %s", code, body)
	}
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'none'") || hdr.Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers %v", hdr)
	}
	for path, wants := range map[string][]string{
		"/console/":         {"gateway.yaml: line 3: unknown key", "rev-42", `<div class="n">1</div><div class="muted">instances you manage`},
		"/console/sessions": {"s-1", "2025-11-25"},
		"/console/tasks":    {"fs/index", "working", "/console/tasks/t-1/cancel"},
		"/console/sign-ins": {"No sign-ins you manage."},
		"/console/policy":   {"rev-42", "What if"},
	} {
		code, body, _ := get(t, c, f.srv.URL+path)
		for _, want := range wants {
			if code != 200 || !strings.Contains(body, want) {
				t.Errorf("%s: %d, lacks %q:\n%s", path, code, want, body)
			}
		}
	}
	// The approvals page links to the console.
	if _, body, _ := get(t, c, f.srv.URL+"/approvals/"); !strings.Contains(body, `href="/console/"`) {
		t.Error("no link to the console")
	}

	// An action: through the control API, as jack, audited.
	csrf := csrfOf(t, body)
	if code, _ := post(t, c, f.srv.URL+"/console/instances/fs-ivy-1/stop", url.Values{}, nil); code != http.StatusForbidden || len(g.stopped) != 0 {
		t.Errorf("without the CSRF token: %d %v", code, g.stopped)
	}
	code, body = post(t, c, f.srv.URL+"/console/instances/fs-ivy-1/stop", url.Values{"csrf": {csrf}}, map[string]string{"Origin": f.srv.URL})
	if code != 200 || !strings.Contains(body, "Done: stopped instance fs-ivy-1") || len(g.stopped) != 1 {
		t.Errorf("stop: %d %v %s", code, g.stopped, body)
	}
	last := f.audit.fields[len(f.audit.fields)-1]
	if last["by"] != "jack" || last["via"] != ViaConsole || last["route"] != "/v1/instances/fs-ivy-1" {
		t.Errorf("audit %v", last)
	}
	if _, body = post(t, c, f.srv.URL+"/console/sessions/s-1/end", url.Values{"csrf": {csrf}}, map[string]string{"Origin": f.srv.URL}); len(g.ended) != 1 || g.ended[0] != "s-1 by jack (console)" {
		t.Errorf("end: %v %s", g.ended, body)
	}
	// A refusal is shown, not hidden.
	if _, body = post(t, c, f.srv.URL+"/console/instances/nope/stop", url.Values{"csrf": {csrf}}, map[string]string{"Origin": f.srv.URL}); !strings.Contains(body, "refused (no such instance)") {
		t.Errorf("refusal: %s", body)
	}
	// The what-if without a policy review: the error, and the data kept.
	_, body = post(t, c, f.srv.URL+"/console/policy/whatif", url.Values{"csrf": {csrf}, "data": {`{"roles": {}}`}}, map[string]string{"Origin": f.srv.URL})
	if !strings.Contains(body, `class="note error"`) || !strings.Contains(body, "{&#34;roles&#34;: {}}") {
		t.Errorf("what-if: %s", body)
	}
	if _, body = post(t, c, f.srv.URL+"/console/policy/whatif", url.Values{"csrf": {csrf}, "data": {`not json`}}, map[string]string{"Origin": f.srv.URL}); !strings.Contains(body, "not JSON") {
		t.Errorf("what-if, not JSON: %s", body)
	}
}

// Someone the approver rules give nothing sees the pages without
// anyone's instances, and cannot act.
func TestConsolePagesOthers(t *testing.T) {
	f, g := consolePagesFixture(t)
	f.idp.user = "zed"
	c := f.browser(t)
	code, body, _ := get(t, c, f.srv.URL+"/console/servers")
	if code != 200 || strings.Contains(body, "fs-ivy-1") || !strings.Contains(body, "No instances you manage") {
		t.Fatalf("servers: %d %s", code, body)
	}
	csrf := csrfOf(t, body)
	_, body = post(t, c, f.srv.URL+"/console/instances/fs-ivy-1/stop", url.Values{"csrf": {csrf}}, map[string]string{"Origin": f.srv.URL})
	if len(g.stopped) != 0 || !strings.Contains(body, "refused") {
		t.Errorf("zed stopped %v: %s", g.stopped, body)
	}
}

type pageDoctor struct {
	runs    int
	replica string
	others  []control.DoctorReport
}

func (d *pageDoctor) Report(context.Context) control.DoctorReport {
	return control.DoctorReport{Checked: time.Now(), Trigger: "start", Replica: d.replica, Replicas: d.others, Results: []doctor.Result{
		{Check: "policy", Status: doctor.OK, Summary: "OPA decides"},
		{Check: "server tickets", Status: doctor.Fail, Summary: "tickets.svc:80 does not answer", Details: []string{"check its url"}}}}
}

func (d *pageDoctor) Run(ctx context.Context) control.DoctorReport {
	d.runs++
	r := d.Report(ctx)
	r.Trigger = "request"
	return r
}

func TestConsoleDoctor(t *testing.T) {
	// Without the doctor in the gateway: what to do instead.
	f, _ := consolePagesFixture(t)
	c := f.browser(t)
	if _, body, _ := get(t, c, f.srv.URL+"/console/doctor"); !strings.Contains(body, "run mcp-gateway-admin doctor") || strings.Contains(body, "Check again") {
		t.Errorf("no doctor: %s", body)
	}

	b, err := broker.New(broker.Options{Timeout: time.Minute, Policy: jackOnly{}})
	if err != nil {
		t.Fatal(err)
	}
	d := &pageDoctor{}
	f = newFixture(t, func(pg *Page) { pg.Control = (&control.Server{Broker: b, Doctor: d}).Handler() })
	c = f.browser(t)
	code, body, _ := get(t, c, f.srv.URL+"/console/doctor")
	if code != 200 || !strings.Contains(body, `<span class="status fail">fail</span>`) || !strings.Contains(body, "tickets.svc:80 does not answer") ||
		!strings.Contains(body, "at the start") || strings.Contains(body, "by the replica") || d.runs != 0 {
		t.Fatalf("doctor: %d %s", code, body)
	}
	_, body = post(t, c, f.srv.URL+"/console/doctor", url.Values{"csrf": {csrfOf(t, body)}}, map[string]string{"Origin": f.srv.URL})
	if d.runs != 1 || !strings.Contains(body, "on request") {
		t.Errorf("check again: %d %s", d.runs, body)
	}
	// One of several replicas: the one that ran the checks, and the
	// others' reports.
	d.replica = "gw-b"
	d.others = []control.DoctorReport{{Replica: "gw-c", Trigger: "start", Checked: time.Now(),
		Results: []doctor.Result{{Check: "policy", Status: doctor.OK, Summary: "gw-c's OPA decides"}}},
		{Replica: "gw-d", Unreachable: "connection refused"}}
	_, body, _ = get(t, c, f.srv.URL+"/console/doctor")
	for _, want := range []string{"(at the start) by the replica gw-b.", "<h2>Replica gw-c</h2>", "gw-c&#39;s OPA decides",
		"<h2>Replica gw-d</h2>", "It does not answer: connection refused"} {
		if !strings.Contains(body, want) {
			t.Errorf("replicas: lacks %q: %s", want, body)
		}
	}
}

// With several replicas a row of another names it, and an action on it
// goes to the control API with its id as the merged view gave it.
func TestConsoleOtherReplica(t *testing.T) {
	f, g := consolePagesFixture(t)
	g.replica = "gw-c"
	c := f.browser(t)
	_, body, _ := get(t, c, f.srv.URL+"/console/servers")
	if !strings.Contains(body, `gw-c~fs-ivy-1 <span class="muted">on gw-c</span>`) {
		t.Fatalf("servers: %s", body)
	}
	code, body := post(t, c, f.srv.URL+"/console/instances/gw-c~fs-ivy-1/stop", url.Values{"csrf": {csrfOf(t, body)}}, map[string]string{"Origin": f.srv.URL})
	if code != 200 || len(g.stopped) != 1 || g.stopped[0] != "gw-c~fs-ivy-1" {
		t.Errorf("stop: %d %v %s", code, g.stopped, body)
	}
}

// With several replicas the status names the replica that serves the
// page and the live ones.
func TestConsoleReplicas(t *testing.T) {
	b, err := broker.New(broker.Options{Timeout: time.Minute, Policy: jackOnly{}})
	if err != nil {
		t.Fatal(err)
	}
	cs := &control.Server{Broker: b, Replicas: func() (string, []string) { return "gw-b", []string{"gw-a", "gw-b", "gw-c"} }}
	f := newFixture(t, func(pg *Page) { pg.Control = cs.Handler() })
	c := f.browser(t)
	if code, body, _ := get(t, c, f.srv.URL+"/console/"); code != 200 || !strings.Contains(body, "<dt>Replica</dt><dd>gw-b") ||
		!strings.Contains(body, "3 live: gw-a, gw-b, gw-c") {
		t.Fatalf("status: %d %s", code, body)
	}
	cs.Replicas = nil
	if _, body, _ := get(t, c, f.srv.URL+"/console/"); strings.Contains(body, "<dt>Replica</dt>") {
		t.Errorf("one replica: %s", body)
	}
}
