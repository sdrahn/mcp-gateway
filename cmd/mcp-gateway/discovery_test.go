package main

import (
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/discovery"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
)

func found(name, ns, svc, url string) *config.Backend {
	return &config.Backend{Name: name, URL: url, Discovered: &config.Discovered{Namespace: ns, Service: svc}}
}

// The audit records each discovered server that came, changed or went,
// and none of the server files'.
func TestDiscoveryAudit(t *testing.T) {
	s := &discoverySource{}
	a := &fakeAudit{}
	file := &config.Backend{Name: "git", URL: "https://git.example/mcp"}
	s.audit(a, map[string]*config.Backend{"git": file, "team-a-tickets": found("team-a-tickets", "team-a", "tickets", "http://tickets.team-a.svc:80/mcp")})
	s.audit(a, map[string]*config.Backend{"git": file,
		"team-a-tickets": found("team-a-tickets", "team-a", "tickets", "http://tickets.team-a.svc:8080/mcp"),
		"team-a-wiki":    found("team-a-wiki", "team-a", "wiki", "http://wiki.team-a.svc:80/mcp")})
	// Unchanged: nothing recorded.
	s.audit(a, map[string]*config.Backend{"git": file,
		"team-a-tickets": found("team-a-tickets", "team-a", "tickets", "http://tickets.team-a.svc:8080/mcp"),
		"team-a-wiki":    found("team-a-wiki", "team-a", "wiki", "http://wiki.team-a.svc:80/mcp")})
	s.audit(a, map[string]*config.Backend{"git": file, "team-a-wiki": found("team-a-wiki", "team-a", "wiki", "http://wiki.team-a.svc:80/mcp")})
	var got []string
	for _, r := range a.records {
		if r.op != "mcp-server-discovered" || !r.ok {
			t.Errorf("record %+v", r)
		}
		got = append(got, r.fields["change"]+" "+r.fields["server"]+" "+r.fields["namespace"]+"/"+r.fields["service"]+" "+r.fields["url"])
	}
	want := []string{
		"added team-a-tickets team-a/tickets http://tickets.team-a.svc:80/mcp",
		"changed team-a-tickets team-a/tickets http://tickets.team-a.svc:8080/mcp",
		"added team-a-wiki team-a/wiki http://wiki.team-a.svc:80/mcp",
		"removed team-a-tickets team-a/tickets http://tickets.team-a.svc:8080/mcp",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var none *discoverySource
	none.audit(a, nil) // without discovery: nothing
}

type fakeProblems struct {
	problems []discovery.Problem
	errs     map[string]string
}

func (f fakeProblems) Problems() ([]discovery.Problem, map[string]string) { return f.problems, f.errs }

// The doctor: a namespace not followed fails; Services that give no server
// warn; overridden ones are details only.
func TestSelfCheckServerDiscovery(t *testing.T) {
	gw := &config.Gateway{ServerDiscovery: config.ServerDiscovery{Namespaces: []config.DiscoveryNamespace{{Namespace: "team-a"}, {Namespace: "team-b"}}}}
	backends := map[string]*config.Backend{"git": {Name: "git"}, "team-a-tickets": found("team-a-tickets", "team-a", "tickets", "")}
	c := &selfCheck{gw: gw, backends: func() map[string]*config.Backend { return backends }}
	c.discovery = fakeProblems{}
	rs := c.serverDiscovery()
	if len(rs) != 1 || rs[0].Status != doctor.OK || rs[0].Summary != "1 servers discovered in 1 of 2 namespaces" {
		t.Errorf("ok: %+v", rs)
	}
	c.discovery = fakeProblems{
		problems: []discovery.Problem{
			{Namespace: "team-a", Service: "x", Server: "team-a-x", Reason: "the Service has no TCP port"},
			{Namespace: "team-a", Service: "git", Server: "team-a-git", Reason: "a server file defines team-a-git, and is in force instead", Overridden: true},
		},
		errs: map[string]string{"team-b": "forbidden"},
	}
	rs = c.serverDiscovery()
	if len(rs) != 2 || rs[0].Status != doctor.Fail || rs[0].Subject != "team-b" || !strings.Contains(rs[0].Summary, "forbidden") {
		t.Fatalf("namespace: %+v", rs)
	}
	if rs[1].Status != doctor.Warn || !strings.Contains(rs[1].Summary, "1 Services give no server") || len(rs[1].Details) != 2 ||
		!strings.Contains(rs[1].Details[0], "team-a/x") || !strings.Contains(rs[1].Details[1], "in force instead") {
		t.Errorf("problems: %+v", rs[1])
	}
}
