package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

type fakeDecider struct{ err error }

func (f fakeDecider) Decide(context.Context, pep.Input) (pep.Decision, error) {
	return pep.Decision{Effect: pep.Deny}, f.err
}

func byCheck(rs []doctor.Result) map[string]doctor.Result {
	m := map[string]doctor.Result{}
	for _, r := range rs {
		m[r.Check] = r
	}
	return m
}

// The doctor in the gateway: the configuration's reload state, OPA, the
// servers' URLs (or their proxy), the state volume; the report kept.
func TestSelfCheck(t *testing.T) {
	state := t.TempDir()
	reloader := &serverReloader{configErr: "gateway.yaml: line 3: unknown key"}
	var dialed []string
	c := &selfCheck{log: slog.New(slog.DiscardHandler), gw: &config.Gateway{StateDir: state}, reloader: reloader, opa: fakeDecider{},
		backends: func() map[string]*config.Backend {
			return map[string]*config.Backend{
				"up":      {Name: "up", URL: "http://up.tools.svc:8080/mcp"},
				"down":    {Name: "down", URL: "https://down.example.com/mcp"},
				"proxied": {Name: "proxied", URL: "https://far.example.com/mcp", Proxy: "http://proxy.example.com:3128"},
				"stdio":   {Name: "stdio", Command: []string{"/bin/true"}},
			}
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			if strings.HasPrefix(addr, "down.") {
				return nil, errors.New("connection refused")
			}
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		}}
	c.replica = "gw-b"
	rep := c.Report(context.Background())
	if rep.Trigger != "request" || rep.Checked.IsZero() || rep.Replica != "gw-b" {
		t.Errorf("report %+v", rep)
	}
	m := byCheck(rep.Results)
	if r := m["configuration"]; r.Status != doctor.Fail || !strings.Contains(strings.Join(r.Details, " "), "unknown key") {
		t.Errorf("configuration %+v", r)
	}
	if r := m["policy"]; r.Status != doctor.OK || !strings.Contains(r.Summary, "deny") {
		t.Errorf("policy %+v", r)
	}
	if r := m["server up"]; r.Status != doctor.OK || r.ID != "server" || r.Subject != "up" || r.Summary != "up.tools.svc:8080 accepts connections" {
		t.Errorf("up %+v", r)
	}
	if r := m["server down"]; r.Status != doctor.Fail || !strings.Contains(r.Summary, "down.example.com:443 does not answer: connection refused") {
		t.Errorf("down %+v", r)
	}
	if r := m["server proxied"]; r.Status != doctor.OK || r.Summary != "proxy.example.com:3128 through its proxy accepts connections" {
		t.Errorf("proxied %+v", r)
	}
	if _, ok := m["server stdio"]; ok {
		t.Error("a stdio server dialed")
	}
	if r := m["state volume"]; r.Status != doctor.OK || r.ID != "state-volume" {
		t.Errorf("state volume %+v", r)
	}
	if ents, _ := os.ReadDir(state); len(ents) != 0 {
		t.Errorf("left in the state directory: %v", ents)
	}

	// Kept: Report does not run them again; Run does.
	n := len(dialed)
	c.Report(context.Background())
	if len(dialed) != n {
		t.Error("Report ran the checks again")
	}
	reloader.configErr = ""
	reloader.restart = []string{"http.listen"}
	c.opa = fakeDecider{err: errors.New("dial unix /run/mcp-gateway/opa.sock: no such file")}
	c.gw.StateDir = filepath.Join(state, "missing")
	m = byCheck(c.Run(context.Background()).Results)
	if r := m["configuration"]; r.Status != doctor.Warn || !strings.Contains(r.Summary, "http.listen") {
		t.Errorf("restart needed %+v", r)
	}
	if r := m["policy"]; r.Status != doctor.Fail {
		t.Errorf("OPA down %+v", r)
	}
	if r := m["state volume"]; r.Status != doctor.Fail {
		t.Errorf("no state volume %+v", r)
	}
	// gateway.yaml's warnings (#412).
	reloader.restart = nil
	c.gw.Warnings = []string{"http.issuers[0] (https://kubernetes.default.svc) is the issuer people sign in with"}
	m = byCheck(c.Run(context.Background()).Results)
	if r := m["configuration"]; r.Status != doctor.Warn || !strings.Contains(strings.Join(r.Details, " "), "people sign in with") {
		t.Errorf("warnings %+v", r)
	}
}

// A webhook's check posts a ping to its receiver: not at the start or a
// reload.
func TestSelfCheckWebhooksOnRequest(t *testing.T) {
	gw := &config.Gateway{StateDir: t.TempDir()}
	gw.Approvals.Webhooks = []config.Webhook{{Name: "chat", URL: "https://chat.example.com/hook", SecretFile: "/nonexistent"}}
	c := &selfCheck{log: slog.New(slog.DiscardHandler), gw: gw, opa: fakeDecider{},
		backends: func() map[string]*config.Backend { return nil }}
	if r := byCheck(c.check(context.Background(), "reload").Results)["webhook chat"]; r.Status != doctor.Skip {
		t.Errorf("on reload: %+v", r)
	}
	if r := byCheck(c.Run(context.Background()).Results)["webhook chat"]; r.Status != doctor.Fail || !strings.Contains(r.Summary, "secret_file") {
		t.Errorf("on request: %+v", r)
	}
}

// The run at the start waits for the policy engine, at most startWait.
func TestSelfCheckWaitsForOPA(t *testing.T) {
	defer func(w, p time.Duration) { startWait, readyPoll = w, p }(startWait, readyPoll)
	startWait, readyPoll = time.Second, time.Millisecond
	asked := 0
	c := &selfCheck{ready: func(context.Context) error {
		if asked++; asked < 3 {
			return errors.New("no socket yet")
		}
		return nil
	}}
	c.waitReady(context.Background())
	if asked != 3 {
		t.Errorf("asked %d times", asked)
	}
	c.ready = func(context.Context) error { return errors.New("never") }
	start := time.Now()
	c.waitReady(context.Background())
	if d := time.Since(start); d < startWait || d > 5*startWait {
		t.Errorf("waited %v", d)
	}
}

func TestHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.example.com/mcp":   "a.example.com:443",
		"http://svc.ns.svc/mcp":       "svc.ns.svc:80",
		"http://[::1]:8080/x":         "[::1]:8080",
		"https://a.example.com:9443/": "a.example.com:9443",
	} {
		if got, err := hostPort(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	if _, err := hostPort("not a url"); err == nil {
		t.Error("not a URL: no error")
	}
}
