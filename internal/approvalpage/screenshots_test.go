//go:build screenshots

package approvalpage

// The console's pages with the demo data of a gateway in a cluster, for
// the README's screenshots (make screenshots, tools/screenshots): the
// pages as the gateway renders them, written to $SCREENSHOTS_DIR.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// demo is a gateway in a cluster: stdio servers in pods of their own,
// servers that speak HTTP in the cluster, agents with ServiceAccount
// tokens and people of the organization's identity provider.
type demo struct{}

const (
	orgIdP  = "https://login.example.com/realms/ops"
	cluster = "https://kubernetes.default.svc.cluster.local"
)

var demoStart = time.Now()

func before(d time.Duration) time.Time { return demoStart.Add(-d) }

func (demo) Instances() []router.InstanceInfo {
	return []router.InstanceInfo{
		{ID: "fs-7k2qd", Server: "fs", Sub: "k8s:system:serviceaccount:agents:custos", Issuer: cluster, Isolation: "principal",
			Started: before(42 * time.Minute), Sessions: 2, Definition: "current"},
		{ID: "fs-p9k4m", Server: "fs", Sub: "anna", Issuer: orgIdP, Isolation: "principal", Started: before(8 * time.Minute), Sessions: 1, Definition: "current"},
		{ID: "git-c81vb", Server: "git", Sub: "k8s:system:serviceaccount:agents:release-bot", Issuer: cluster, Isolation: "principal",
			Started: before(3 * time.Hour), Sessions: 1, Busy: true, Definition: "previous"},
		{ID: "tickets-2hd7s", Server: "tickets", Sub: "anna", Issuer: orgIdP, Isolation: "principal", Started: before(25 * time.Minute), Sessions: 1, Definition: "current"},
	}
}
func (demo) StopInstance(string) bool { return true }

func (demo) Sessions() []router.SessionInfo {
	return []router.SessionInfo{
		{ID: "s-1", Kind: "session", Sub: "k8s:system:serviceaccount:agents:custos", Issuer: cluster, Endpoint: "all",
			Client: principal.Client{Name: "custos", Version: "1.4.0"}, Protocol: "2025-11-25", Started: before(42 * time.Minute), LastActive: before(20 * time.Second)},
		{ID: "s-2", Kind: "agent", Sub: "anna", Issuer: orgIdP, Endpoint: "fs",
			Client: principal.Client{Name: "claude-code", Version: "2.1"}, Protocol: "2026-07-28", Started: before(8 * time.Minute), LastActive: before(1 * time.Minute)},
		{ID: "s-3", Kind: "session", Sub: "k8s:system:serviceaccount:agents:release-bot", Issuer: cluster, Endpoint: "git",
			Client: principal.Client{Name: "release-bot", Version: "0.9"}, Protocol: "2025-11-25", Started: before(3 * time.Hour), LastActive: before(4 * time.Minute)},
	}
}
func (demo) EndSession(string, string) error { return nil }

func (demo) Tasks() []router.TaskInfo {
	done := before(12 * time.Minute)
	return []router.TaskInfo{
		{ID: "t-1", Server: "git", Tool: "build_release", Sub: "k8s:system:serviceaccount:agents:release-bot", Status: "working",
			Message: "running the tests", Created: before(14 * time.Minute), Updated: before(30 * time.Second)},
		{ID: "t-2", Server: "fs", Tool: "index_tree", Sub: "k8s:system:serviceaccount:agents:custos", Status: "completed",
			Created: before(35 * time.Minute), Updated: done, Ended: &done, Delivered: true},
	}
}
func (demo) CancelTask(string, string) error { return nil }

func (demo) Bundles(context.Context) (map[string]string, error) {
	return map[string]string{"/policy": "2.0.0", "mcp.rbac": "configmap 8f3c2e1"}, nil
}

func (demo) List() []signin.Entry {
	return []signin.Entry{{Server: "tickets", Principal: signin.Key{Sub: "anna", Issuer: orgIdP, Transport: "http"},
		Since: before(25 * time.Minute), Expiry: demoStart.Add(35 * time.Minute), Scope: "tickets.read tickets.write", Refreshable: true}}
}
func (demo) PendingFor(uint32) []signin.PendingInfo { return nil }
func (demo) SignOut(context.Context, *config.Backend, signin.Key, string) (bool, bool, error) {
	return true, true, nil
}

func (demo) Report(context.Context) control.DoctorReport {
	return control.DoctorReport{Checked: before(2 * time.Minute), Trigger: "reload", Results: []doctor.Result{
		{Check: "configuration", Status: doctor.OK, Summary: "gateway.yaml and the server definitions are in force"},
		{Check: "policy", Status: doctor.OK, Summary: "OPA decides (deny for an unknown principal)"},
		{Check: "TLS", Status: doctor.OK, Summary: "certificate for mcp.example.com, valid until 2027-02-24"},
		{Check: "identity provider " + orgIdP, Status: doctor.OK, Summary: "key set with 2 keys"},
		{Check: "identity provider " + cluster, Status: doctor.OK, Summary: "key set with 1 key"},
		{Check: "approval page", Status: doctor.OK, Summary: "the identity provider takes the client mcp-gateway-approvals"},
		{Check: "server tickets", Status: doctor.OK, Summary: "tickets.tools.svc:8080 accepts connections"},
		{Check: "server wiki", Status: doctor.Fail, Summary: "wiki.tools.svc:80 does not answer: connection refused",
			Details: []string{"calls to this server fail; check its url, the Service or DNS name, and the gateway pod's NetworkPolicy"}},
		{Check: "state volume", Status: doctor.OK, Summary: "/var/lib/mcp-gateway is writable"},
		{Check: "kubernetes", Status: doctor.OK, Summary: "the API server answers: 3 instance pods in mcp-instances"},
	}}
}
func (d demo) Run(ctx context.Context) control.DoctorReport { return d.Report(ctx) }

// operators lets the remote group ops manage everything, as the role
// data's "remote-group:ops" does.
type operators struct{}

func (operators) Bool(_ context.Context, _ string, input any) (bool, error) {
	in, ok := input.(broker.ApproverInput)
	return ok && in.Approver != nil && in.Approver.Remote && slices.Contains(in.Approver.Groups, "ops"), nil
}

type demoElicitor struct{}

func (demoElicitor) SupportsForm() bool { return false }
func (demoElicitor) SupportsURL() bool  { return false }
func (demoElicitor) Elicit(context.Context, any) (broker.ElicitResult, error) {
	return broker.ElicitResult{}, errors.New("unsupported")
}
func (demoElicitor) Notify(string, any) {}

func TestScreenshots(t *testing.T) {
	dir := os.Getenv("SCREENSHOTS_DIR")
	if dir == "" {
		t.Skip("SCREENSHOTS_DIR not set")
	}
	version.Version = "2.0.0"
	b, err := broker.New(broker.Options{Timeout: time.Hour, OOB: true, Policy: operators{}})
	if err != nil {
		t.Fatal(err)
	}
	// An agent's call that waits for an operator.
	go func() {
		_, _ = b.Approve(context.Background(), demoElicitor{}, pep.Input{
			Principal: principal.Principal{Sub: "k8s:system:serviceaccount:agents:custos", Issuer: cluster, Transport: "http",
				Client: principal.Client{Name: "custos", Version: "1.4.0"}},
			Action:   "tools.call",
			Resource: pep.Resource{Server: "fs", Kind: "tool", Name: "write_file"},
			Args:     map[string]any{"path": "/data/reports/2026-11.md", "content": "# November\n…"},
		}, pep.AskSpec{Channel: pep.ChannelOOB, Scopes: []string{"once", "1h"}, Prompt: "Write the monthly report?"})
	}()
	for i := 0; i < 200 && len(b.ListPending(context.Background(), broker.Approver{})) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	d := demo{}
	cs := &control.Server{Broker: b, Instances: d, Sessions: d, Tasks: d, Policy: d, SignIns: d, Doctor: d,
		Backends: func() map[string]*config.Backend {
			return map[string]*config.Backend{
				"fs":      {Name: "fs", Isolation: "principal"},
				"git":     {Name: "git", Isolation: "principal", Network: true},
				"tickets": {Name: "tickets", Isolation: "principal", Network: true, URL: "http://tickets.tools.svc:8080/mcp", SignIn: &config.SignIn{}},
				"wiki":    {Name: "wiki", Isolation: "shared", Network: true, URL: "http://wiki.tools.svc/mcp"},
			}
		},
		ConfigReloads: func() int { return 3 }}
	f := newFixture(t, func(pg *Page) {
		pg.SessionTTL = 8 * time.Hour
		pg.Control = cs.Handler()
		pg.Broker = b
		pg.Branding = Branding{OSName: "Kubernetes · namespace mcp-gateway", Host: "mcp.example.com"}
	})
	f.idp.user = "olivia"
	c := f.browser(t)
	pending := b.ListPending(context.Background(), broker.Approver{})
	if len(pending) != 1 {
		t.Fatalf("pending %v", pending)
	}
	for name, p := range map[string]string{"console": "/console/", "console-servers": "/console/servers",
		"console-doctor": "/console/doctor", "console-approval": "/approvals/" + pending[0].ID} {
		code, body, _ := get(t, c, f.srv.URL+p)
		if code != 200 {
			t.Fatalf("%s: %d %s", p, code, body)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
