package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

type nopElicitor struct{}

func (nopElicitor) SupportsForm() bool { return false }
func (nopElicitor) SupportsURL() bool  { return false }
func (nopElicitor) Elicit(context.Context, any) (broker.ElicitResult, error) {
	return broker.ElicitResult{}, errors.New("unsupported")
}
func (nopElicitor) Notify(string, any) {}

var users = map[uint32]broker.Approver{
	1001: {Name: "alice", UID: 1001},
	1002: {Name: "bob", UID: 1002},
}

func identify(p transport.PeerCred) (broker.Approver, error) {
	if a, ok := users[p.UID]; ok {
		return a, nil
	}
	return broker.Approver{}, errors.New("unknown")
}

// setup returns a server and a pending approval of alice's, whose
// outcome arrives on the returned channel.
func setup(t *testing.T) (*Server, string, chan *pep.Grant) {
	t.Helper()
	b, err := broker.New(broker.Options{Timeout: 5 * time.Second, OOB: true}) // no policy: self only
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(1001)
	in := pep.Input{
		Principal: principal.Principal{Sub: "alice", UID: &uid, SessionID: "s1"},
		Action:    "tools.call",
		Resource:  pep.Resource{Server: "fs", Kind: "tool", Name: "write_file"},
	}
	outcome := make(chan *pep.Grant, 1)
	go func() {
		g, _ := b.Approve(context.Background(), nopElicitor{}, in, pep.AskSpec{Channel: pep.ChannelOOB, Scopes: []string{"once", "session"}})
		outcome <- g
	}()
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ps := b.ListPending(context.Background(), broker.Approver{UID: 0}); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval")
	}
	return &Server{Broker: b, Identify: identify}, id, outcome
}

func call(t *testing.T, s *Server, uid uint32, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if uid != 0 {
		req = req.WithContext(WithPeer(req.Context(), transport.PeerCred{UID: uid}))
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestNoPeer(t *testing.T) {
	s, _, _ := setup(t)
	if rec := call(t, s, 0, "GET", "/v1/approvals", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
	if rec := call(t, s, 4242, "GET", "/v1/approvals", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown uid: %d", rec.Code)
	}
}

func TestWhoami(t *testing.T) {
	s, _, _ := setup(t)
	rec := call(t, s, 1001, "GET", "/v1/whoami", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"alice"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestListAndGet(t *testing.T) {
	s, id, _ := setup(t)
	var ps []broker.Pending
	rec := call(t, s, 1001, "GET", "/v1/approvals", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &ps); err != nil || len(ps) != 1 || ps[0].ID != id || ps[0].Name != "write_file" {
		t.Fatalf("alice: %s %v", rec.Body, err)
	}
	rec = call(t, s, 1002, "GET", "/v1/approvals", "")
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("bob sees %s", rec.Body)
	}
	if rec := call(t, s, 1001, "GET", "/v1/approvals/"+id, ""); rec.Code != 200 {
		t.Fatalf("get: %d", rec.Code)
	}
	if rec := call(t, s, 1002, "GET", "/v1/approvals/"+id, ""); rec.Code != 404 {
		t.Fatalf("bob get: %d", rec.Code)
	}
}

func TestResolve(t *testing.T) {
	s, id, outcome := setup(t)
	for _, tc := range []struct {
		uid  uint32
		body string
		want int
	}{
		{1001, `{"decision":"maybe"}`, 400},
		{1001, `not json`, 400},
		{1001, `{"decision":"approve","scope":"forever"}`, 400},
		{1002, `{"decision":"approve","scope":"once"}`, 404},
	} {
		if rec := call(t, s, tc.uid, "POST", "/v1/approvals/"+id, tc.body); rec.Code != tc.want {
			t.Fatalf("%d %s: got %d %s", tc.uid, tc.body, rec.Code, rec.Body)
		}
	}
	rec := call(t, s, 1001, "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"session"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"approved_by":"alice"`) {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if g := <-outcome; g == nil || g.Scope != "session" {
		t.Fatalf("outcome %+v", g)
	}
	if rec := call(t, s, 1001, "POST", "/v1/approvals/"+id, `{"decision":"deny"}`); rec.Code != 404 {
		t.Fatalf("second decision: %d", rec.Code)
	}

	// The session grant is listed for alice, not bob, and alice can revoke it.
	var gs []pep.Grant
	rec = call(t, s, 1001, "GET", "/v1/grants", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &gs); err != nil || len(gs) != 1 {
		t.Fatalf("grants: %s", rec.Body)
	}
	if rec := call(t, s, 1002, "DELETE", "/v1/grants/"+gs[0].ID, ""); rec.Code != 404 {
		t.Fatalf("bob revoke: %d", rec.Code)
	}
	if rec := call(t, s, 1001, "DELETE", "/v1/grants/"+gs[0].ID, ""); rec.Code != 204 {
		t.Fatalf("revoke: %d", rec.Code)
	}
}

func TestDeny(t *testing.T) {
	s, id, outcome := setup(t)
	if rec := call(t, s, 1001, "POST", "/v1/approvals/"+id, `{"decision":"deny"}`); rec.Code != 204 {
		t.Fatalf("deny: %d", rec.Code)
	}
	if g := <-outcome; g != nil {
		t.Fatalf("outcome %+v", g)
	}
}

func TestServeOverUnixSocket(t *testing.T) {
	b, err := broker.New(broker.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "control.sock")
	l, err := transport.ListenUnix(sock, 0o660, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{Broker: b} // real NSS identification of the peer
	go func() { _ = s.Serve(ctx, l) }()

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	resp, err := client.Get("http://control/v1/whoami")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var a broker.Approver
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		t.Fatal(err)
	}
	if a.UID != uint32(os.Getuid()) || a.Name == "" {
		t.Fatalf("whoami %+v", a)
	}
}

type fakeInstances struct {
	list    []router.InstanceInfo
	stopped []string
}

func (f *fakeInstances) Instances() []router.InstanceInfo { return f.list }

func (f *fakeInstances) StopInstance(id string) bool {
	f.stopped = append(f.stopped, id)
	return true
}

type fakePolicy map[string]string

func (f fakePolicy) Bundles(context.Context) (map[string]string, error) { return f, nil }

func TestServersAndInstances(t *testing.T) {
	s, _, _ := setup(t)
	alice, bob := uint32(1001), uint32(1002)
	insts := &fakeInstances{list: []router.InstanceInfo{
		{ID: "i-alice", Server: "fs", Unit: "mcp-fs-1.service", Sub: "alice", UID: &alice},
		{ID: "i-bob", Server: "fs", Unit: "mcp-fs-2.service", Sub: "bob", UID: &bob},
		{ID: "i-zypp", Server: "zypp", Unit: "mcp-zypp-3.service", Sub: "alice", UID: &alice, Privileged: true, Busy: true},
	}}
	s.Backends = map[string]*config.Backend{
		"fs":   {Name: "fs", SELinuxType: "mcpsrv_fs_t", Isolation: config.IsolationPrincipal, RunAs: "principal", Command: []string{"/secret", "--token=x"}},
		"git":  {Name: "git", SELinuxType: "mcpsrv_git_t", Network: true},
		"zypp": {Name: "zypp", SELinuxType: "mcpsrv_zypp_t", RunAs: "root", Privileged: true},
	}
	s.Instances = insts

	rec := call(t, s, 1001, "GET", "/v1/servers", "")
	var got []serverInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(got) != 3 || got[0].Name != "fs" || got[1].Name != "git" || got[1].Privileged || !got[2].Privileged {
		t.Fatalf("servers %+v", got)
	}
	if len(got[0].Instances) != 1 || got[0].Instances[0].ID != "i-alice" {
		t.Fatalf("alice sees instances %+v", got[0].Instances)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("command line exposed")
	}

	// Bob cannot stop alice's instance (reported as unknown); alice can.
	if rec := call(t, s, 1002, "DELETE", "/v1/instances/i-alice", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("bob stop: %d", rec.Code)
	}
	if rec := call(t, s, 1001, "DELETE", "/v1/instances/i-alice", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("alice stop: %d", rec.Code)
	}
	// A privileged instance with a call running is not stopped.
	if rec := call(t, s, 1001, "DELETE", "/v1/instances/i-zypp", ""); rec.Code != http.StatusConflict {
		t.Fatalf("busy privileged stop: %d", rec.Code)
	}
	if rec := call(t, s, 1001, "DELETE", "/v1/instances/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown instance: %d", rec.Code)
	}
	if len(insts.stopped) != 1 || insts.stopped[0] != "i-alice" {
		t.Fatalf("stopped %v", insts.stopped)
	}
}

func TestStatus(t *testing.T) {
	s, _, _ := setup(t)
	if rec := call(t, s, 1001, "GET", "/v1/status", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"restart_pending":false`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	s.RestartPending = func() bool { return true }
	if rec := call(t, s, 1001, "GET", "/v1/status", ""); !strings.Contains(rec.Body.String(), `"restart_pending":true`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestPolicyStatus(t *testing.T) {
	s, _, _ := setup(t)
	s.Policy = fakePolicy{"mcp": "r42"}
	rec := call(t, s, 1001, "GET", "/v1/policy", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mode":"bundle"`) || !strings.Contains(rec.Body.String(), `"mcp":"r42"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	s.Policy = fakePolicy{}
	if rec := call(t, s, 1001, "GET", "/v1/policy", ""); !strings.Contains(rec.Body.String(), `"mode":"directories"`) {
		t.Fatalf("%s", rec.Body)
	}
}

type fakeShippedPolicy struct {
	fakePolicy
	shipped string
}

func (f fakeShippedPolicy) ShippedRoles(context.Context) (json.RawMessage, error) {
	return json.RawMessage(f.shipped), nil
}

func TestPolicyShippedRoles(t *testing.T) {
	s, _, _ := setup(t)
	s.Policy = fakeShippedPolicy{fakePolicy{}, `{"systemd": {"roles": {"systemd-reader": {"description": "read",
		"permissions": [{"server": "systemd", "tool": "list_units"}]}}}}`}
	rec := call(t, s, 1001, "GET", "/v1/policy", "")
	var got struct {
		ShippedRoles map[string]shippedRole `json:"shipped_roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	r := got.ShippedRoles["systemd-reader"]
	if r.Setup != "systemd" || r.Description != "read" || !strings.Contains(string(r.Permissions), "list_units") {
		t.Fatalf("shipped roles %+v", got.ShippedRoles)
	}
	// None installed: an empty list, not an error.
	s.Policy = fakeShippedPolicy{fakePolicy{}, ``}
	if rec := call(t, s, 1001, "GET", "/v1/policy", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"shipped_roles":{}`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestEvents(t *testing.T) {
	s, id, _ := setup(t)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return WithPeer(ctx, transport.PeerCred{UID: 1001}) // alice
	}
	srv.Start()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	events := make(chan approvalEvent, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var ev approvalEvent
				if json.Unmarshal([]byte(data), &ev) == nil {
					events <- ev
				}
			}
		}
		close(events)
	}()
	next := func() approvalEvent {
		t.Helper()
		select {
		case ev := <-events:
			return ev
		case <-time.After(3 * time.Second):
			t.Fatal("no event")
		}
		return approvalEvent{}
	}
	// The pending approval of alice's comes first.
	if ev := next(); ev.Type != "pending" || ev.ID != id || ev.Pending == nil || ev.Pending.Name != "write_file" {
		t.Fatalf("initial %+v", ev)
	}
	// Bob's approvals are not alice's to see.
	uid := uint32(1002)
	go func() {
		_, _ = s.Broker.Approve(context.Background(), nopElicitor{}, pep.Input{
			Principal: principal.Principal{Sub: "bob", UID: &uid, SessionID: "s2"}, Action: "tools.call",
			Resource: pep.Resource{Server: "fs", Kind: "tool", Name: "delete_file"},
		}, pep.AskSpec{Channel: pep.ChannelOOB, Scopes: []string{"once"}})
	}()
	// Deciding alice's shows as resolved.
	if rec := call(t, s, 1001, "POST", "/v1/approvals/"+id, `{"decision":"deny"}`); rec.Code != 204 {
		t.Fatalf("deny: %d", rec.Code)
	}
	if ev := next(); ev.Type != "resolved" || ev.ID != id {
		t.Fatalf("got %+v (bob's approval must not show)", ev)
	}
}

type fakeReview struct {
	current json.RawMessage
	got     pep.WhatIfInput
}

func (f *fakeReview) RoleData(context.Context) (json.RawMessage, error) { return f.current, nil }

func (f *fakeReview) WhatIf(_ context.Context, in pep.WhatIfInput) ([]pep.Change, error) {
	f.got = in
	return []pep.Change{
		{Principal: "user:zed", Server: "fs", Kind: "tool", Name: "write_file", Before: "deny", After: "ask"},
		{Principal: "group:dev", Server: "fs", Kind: "tool", Name: "read_file", Before: "deny", After: "allow"},
	}, nil
}

type fakeCatalog struct{}

func (fakeCatalog) Catalog(context.Context) router.Catalog {
	return router.Catalog{
		Resources: []pep.Resource{{Server: "fs", Kind: "tool", Name: "read_file"}},
		Unchecked: map[string]string{"db": "tools and prompts are listed per user (discovery: per-user)"},
	}
}

func TestWhatIf(t *testing.T) {
	s, _, _ := setup(t)
	review := &fakeReview{current: json.RawMessage(`{"roles": {}, "bindings": {"users": {"zed-no-such-user": ["r"]}}}`)}
	s.Review, s.Catalog = review, fakeCatalog{}
	proposed := `{"roles": {}, "bindings": {"users": {"zed": ["r"]}, "groups": {"dev": ["r"]}}}`

	// Without approver policy, only root may review.
	if rec := call(t, s, 1001, "POST", "/v1/policy/whatif", proposed); rec.Code != http.StatusForbidden {
		t.Fatalf("alice: %d %s", rec.Code, rec.Body)
	}
	s.Identify = func(transport.PeerCred) (broker.Approver, error) { return broker.Approver{Name: "root", UID: 0}, nil }
	req := httptest.NewRequest("POST", "/v1/policy/whatif", strings.NewReader(proposed))
	req = req.WithContext(WithPeer(req.Context(), transport.PeerCred{UID: 0}))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("root: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Changes    []pep.Change      `json:"changes"`
		Principals int               `json:"principals"`
		Resources  int               `json:"resources"`
		Unchecked  map[string]string `json:"unchecked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// Sorted by principal; the principals of both role data, users first.
	if len(out.Changes) != 2 || out.Changes[0].Principal != "group:dev" || out.Resources != 1 || out.Unchecked["db"] == "" {
		t.Fatalf("%+v", out)
	}
	var labels []string
	for _, p := range review.got.Principals {
		labels = append(labels, p.Label)
	}
	if strings.Join(labels, " ") != "user:zed user:zed-no-such-user group:dev" || out.Principals != 3 {
		t.Fatalf("principals %v", labels)
	}
	// An unknown user is a remote principal without a local account.
	if p := review.got.Principals[1].Principal; p.UID != nil || p.Transport != principal.TransportHTTP {
		t.Fatalf("unknown user: %+v", p)
	}
	if string(review.got.Proposed) != proposed {
		t.Fatalf("proposed %s", review.got.Proposed)
	}

	req = httptest.NewRequest("POST", "/v1/policy/whatif", strings.NewReader(`[1, 2]`))
	req = req.WithContext(WithPeer(req.Context(), transport.PeerCred{UID: 0}))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("not an object: %d", rec.Code)
	}
}
