package main

import (
	"encoding/json"
	"fmt"

	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// approvalsAPI is a control API with fixed pending approvals and grants;
// it records the decisions and revocations, with their bodies and
// queries.
type approvalsAPI struct {
	sock      string
	mu        sync.Mutex
	pending   []broker.Pending
	grants    []pep.Grant
	decisions []map[string]string // id, decision, scope, via
	revoked   []string            // id?query
	events    []string            // data lines of /v1/events
}

func newApprovalsAPI(t *testing.T) *approvalsAPI {
	t.Helper()
	dir, err := os.MkdirTemp("", "gwapr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	api := &approvalsAPI{sock: filepath.Join(dir, "control.sock")}
	uid := uint32(1000)
	alice := principal.Principal{Sub: "alice", UID: &uid, Transport: principal.TransportUnix,
		Client: principal.Client{Name: "kit", Version: "0.3.1"}}
	api.pending = []broker.Pending{
		{ID: "a-7f3e9c2b11d04a55", Channel: pep.ChannelOOB, Principal: alice, Action: "tools.call", Server: "fs",
			Name: "write_file", Args: map[string]any{"path": "/home/alice/notes.txt"}, Scopes: []string{"once", "session"},
			Created: fixtureNow.Add(-30 * time.Second), Expires: fixtureNow.Add(90 * time.Second), Waiting: true},
		{ID: "a-7f3e00aa22b13c66", Channel: pep.ChannelOOB, Principal: alice, Action: "tools.call", Server: "zypp",
			Name: "install", Scopes: []string{"1h", "8h"},
			Created: fixtureNow.Add(-time.Minute), Expires: fixtureNow.Add(time.Minute), Waiting: false},
	}
	api.grants = []pep.Grant{
		{ID: "g-1a2b3c4d", Sub: "alice", UID: &uid, Server: "fs", Tool: "read_file", Scope: "session",
			Expires: fixtureNow.Add(2 * time.Hour).UTC().Format(time.RFC3339), ApprovedBy: "alice", Channel: pep.ChannelOOB},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals", func(w http.ResponseWriter, _ *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.pending)
	})
	mux.HandleFunc("POST /v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		for i, p := range api.pending {
			if p.ID != r.PathValue("id") {
				continue
			}
			body["id"] = p.ID
			api.decisions = append(api.decisions, body)
			api.pending = append(api.pending[:i], api.pending[i+1:]...)
			if body["decision"] == "deny" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(pep.Grant{ID: "g-new", Scope: body["scope"]})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no such approval"}`))
	})
	mux.HandleFunc("GET /v1/grants", func(w http.ResponseWriter, _ *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.grants)
	})
	mux.HandleFunc("DELETE /v1/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		for _, g := range api.grants {
			if g.ID == r.PathValue("id") {
				api.revoked = append(api.revoked, g.ID+"?"+r.URL.RawQuery)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no such grant"}`))
	})
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, _ *http.Request) {
		api.mu.Lock()
		events := api.events
		api.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		for _, e := range events {
			_, _ = fmt.Fprintf(w, "event: approval\ndata: %s\n\n: ping\n\n", e)
		}
		// The stream ends: as a gateway that stops.
	})
	l, err := net.Listen("unix", api.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return api
}

// runApprovals runs mcp-gateway-admin with args against api.
func runApprovalsCmd(t *testing.T, api *approvalsAPI, answer string, args ...string) (int, string, string) {
	t.Helper()
	return runAdmin(t, &fixtureAPI{sock: api.sock}, answer, args...)
}

func TestApprovalsList(t *testing.T) {
	api := newApprovalsAPI(t)
	rc, out, errs := runApprovalsCmd(t, api, "", "approvals")
	if rc != 0 {
		t.Fatalf("rc %d: %s", rc, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "USER") {
		t.Fatalf("list:\n%s", out)
	}
	// Oldest first.
	for i, want := range [][]string{
		{"alice", "zypp/install", "kit 0.3.1", "1h,8h", "1m ago", "in 1m", "no", "a-7f3e00"},
		{"alice", "fs/write_file", "once,session", "30s ago", "in 1m", "yes", "a-7f3e9c"},
	} {
		for _, w := range want {
			if !strings.Contains(lines[i+1], w) {
				t.Errorf("line %d lacks %q: %s", i+1, w, lines[i+1])
			}
		}
	}
	rc, out, _ = runApprovalsCmd(t, api, "", "approvals", "--json")
	var got []broker.Pending
	if rc != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got) != 2 {
		t.Errorf("--json: %d %s", rc, out)
	}
	api.pending = nil
	if rc, out, _ = runApprovalsCmd(t, api, "", "approvals"); rc != 0 || out != "no pending approvals\n" {
		t.Errorf("none: %d %q", rc, out)
	}
}

func TestApprovalsShow(t *testing.T) {
	api := newApprovalsAPI(t)
	rc, out, errs := runApprovalsCmd(t, api, "", "approvals", "show", "a-7f3e9")
	if rc != 0 {
		t.Fatalf("rc %d: %s", rc, errs)
	}
	for _, w := range []string{"a-7f3e9c2b11d04a55", "fs/write_file", "kit 0.3.1", "oob", "once, session",
		"yes, the call waits", `"path": "/home/alice/notes.txt"`} {
		if !strings.Contains(out, w) {
			t.Errorf("show lacks %q:\n%s", w, out)
		}
	}
	if rc, out, _ := runApprovalsCmd(t, api, "", "approvals", "show", "a-7f3e00"); rc != 0 ||
		!strings.Contains(out, "agent's next attempt finds the decision") || !strings.Contains(out, "Arguments: none") {
		t.Errorf("not waiting: %d %s", rc, out)
	}
	if rc, out, _ := runApprovalsCmd(t, api, "", "approvals", "show", "a-7f3e9", "--json"); rc != 0 || !strings.Contains(out, `"write_file"`) {
		t.Errorf("--json: %d %s", rc, out)
	}
}

func TestApprovalsDecide(t *testing.T) {
	api := newApprovalsAPI(t)
	// Asked, and answered no: nothing decided.
	if rc, _, errs := runApprovalsCmd(t, api, "n\n", "approvals", "approve", "a-7f3e9"); rc != exitRefused ||
		!strings.Contains(errs, "Approve fs/write_file for alice (a-7f3e9c, scope once)? [y/N]") || !strings.Contains(errs, "not approved") {
		t.Errorf("no: %d %s", rc, errs)
	}
	// Yes: "once" by default, via the command line.
	if rc, out, errs := runApprovalsCmd(t, api, "y\n", "approvals", "approve", "a-7f3e9"); rc != 0 ||
		!strings.Contains(out, "approved a-7f3e9c (fs/write_file for alice, scope once)") {
		t.Errorf("yes: %d %s %s", rc, out, errs)
	}
	// Without "once" and with two scopes, --scope is needed; one not
	// offered is refused before asking the gateway.
	if rc, _, errs := runApprovalsCmd(t, api, "", "approvals", "approve", "a-7f3e00", "--yes"); rc != exitRefused ||
		!strings.Contains(errs, "offers the scopes 1h, 8h: name one with --scope") {
		t.Errorf("no scope: %d %s", rc, errs)
	}
	if rc, _, errs := runApprovalsCmd(t, api, "", "approvals", "approve", "a-7f3e00", "--scope", "30d", "--yes"); rc != exitRefused ||
		!strings.Contains(errs, `offers the scopes 1h, 8h, not "30d"`) {
		t.Errorf("bad scope: %d %s", rc, errs)
	}
	// A call that went away: the decision waits for the next attempt.
	if rc, out, errs := runApprovalsCmd(t, api, "", "approvals", "approve", "a-7f3e00", "--scope", "1h", "--yes"); rc != 0 ||
		!strings.Contains(out, "scope 1h") || !strings.Contains(out, "next attempt finds the decision") {
		t.Errorf("1h: %d %s %s", rc, out, errs)
	}
	want := []string{"a-7f3e9c2b11d04a55 approve once cli", "a-7f3e00aa22b13c66 approve 1h cli"}
	var got []string
	for _, d := range api.decisions {
		got = append(got, d["id"]+" "+d["decision"]+" "+d["scope"]+" "+d["via"])
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("decisions %v, want %v", got, want)
	}
	// Both are gone now: unknown.
	if rc, _, errs := runApprovalsCmd(t, api, "", "approvals", "deny", "a-7f3e9"); rc != exitRefused || !strings.Contains(errs, "no such approval: a-7f3e9") {
		t.Errorf("gone: %d %s", rc, errs)
	}
}

func TestApprovalsDeny(t *testing.T) {
	api := newApprovalsAPI(t)
	// Denying asks nothing.
	if rc, out, errs := runApprovalsCmd(t, api, "", "approvals", "deny", "a-7f3e9"); rc != 0 ||
		!strings.Contains(out, "denied a-7f3e9c (fs/write_file for alice)") {
		t.Errorf("deny: %d %s %s", rc, out, errs)
	}
	if len(api.decisions) != 1 || api.decisions[0]["decision"] != "deny" || api.decisions[0]["via"] != "cli" {
		t.Errorf("decisions %v", api.decisions)
	}
	// An ambiguous prefix.
	api = newApprovalsAPI(t)
	if rc, _, errs := runApprovalsCmd(t, api, "", "approvals", "deny", "a-7f3e"); rc != exitRefused || !strings.Contains(errs, "a-7f3e names 2 approvals") {
		t.Errorf("ambiguous: %d %s", rc, errs)
	}
}

func TestApprovalsWatch(t *testing.T) {
	api := newApprovalsAPI(t)
	p := api.pending[0]
	pending, _ := json.Marshal(map[string]any{"type": "pending", "id": p.ID, "new": true, "pending": p})
	api.events = []string{string(pending), `{"type":"resolved","id":"` + p.ID + `"}`, `{"type":"resolved","id":"a-other"}`}
	rc, out, errs := runApprovalsCmd(t, api, "", "approvals", "watch")
	// The stream ended: as a gateway that went away.
	if rc != exitUnreachable || !strings.Contains(errs, "the gateway ended the stream") {
		t.Errorf("rc %d: %s", rc, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "pending a-7f3e9c2b11d04a55 fs/write_file for alice (scopes once, session; expires 12:01") ||
		!strings.Contains(lines[1], "gone    a-7f3e9c2b11d04a55 fs/write_file for alice (decided or expired)") ||
		!strings.Contains(lines[2], "gone    a-other") {
		t.Errorf("watch:\n%s", out)
	}
	if rc, out, _ := runApprovalsCmd(t, api, "", "approvals", "watch", "--json"); rc != exitUnreachable ||
		strings.Count(out, "\n") != 3 || !strings.HasPrefix(out, `{"id":"a-7f3e9c2b11d04a55"`) {
		t.Errorf("--json: %d %s", rc, out)
	}
}

func TestGrants(t *testing.T) {
	api := newApprovalsAPI(t)
	rc, out, errs := runApprovalsCmd(t, api, "", "grants")
	if rc != 0 {
		t.Fatalf("rc %d: %s", rc, errs)
	}
	for _, w := range []string{"USER", "alice", "fs/read_file", "session", "14:00 (in 2h)", "g-1a2b3c"} {
		if !strings.Contains(out, w) {
			t.Errorf("list lacks %q:\n%s", w, out)
		}
	}
	if rc, _, errs := runApprovalsCmd(t, api, "n\n", "grants", "revoke", "g-1a"); rc != exitRefused ||
		!strings.Contains(errs, "Revoke the grant of fs/read_file for alice (g-1a2b3c)? [y/N]") {
		t.Errorf("no: %d %s", rc, errs)
	}
	if rc, out, errs := runApprovalsCmd(t, api, "", "grants", "revoke", "g-1a", "--yes"); rc != 0 ||
		!strings.Contains(out, "revoked g-1a2b3c (fs/read_file for alice)") {
		t.Errorf("revoke: %d %s %s", rc, out, errs)
	}
	if len(api.revoked) != 1 || api.revoked[0] != "g-1a2b3c4d?via=cli" {
		t.Errorf("revoked %v", api.revoked)
	}
	if rc, _, errs := runApprovalsCmd(t, api, "", "grants", "revoke", "g-9", "--yes"); rc != exitRefused || !strings.Contains(errs, "no such grant: g-9") {
		t.Errorf("unknown: %d %s", rc, errs)
	}
}

func TestApprovalsUsage(t *testing.T) {
	api := newApprovalsAPI(t)
	for _, args := range [][]string{{"approvals", "nope"}, {"approvals", "approve"}, {"approvals", "watch", "x"},
		{"approvals", "show", "a", "b"}, {"grants", "revoke"}, {"grants", "drop", "x"}} {
		if rc, _, errs := runApprovalsCmd(t, api, "", args...); rc != exitUsage || !strings.Contains(errs, "usage: mcp-gateway-admin "+args[0]) {
			t.Errorf("%v: %d %s", args, rc, errs)
		}
	}
	for _, name := range []string{"approvals", "grants"} {
		if rc, _, errs := runApprovalsCmd(t, api, "", name, "-h"); rc != 0 || !strings.Contains(errs, "Exit status:") {
			t.Errorf("%s -h: %d %s", name, rc, errs)
		}
	}
	gone := &approvalsAPI{sock: filepath.Join(t.TempDir(), "control.sock")}
	for _, args := range [][]string{{"approvals"}, {"approvals", "watch"}, {"grants"}} {
		if rc, _, errs := runApprovalsCmd(t, gone, "", args...); rc != exitUnreachable || !strings.Contains(errs, "is it running?") {
			t.Errorf("%v, not running: %d %s", args, rc, errs)
		}
	}
}

func TestPickScope(t *testing.T) {
	for _, c := range []struct {
		offered []string
		asked   string
		want    string
		ok      bool
	}{
		{[]string{"once", "session"}, "", "once", true},
		{[]string{"session"}, "", "session", true},
		{[]string{"1h", "8h"}, "", "", false},
		{[]string{"1h", "8h"}, "8h", "8h", true},
		{[]string{"once"}, "session", "session", false},
	} {
		if got, ok := pickScope(c.offered, c.asked); got != c.want || ok != c.ok {
			t.Errorf("%v %q: %q %v", c.offered, c.asked, got, ok)
		}
	}
}
