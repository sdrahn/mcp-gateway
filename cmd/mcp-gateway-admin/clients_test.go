package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// fixtureAPI is a control API with fixed clients and tasks, as the caller
// may manage them; it records what was ended and cancelled.
type fixtureAPI struct {
	sock      string
	mu        sync.Mutex
	clients   []router.SessionInfo
	tasks     []router.TaskInfo
	ended     []string
	cancelled []string
	// refuse answers every end as the API does a client not the caller's.
	refuse bool
}

var fixtureNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.Local)

func newFixtureAPI(t *testing.T) *fixtureAPI {
	t.Helper()
	// A short path: a socket's path is limited to 108 bytes.
	dir, err := os.MkdirTemp("", "gwctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	api := &fixtureAPI{sock: filepath.Join(dir, "control.sock")}
	uid := uint32(1000)
	api.clients = []router.SessionInfo{
		{ID: "4f1c2a9be0d34711", Kind: "session", Sub: "alice", UID: &uid, Transport: principal.TransportUnix,
			Endpoint: "all", Servers: []string{"fs"}, Client: principal.Client{Name: "kit", Version: "0.3.1"},
			Protocol: "2025-06-18", Capped: "2025-06-18", Started: fixtureNow.Add(-2 * time.Hour), LastActive: fixtureNow.Add(-5 * time.Second)},
		{ID: "4f1c77d0aa0b1c2d", Kind: "session", Sub: "alice", UID: &uid, Transport: principal.TransportUnix,
			Endpoint: "fs", Servers: []string{"fs"}, Client: principal.Client{Name: "claude-code", Version: "2.1"},
			Protocol: "2025-11-25", Started: fixtureNow.Add(-26 * time.Hour), LastActive: fixtureNow.Add(-3 * time.Minute)},
		{ID: "agent-9a8b7c6d5e4f3021", Kind: "agent", Sub: "bob@example.com", Transport: principal.TransportHTTP,
			Endpoint: "all", Servers: []string{"fs"}, Protocol: "2026-07-28", Started: fixtureNow.Add(-time.Minute), LastActive: fixtureNow},
	}
	api.tasks = []router.TaskInfo{
		{ID: "QZ7K3M2WXR5TB4N6YH8JD9CFGA", Server: "zypp", Tool: "update", Sub: "alice", Status: "working", Created: fixtureNow.Add(-10 * time.Minute)},
		{ID: "B2C4D6F8H1J3K5L7M9N0P2Q4R6", Server: "fs", Tool: "search", Sub: "alice", Status: "completed", Created: fixtureNow.Add(-time.Hour)},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, _ *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.clients)
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		for _, c := range api.clients {
			if c.ID == r.PathValue("id") && !api.refuse {
				api.ended = append(api.ended, c.ID)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no such session"}`))
	})
	mux.HandleFunc("GET /v1/tasks", func(w http.ResponseWriter, _ *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.tasks)
	})
	mux.HandleFunc("POST /v1/tasks/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		for _, t := range api.tasks {
			if t.ID != r.PathValue("id") {
				continue
			}
			if t.Status != "working" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"the task has ended"}`))
				return
			}
			api.cancelled = append(api.cancelled, t.ID)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no such task"}`))
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

// runAdmin runs mcp-gateway-admin with args against api, answer on stdin.
func runAdmin(t *testing.T, api *fixtureAPI, answer string, args ...string) (int, string, string) {
	t.Helper()
	defer func(n func() time.Time, in io.Reader) { now, stdin = n, in }(now, stdin)
	now = func() time.Time { return fixtureNow }
	stdin = strings.NewReader(answer)
	var stdout, stderr bytes.Buffer
	rc := run(append(args, "--socket", api.sock), &stdout, &stderr)
	return rc, stdout.String(), stderr.String()
}

func TestClientsList(t *testing.T) {
	api := newFixtureAPI(t)
	rc, out, errs := runAdmin(t, api, "", "clients")
	if rc != 0 {
		t.Fatalf("rc %d: %s", rc, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "USER") {
		t.Fatalf("list:\n%s", out)
	}
	for i, want := range [][]string{
		{"alice", "kit 0.3.1", "2025-06-18 (capped)", "all", "10:00", "5s ago", "4f1c2a9b"},
		{"alice", "claude-code 2.1", "2025-11-25", "fs", "2026-10-14 10:00", "3m ago", "4f1c77d0"},
		{"bob@example.com", "-", "2026-07-28", "all", "11:59", "now", "agent-9a8b7c6d"},
	} {
		for _, w := range want {
			if !strings.Contains(lines[i+1], w) {
				t.Errorf("line %d lacks %q: %s", i+1, w, lines[i+1])
			}
		}
	}
	// The ids are shortened to 8 characters, more where they would clash.
	if strings.Contains(out, "4f1c2a9be") || strings.Contains(out, "agent-9a8b7c6d5") {
		t.Errorf("ids not shortened:\n%s", out)
	}

	rc, out, _ = runAdmin(t, api, "", "clients", "--json")
	var got []router.SessionInfo
	if rc != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got) != 3 || got[2].ID != "agent-9a8b7c6d5e4f3021" {
		t.Errorf("--json: %d %s", rc, out)
	}

	api.clients = nil
	if rc, out, _ = runAdmin(t, api, "", "clients"); rc != 0 || out != "no clients\n" {
		t.Errorf("none: %d %q", rc, out)
	}
}

func TestClientsEnd(t *testing.T) {
	api := newFixtureAPI(t)
	// A prefix, the options after the words.
	if rc, out, errs := runAdmin(t, api, "", "clients", "end", "4f1c2a", "--yes"); rc != 0 || !strings.Contains(out, "ended 4f1c2a9b (kit 0.3.1 of alice)") {
		t.Errorf("--yes: %d %s %s", rc, out, errs)
	}
	// Asked, answered yes.
	if rc, _, errs := runAdmin(t, api, "y\n", "clients", "end", "agent-9a8b"); rc != 0 ||
		!strings.Contains(errs, "End the client - of bob@example.com on all (agent-9a8b7c6d)? [y/N]") {
		t.Errorf("yes: %d %s", rc, errs)
	}
	// Answered no, or not at all.
	for _, answer := range []string{"n\n", ""} {
		if rc, _, errs := runAdmin(t, api, answer, "clients", "end", "4f1c77d0aa0b1c2d"); rc != exitRefused || !strings.Contains(errs, "not ended") {
			t.Errorf("answer %q: %d %s", answer, rc, errs)
		}
	}
	if want := []string{"4f1c2a9be0d34711", "agent-9a8b7c6d5e4f3021"}; strings.Join(api.ended, " ") != strings.Join(want, " ") {
		t.Errorf("ended %v, want %v", api.ended, want)
	}
	// An ambiguous prefix, an id not listed (unknown, or another's).
	if rc, _, errs := runAdmin(t, api, "", "clients", "end", "4f1c", "--yes"); rc != exitRefused || !strings.Contains(errs, "4f1c names 2 clients") {
		t.Errorf("ambiguous: %d %s", rc, errs)
	}
	if rc, _, errs := runAdmin(t, api, "", "clients", "end", "77", "--yes"); rc != exitRefused || !strings.Contains(errs, "no such client: 77") {
		t.Errorf("unknown: %d %s", rc, errs)
	}
	// Listed, but refused when ended (it went meanwhile, or the rules
	// changed): as unknown.
	api.refuse = true
	if rc, _, errs := runAdmin(t, api, "", "clients", "end", "4f1c77", "--yes"); rc != exitRefused || !strings.Contains(errs, "no such client: 4f1c77") {
		t.Errorf("refused: %d %s", rc, errs)
	}
}

func TestTasks(t *testing.T) {
	api := newFixtureAPI(t)
	rc, out, errs := runAdmin(t, api, "", "tasks")
	if rc != 0 || !strings.Contains(out, "SERVER") {
		t.Fatalf("rc %d: %s %s", rc, out, errs)
	}
	for _, w := range []string{"zypp", "update", "alice", "11:50", "working", "QZ7K3M2W", "completed", "B2C4D6F8"} {
		if !strings.Contains(out, w) {
			t.Errorf("list lacks %q:\n%s", w, out)
		}
	}
	if rc, out, _ := runAdmin(t, api, "", "tasks", "--json"); rc != 0 || !strings.Contains(out, `"QZ7K3M2WXR5TB4N6YH8JD9CFGA"`) {
		t.Errorf("--json: %d %s", rc, out)
	}
	if rc, out, errs := runAdmin(t, api, "", "tasks", "cancel", "QZ7"); rc != 0 || !strings.Contains(out, "cancelled QZ7K3M2W (zypp update of alice)") {
		t.Errorf("cancel: %d %s %s", rc, out, errs)
	}
	if rc, _, errs := runAdmin(t, api, "", "tasks", "cancel", "B2C"); rc != exitRefused || !strings.Contains(errs, "the task has ended") {
		t.Errorf("ended: %d %s", rc, errs)
	}
	if rc, _, errs := runAdmin(t, api, "", "tasks", "cancel", "ZZ"); rc != exitRefused || !strings.Contains(errs, "no such task: ZZ") {
		t.Errorf("unknown: %d %s", rc, errs)
	}
	if len(api.cancelled) != 1 || api.cancelled[0] != "QZ7K3M2WXR5TB4N6YH8JD9CFGA" {
		t.Errorf("cancelled %v", api.cancelled)
	}
}

// Wrong usage exits 2, -h 0; a gateway that does not answer, 3.
func TestClientsUsageAndUnreachable(t *testing.T) {
	api := newFixtureAPI(t)
	for _, args := range [][]string{{"clients", "nope"}, {"clients", "end"}, {"clients", "end", "a", "b"},
		{"tasks", "cancel"}, {"tasks", "end", "x"}, {"clients", "--nope"}, {"tasks", "--yes"}} {
		if rc, _, errs := runAdmin(t, api, "", args...); rc != exitUsage || !strings.Contains(errs, "usage: mcp-gateway-admin "+args[0]) {
			t.Errorf("%v: %d %s", args, rc, errs)
		}
	}
	for _, name := range []string{"clients", "tasks"} {
		if rc, _, errs := runAdmin(t, api, "", name, "-h"); rc != 0 || !strings.Contains(errs, "Exit status:") {
			t.Errorf("%s -h: %d %s", name, rc, errs)
		}
	}
	gone := &fixtureAPI{sock: filepath.Join(t.TempDir(), "control.sock")}
	for _, name := range []string{"clients", "tasks"} {
		if rc, _, errs := runAdmin(t, gone, "", name); rc != exitUnreachable ||
			!strings.Contains(errs, "the gateway does not answer at "+gone.sock+": is it running?") {
			t.Errorf("%s, not running: %d %s", name, rc, errs)
		}
	}
}

func TestShortIDs(t *testing.T) {
	got := shortIDs([]string{"abcdef0123", "abcdef0199", "agent-0123456789", "short", "abcdef01"})
	want := []string{"abcdef012", "abcdef019", "agent-01234567", "short", "abcdef01"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}
}
