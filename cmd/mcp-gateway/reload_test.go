package main

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

type auditRecord struct {
	op     string
	ok     bool
	fields map[string]string
}

type fakeAudit struct {
	mu      sync.Mutex
	records []auditRecord
}

func (a *fakeAudit) Event(op string, ok bool, fields map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, auditRecord{op, ok, fields})
}

func (a *fakeAudit) last() auditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.records) == 0 {
		return auditRecord{}
	}
	return a.records[len(a.records)-1]
}

// testReloader reloads from a vendor and an admin directory into a router
// that serves fs and git.
func testReloader(t *testing.T) (*serverReloader, *router.Router, *fakeAudit, string, string) {
	t.Helper()
	vendor, admin := t.TempDir(), t.TempDir()
	write(t, vendor, "fs.yaml", "name: fs\ncommand: [/usr/libexec/fs]\n")
	write(t, vendor, "git.yaml", "name: git\ncommand: [/usr/libexec/git]\n")
	initial, err := config.LoadBackends(vendor, admin)
	if err != nil {
		t.Fatal(err)
	}
	r := &router.Router{Backends: initial, Log: slog.New(slog.DiscardHandler)}
	a := &fakeAudit{}
	l := &serverReloader{log: slog.New(slog.DiscardHandler), audit: a, dirs: []string{vendor, admin},
		load: config.LoadBackends, set: r.SetBackends}
	return l, r, a, vendor, admin
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func serverNames(r *router.Router) string {
	return strings.Join(slices.Sorted(maps.Keys(r.CurrentBackends())), ",")
}

func TestReload(t *testing.T) {
	l, r, a, vendor, admin := testReloader(t)
	write(t, admin, "web.yaml", "name: web\ncommand: [/opt/web]\nnetwork: true\n")
	write(t, admin, "git.yaml", "name: git\ncommand: [/opt/git]\n") // overrides the vendor's
	if err := os.Remove(filepath.Join(vendor, "fs.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := l.reload("test"); err != nil || l.Err() != "" {
		t.Fatalf("%v %q", err, l.Err())
	}
	if got := serverNames(r); got != "git,web" || r.CurrentBackends()["git"].Command[0] != "/opt/git" {
		t.Fatalf("servers %s", got)
	}
	rec := a.last()
	if rec.op != "mcp-config-reload" || !rec.ok || rec.fields["added"] != "web" || rec.fields["changed"] != "git" ||
		rec.fields["removed"] != "fs" || rec.fields["trigger"] != "test" {
		t.Fatalf("audit %+v", rec)
	}
	// Nothing changed: no audit record.
	n := len(a.records)
	if err := l.reload("test"); err != nil || len(a.records) != n {
		t.Fatalf("%v %+v", err, a.records)
	}
}

// A definition that does not load, for any reason, leaves the gateway
// serving the definitions it had, and says why until a reload succeeds.
func TestReloadKeepsDefinitionsOnError(t *testing.T) {
	for name, tc := range map[string]struct {
		file, content string
		want          string
	}{
		"broken yaml": {"web.yaml", "name: web\ncommand: [/opt/web\n", "web.yaml"},
		"unknown key": {"web.yaml", "name: web\ncommand: [/opt/web]\nnetwrok: true\n", "netwrok"},
		"invalid":     {"web.yaml", "name: web\ncommand: [opt/web]\n", "absolute path"},
		"duplicate":   {"web.yaml", "name: fs\ncommand: [/opt/fs]\n", "fs"},
		"privileged":  {"zypp.yaml", "name: zypp\ncommand: [/usr/bin/zypp]\nrun_as: root\nprivileged: true\n", "privileged"},
		"not a file":  {"web.yaml", "", "web.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			l, r, a, vendor, admin := testReloader(t)
			switch name {
			case "privileged": // only allowed in the admin directory
				write(t, vendor, tc.file, tc.content)
			case "not a file":
				if err := os.Mkdir(filepath.Join(admin, tc.file), 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				write(t, admin, tc.file, tc.content)
			}
			err := l.reload("test")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
			if got := serverNames(r); got != "fs,git" {
				t.Fatalf("servers %s", got)
			}
			if l.Err() != err.Error() {
				t.Fatalf("Err %q", l.Err())
			}
			if rec := a.last(); rec.op != "mcp-config-reload" || rec.ok || rec.fields["error"] != err.Error() {
				t.Fatalf("audit %+v", rec)
			}
			// Fixed: the next reload succeeds and clears the error.
			for _, f := range []string{filepath.Join(admin, "web.yaml"), filepath.Join(vendor, "zypp.yaml")} {
				_ = os.Remove(f)
			}
			if err := l.reload("test"); err != nil || l.Err() != "" {
				t.Fatalf("%v %q", err, l.Err())
			}
		})
	}
}

func TestReloadRefusesNoDefinitions(t *testing.T) {
	l, r, _, vendor, _ := testReloader(t)
	for _, f := range []string{"fs.yaml", "git.yaml"} {
		_ = os.Remove(filepath.Join(vendor, f))
	}
	if err := l.reload("test"); err == nil || !strings.Contains(err.Error(), "no server definitions") {
		t.Fatalf("got %v", err)
	}
	if got := serverNames(r); got != "fs,git" {
		t.Fatalf("servers %s", got)
	}
}

func TestReloadRecoversPanics(t *testing.T) {
	for _, where := range []string{"load", "set"} {
		l, r, a, _, admin := testReloader(t)
		write(t, admin, "web.yaml", "name: web\ncommand: [/opt/web]\n")
		if where == "load" {
			l.load = func(...string) (map[string]*config.Backend, error) { panic("boom") }
		} else {
			l.set = func(map[string]*config.Backend) router.BackendChanges { panic("boom") }
		}
		err := l.reload("test")
		if err == nil || !strings.Contains(err.Error(), "boom") || !strings.Contains(l.Err(), "boom") {
			t.Fatalf("%s: got %v", where, err)
		}
		if got := serverNames(r); got != "fs,git" {
			t.Fatalf("%s: servers %s", where, got)
		}
		if rec := a.last(); rec.ok {
			t.Fatalf("%s: audit %+v", where, rec)
		}
		// The reloader still works.
		l.load, l.set = config.LoadBackends, r.SetBackends
		if err := l.reload("test"); err != nil || serverNames(r) != "fs,git,web" {
			t.Fatalf("%s: %v %s", where, err, serverNames(r))
		}
	}
}

func TestReloadWatch(t *testing.T) {
	l, r, a, _, admin := testReloader(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hup := make(chan os.Signal, 1)
	go l.watch(ctx, 10*time.Millisecond, serversFingerprint(l.dirs), hup)

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for range 500 {
			if cond() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal(what)
	}
	write(t, admin, "web.yaml", "name: web\ncommand: [/opt/web]\n")
	waitFor("new file not loaded", func() bool { return serverNames(r) == "fs,git,web" })

	// A broken edit is reported once, not at every check.
	write(t, admin, "web.yaml", "name: web\ncommand: [/opt/web\n")
	waitFor("broken file not reported", func() bool { return l.Err() != "" })
	count := func() int {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.records)
	}
	n := count()
	time.Sleep(50 * time.Millisecond)
	if count() != n {
		t.Fatal("reported again")
	}
	if got := serverNames(r); got != "fs,git,web" {
		t.Fatalf("servers %s", got)
	}

	// SIGHUP reloads although the files did not change.
	hup <- os.Interrupt
	waitFor("SIGHUP not handled", func() bool { return a.last().fields["trigger"] == "SIGHUP" })

	write(t, admin, "web.yaml", "name: web\ncommand: [/opt/web2]\n")
	waitFor("fix not loaded", func() bool {
		b := r.CurrentBackends()["web"]
		return l.Err() == "" && b != nil && b.Command[0] == "/opt/web2"
	})
}

func TestServersFingerprint(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	fp := func() string { return serversFingerprint([]string{a, b}) }
	empty := fp()
	write(t, a, "x.yaml", "name: x\n")
	one := fp()
	write(t, a, "notes.txt", "ignored")
	if one == empty || fp() != one {
		t.Fatal("fingerprint does not follow the definition files")
	}
	write(t, a, "x.yaml", "name: y\n")
	if fp() == one {
		t.Fatal("edit not noticed")
	}
	edited := fp()
	if err := os.Rename(filepath.Join(a, "x.yaml"), filepath.Join(b, "x.yaml")); err != nil {
		t.Fatal(err)
	}
	if fp() == edited {
		t.Fatal("move to the other directory not noticed")
	}
}
