package main

import (
	"context"
	"errors"
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
	go l.watch(ctx, func() time.Duration { return 10 * time.Millisecond }, l.fingerprint(), hup)

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

// testConfigReloader adds gateway.yaml to testReloader: its file, and the
// configurations applyConfig was given.
func testConfigReloader(t *testing.T) (*serverReloader, *fakeAudit, string, *[]*config.Gateway) {
	t.Helper()
	l, _, a, vendor, admin := testReloader(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	base := "servers_dir: " + admin + "\nvendor_servers_dir: " + vendor + "\nsocket_group: mcp-users\n"
	write(t, dir, "gateway.yaml", base)
	running, err := config.LoadGateway(path)
	if err != nil {
		t.Fatal(err)
	}
	var applied []*config.Gateway
	l.loadConfig = func() (*config.Gateway, error) {
		g, _, err := config.Resolve(path)
		return g, err
	}
	l.applyConfig = func(g *config.Gateway) error {
		applied = append(applied, g)
		return nil
	}
	l.running, l.current = running, running
	l.configFiles = func(*config.Gateway) []string { return []string{path} }
	return l, a, path, &applied
}

func TestReloadConfig(t *testing.T) {
	l, a, path, applied := testConfigReloader(t)
	dir, base := filepath.Dir(path), func() string {
		b, _ := os.ReadFile(path)
		return string(b)
	}()

	// A reloadable key is applied and audited; nothing needs a restart.
	write(t, dir, "gateway.yaml", base+"approval_timeout: 5m\nlimits:\n  instances: 7\n")
	if err := l.reload("test"); err != nil || l.ConfigErr() != "" {
		t.Fatalf("%v %q", err, l.ConfigErr())
	}
	if n := len(*applied); n != 1 || (*applied)[0].ApprovalTimeout != 5*time.Minute || (*applied)[0].Limits.Instances != 7 {
		t.Fatalf("applied %+v", *applied)
	}
	if len(l.RestartNeeded()) != 0 {
		t.Fatalf("restart needed %v", l.RestartNeeded())
	}
	rec := a.last()
	if rec.op != "mcp-config-reload" || !rec.ok || rec.fields["changed"] != "approval_timeout,limits.instances" {
		t.Fatalf("audit %+v", rec)
	}

	// A key bound to the start is reported; the reloadable ones still apply.
	write(t, dir, "gateway.yaml", strings.Replace(base, "mcp-users", "other", 1)+"approval_timeout: 1m\n")
	if err := l.reload("test"); err != nil {
		t.Fatal(err)
	}
	if got := l.RestartNeeded(); !slices.Equal(got, []string{"socket_group"}) {
		t.Fatalf("restart needed %v", got)
	}
	if (*applied)[len(*applied)-1].ApprovalTimeout != time.Minute {
		t.Fatal("reloadable key not applied")
	}

	// A file that does not load changes nothing and is reported until fixed.
	n := len(*applied)
	for name, content := range map[string]string{
		"broken yaml": "approval_timeout: [\n",
		"unknown key": base + "aproval_timeout: 1m\n",
		"invalid":     base + "policy:\n  watch_interval: 1ms\n",
		"no version":  "version: 99\n",
	} {
		write(t, dir, "gateway.yaml", content)
		err := l.reload("test")
		if err == nil || l.ConfigErr() == "" || len(*applied) != n {
			t.Fatalf("%s: %v %q, %d applied", name, err, l.ConfigErr(), len(*applied))
		}
		if rec := a.last(); rec.ok || rec.fields["file"] != "gateway.yaml" {
			t.Fatalf("%s: audit %+v", name, rec)
		}
		if l.current.ApprovalTimeout != time.Minute {
			t.Fatalf("%s: the configuration in force changed", name)
		}
	}
	write(t, dir, "gateway.yaml", base)
	if err := l.reload("test"); err != nil || l.ConfigErr() != "" {
		t.Fatalf("fixed: %v %q", err, l.ConfigErr())
	}
}

// An error or a panic while applying keeps the configuration in force.
func TestReloadConfigApplyFails(t *testing.T) {
	l, _, path, _ := testConfigReloader(t)
	b, _ := os.ReadFile(path)
	write(t, filepath.Dir(path), "gateway.yaml", string(b)+"approval_timeout: 3m\n")
	for _, apply := range []func(*config.Gateway) error{
		func(*config.Gateway) error { return errors.New("http.cert_file: no such file") },
		func(*config.Gateway) error { panic("boom") },
	} {
		l.applyConfig = apply
		if err := l.reload("test"); err == nil || l.ConfigErr() == "" {
			t.Fatalf("%v %q", err, l.ConfigErr())
		}
		if l.current.ApprovalTimeout == 3*time.Minute {
			t.Fatal("configuration in force changed")
		}
		// The server definitions are reloaded all the same.
		if l.Err() != "" {
			t.Fatalf("servers: %q", l.Err())
		}
	}
}

// Editing gateway.yaml triggers a reload, at the interval in force.
func TestReloadWatchConfig(t *testing.T) {
	l, _, path, applied := testConfigReloader(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.watch(ctx, func() time.Duration { return 10 * time.Millisecond }, l.fingerprint(), make(chan os.Signal))
	b, _ := os.ReadFile(path)
	write(t, filepath.Dir(path), "gateway.yaml", string(b)+"approval_timeout: 2m\n")
	for range 500 {
		l.mu.Lock()
		n := len(*applied)
		l.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("an edit of gateway.yaml was not noticed")
}
