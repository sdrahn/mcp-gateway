package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The trees a server keeps to: the system read, the programs executed,
// what the commands name (written unless read_only), what the file's
// landlock adds.
func TestLandlockRules(t *testing.T) {
	cmds := commands(t, `version: 1
landlock:
  write: [/srv/spool]
  exec: [/opt/tool/lib]
commands:
  logs:
    argv: [/usr/bin/journalctl, --directory=/var/log/journal, -u, "{unit}"]
    args: {unit: {pattern: "[a-z.-]+"}}
    read_only: true
  tail:
    argv: [/usr/bin/tail, "/var/log/app/{name}.log"]
    args: {name: {pattern: "[a-z]+"}}
    read_only: true
  rotate:
    argv: [/opt/tool/bin/rotate, /var/lib/app]
    dir: /srv/app
  echo:
    argv: [/usr/bin/echo, "{text}", relative/path, -n]
    args: {text: {pattern: ".*"}}
    read_only: true
`)
	r := landlockRules(cmds)
	want := map[string][]string{
		"read":  {"/run", "/var", "/var/log/app", "/var/log/journal"},
		"write": {"/srv/app", "/srv/spool", "/var/lib/app"},
		"exec":  {"/opt/tool/bin/rotate", "/opt/tool/lib", "/usr/bin/echo", "/usr/bin/journalctl", "/usr/bin/tail"},
	}
	for k, got := range map[string][]string{"read": r.Read, "write": r.Write, "exec": r.Exec} {
		if !slices.Equal(got, want[k]) {
			t.Errorf("%s: %v, want %v", k, got, want[k])
		}
	}
	if r.TCPConnect != nil || r.TCPBind != nil {
		t.Errorf("TCP %v %v: left to the definition", r.TCPConnect, r.TCPBind)
	}
}

func TestNamedPath(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/os-release": "/etc/os-release", "/var/log/{unit}": "/var/log", "/var/log/a-{x}.log": "/var/log",
		"--file=/etc/x": "/etc/x", "--file=rel": "", "-h": "", "{path}": "", "rel/x": "", "/a/../b": "/b",
	} {
		if got := namedPath(in); got != want {
			t.Errorf("namedPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A command file's landlock: trees, absolute, nothing expanded.
func TestLandlockKey(t *testing.T) {
	for _, bad := range []string{
		"landlock: {tcp_connect: [443]}", "landlock: {required: true}", "landlock: {read: [var]}",
		"landlock: {write: [\"${HOME}\"]}", "landlock: {network: true}",
	} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte("version: 1\n"+bad+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := load([]string{p}); err == nil || !strings.Contains(err.Error(), "landlock") && !strings.Contains(err.Error(), "network") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
