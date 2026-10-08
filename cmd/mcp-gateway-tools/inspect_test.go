package main

import (
	"bytes"
	"io"
	"os"
	"slices"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/landlock"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

func TestInspectUsage(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
	}{
		{nil, 2}, // neither -server nor a command
		{[]string{"-server", "x", "--", "/bin/true"}, 2}, // both
		{[]string{"--", "/bin/true"}, 2},                 // a command without -name
		{[]string{"-h"}, 0},
		{[]string{"-server", "x", "-home"}, 2}, // -home without a command or -exec
	} {
		var out, errOut bytes.Buffer
		if got := runInspect(c.args, &out, &errOut); got != c.code {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, got, c.code, errOut.String())
		}
	}
}

// A server without systemd runs under Landlock: the system read-only, a
// directory of its own as home, its program and named paths executable,
// no TCP; -home, -network and -allow widen that, and a definition's own
// landlock stays.
func TestUnderLandlock(t *testing.T) {
	config.LandlockLauncher = os.Args[0] // installed or not, it exists
	prog, _ := os.Executable()
	for _, c := range []struct {
		sb  sandbox
		def *landlock.Rules
	}{
		{sandbox{}, nil},
		{sandbox{home: true, network: true, allow: []string{"/opt/srv"}}, nil},
		{sandbox{}, &landlock.Rules{Read: []string{"/srv/data"}, TCPConnect: []int{443}}},
	} {
		b := &config.Backend{Name: "x", Command: []string{prog, "/etc/os-release", "relative", "/absent"}, Landlock: c.def}
		orig := b
		p := principal.Principal{Sub: "u"}
		cleanup, err := underLandlock(&b, &p, c.sb, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		r := *b.Landlock
		dir := b.Env["TMPDIR"]
		if orig.Landlock != c.def || orig.Env != nil {
			t.Errorf("%+v: the definition was changed", c.sb)
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("%+v: TMPDIR %q: %v", c.sb, dir, err)
		}
		if !slices.Contains(r.Write, dir) || !slices.Contains(r.Exec, prog) || !slices.Contains(r.Exec, "/etc/os-release") ||
			slices.Contains(r.Exec, "relative") || slices.Contains(r.Exec, "/absent") {
			t.Errorf("%+v: rules %+v", c.sb, r)
		}
		if c.sb.home == (p.Home == dir) {
			t.Errorf("%+v: home %q, own directory %q", c.sb, p.Home, dir)
		}
		switch {
		case c.def != nil:
			if !slices.Equal(r.TCPConnect, []int{443}) || !slices.Contains(r.Read, "/srv/data") || slices.Contains(r.Write, "${HOME}") {
				t.Errorf("definition's rules: %+v", r)
			}
		case c.sb.network:
			if r.TCPConnect != nil || !slices.Contains(r.Exec, "/opt/srv") || !slices.Contains(r.Write, "${HOME}") {
				t.Errorf("-home -network -allow: %+v", r)
			}
		default:
			if r.TCPConnect == nil || len(r.TCPConnect) != 0 || r.TCPBind == nil || !slices.Contains(r.Write, "${HOME}") {
				t.Errorf("no TCP: %+v", r)
			}
		}
		cleanup()
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s not removed: %v", dir, err)
		}
	}
}
