package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/profile"
)

func TestProfileDefinition(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	def := "name: fwprof\ncommand: [\"/usr/libexec/mcpgw-fwprof\", \"--x\"]\nrun_as: mcp-sysmgmt\nenv: {A: b}\n"
	if err := os.WriteFile(filepath.Join(src, "fwprof.yaml"), []byte(def), 0o644); err != nil {
		t.Fatal(err)
	}
	backends, err := config.LoadBackends(src)
	if err != nil {
		t.Fatal(err)
	}
	d := profile.NewDomain("fwprof", backends["fwprof"].SELinuxType, config.DefaultSELinuxType, "/usr/libexec/mcpgw-fwprof")
	out, err := definition(backends["fwprof"], d, []string{"network: it connects to http_port_t ports"})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "fwprof.yaml"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := config.LoadBackends(dst)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b := again["fwprof"]
	if b.SELinuxType != "mcpsrv_fwprof_t" || !b.Network || b.RunAs != "mcp-sysmgmt" || b.Env["A"] != "b" || len(b.Command) != 2 {
		t.Errorf("definition %+v\n%s", b, out)
	}
	if !strings.HasPrefix(string(out), "# Draft by mcp-gateway profile") {
		t.Errorf("no header:\n%s", out)
	}
}

func TestProfileUsage(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"--server", "x"}, 2}, // neither --out nor --verify
		{[]string{"--out", "d"}, 2},    // no server
		{[]string{"-h"}, 0},
	} {
		var out, errOut bytes.Buffer
		if got := runProfile(c.args, &out, &errOut); got != c.code {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, got, c.code, errOut.String())
		}
	}
}
