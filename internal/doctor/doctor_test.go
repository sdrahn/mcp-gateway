package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/profile"
)

func TestDenials(t *testing.T) {
	if rs := Denials(nil, nil, "x"); len(rs) != 1 || rs[0].Status != OK {
		t.Fatalf("no denials: %+v", rs)
	}
	denials := []profile.Denial{
		{Source: "mcpsrv_fw_t", Target: "system_dbusd_t", Class: "dbus", Perms: []string{"send_msg"}},
		{Source: "mcpsrv_fw_t", Target: "system_dbusd_t", Class: "dbus", Perms: []string{"send_msg"}},
		{Source: "mcpsrv_prof_t", Target: "sysfs_t", Class: "file", Perms: []string{"read"}, Permissive: true},
		{Source: "init_t", Target: "mcpgw_exec_t", Class: "file", Perms: []string{"execute"}},
		{Source: "sshd_t", Target: "user_home_t", Class: "file", Perms: []string{"read"}}, // not ours
	}
	errs := []profile.Record{
		{Text: "type=SELINUX_ERR msg=audit(1.0:1): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:init_t:s0 newcontext=system_u:system_r:mcpsrv_x_t:s0"},
		{Text: "type=SELINUX_ERR msg=audit(1.0:2): oldcontext=system_u:system_r:init_t:s0 newcontext=system_u:system_r:httpd_t:s0"},
	}
	rs := Denials(denials, errs, "yesterday")
	got := map[string]Result{}
	for _, r := range rs {
		got[r.Check] = r
	}
	if r := got["SELinux mcpsrv_fw_t"]; r.Status != Fail || !strings.HasPrefix(r.Summary, "2 denials (1 distinct)") {
		t.Errorf("fw: %+v", r)
	}
	if r := got["SELinux mcpsrv_prof_t"]; r.Status != Warn || !strings.Contains(r.Summary, "permissive") {
		t.Errorf("prof: %+v", r)
	}
	if r := got["SELinux mcpgw_exec_t"]; r.Status != Fail {
		t.Errorf("target type: %+v", r)
	}
	if r := got["SELinux transitions"]; r.Status != Fail || len(r.Details) != 1 {
		t.Errorf("transitions: %+v", r)
	}
	if len(rs) != 4 {
		t.Errorf("results %+v", rs)
	}
}

func TestPolkit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "60-x.rules"), []byte(`polkit.addRule(function(a, s) { if (s.user == "mcp-sysmgmt") return polkit.Result.YES; });`), 0o644); err != nil {
		t.Fatal(err)
	}
	backends := map[string]*config.Backend{
		"systemd": {Name: "systemd", RunAs: "mcp-sysmgmt"},
		"fw":      {Name: "fw", RunAs: "mcp-fw"},
		"fs":      {Name: "fs", RunAs: "principal"},
		"zypp":    {Name: "zypp", RunAs: "root"},
	}
	rs := Polkit(backends, []string{dir, filepath.Join(dir, "missing")})
	if len(rs) != 2 || rs[0].Check != "polkit mcp-fw" || rs[0].Status != Warn || rs[1].Status != OK {
		t.Fatalf("%+v", rs)
	}
	if !strings.Contains(rs[0].Summary, "servers fw run as mcp-fw") {
		t.Errorf("summary %q", rs[0].Summary)
	}
}

func TestUnbound(t *testing.T) {
	groups := map[string][]string{"alice": {"users", "dev"}, "bob": {"users"}, "carol": {"users"}}
	b := Bindings{Users: map[string][]string{"bob": {"viewer"}, "carol": {}}, Groups: map[string][]string{"dev": {"developer"}}}
	got := Unbound([]string{"carol", "alice", "bob", "dave"}, func(u string) []string { return groups[u] }, b)
	if strings.Join(got, ",") != "carol,dave" {
		t.Errorf("got %v", got)
	}
}

func TestWriteText(t *testing.T) {
	var b strings.Builder
	rs := []Result{{Check: "a", Status: OK, Summary: "fine"}, {Check: "b", Status: Fail, Summary: "broken", Details: []string{"why"}}}
	if err := WriteText(&b, rs); err != nil {
		t.Fatal(err)
	}
	want := "ok    a: fine\nfail  b: broken\n        why\n\n1 ok, 0 warnings, 1 failed, 0 skipped\n"
	if b.String() != want {
		t.Errorf("got %q", b.String())
	}
	if !Failed(rs) || Failed(rs[:1]) {
		t.Error("Failed")
	}
}

func TestSELinuxTypes(t *testing.T) {
	backends := map[string]*config.Backend{
		"fs":   {Name: "fs", SELinuxType: "mcpsrv_fs_t"},
		"zypp": {Name: "zypp", SELinuxType: "mcpsrv_zypp_t"},
		"pkg":  {Name: "pkg", SELinuxType: "mcpsrv_zypp_t"},
	}
	known := map[string]bool{"system_u:system_r:mcpsrv_fs_t:s0": true}
	valid := func(ctx string) (bool, error) { return known[ctx], nil }
	rs := SELinuxTypes(backends, valid)
	if len(rs) != 1 || rs[0].Status != Fail || !strings.Contains(rs[0].Summary, "mcpsrv_zypp_t") ||
		!strings.Contains(rs[0].Summary, "pkg, zypp") {
		t.Fatalf("missing type: %+v", rs)
	}
	known["system_u:system_r:mcpsrv_zypp_t:s0"] = true
	if rs := SELinuxTypes(backends, valid); len(rs) != 1 || rs[0].Status != OK {
		t.Fatalf("all known: %+v", rs)
	}
	denied := func(string) (bool, error) { return false, os.ErrPermission }
	if rs := SELinuxTypes(backends, denied); len(rs) != 1 || rs[0].Status != Skip {
		t.Fatalf("cannot check: %+v", rs)
	}
}
