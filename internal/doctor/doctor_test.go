package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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
		"systemd": {Name: "systemd", RunAs: "mcp-sysmgmt", SELinuxType: "mcpsrv_systemd_t"},
		"fw":      {Name: "fw", RunAs: "mcp-fw", SELinuxType: "mcpsrv_firewalld_t"},
		"custom":  {Name: "custom", RunAs: "mcp-custom"},
		"fs":      {Name: "fs", RunAs: "principal"},
		"zypp":    {Name: "zypp", RunAs: "root"},
		"docs":    {Name: "docs", RunAs: "dynamic"},
	}
	rs := Polkit(backends, []string{dir, filepath.Join(dir, "missing")})
	if len(rs) != 3 {
		t.Fatalf("%+v", rs)
	}
	// A server whose domain may not use polkit at all: a note.
	if rs[0].Check != "polkit mcp-custom" || rs[0].Status != OK || len(rs[0].Details) == 0 {
		t.Errorf("custom: %+v", rs[0])
	}
	// One that acts through polkit without a rule: a warning naming the fix.
	if rs[1].Check != "polkit mcp-fw" || rs[1].Status != Warn ||
		!strings.Contains(rs[1].Summary, "servers fw act through polkit as mcp-fw") || len(rs[1].Details) == 0 {
		t.Errorf("fw: %+v", rs[1])
	}
	if rs[2].Check != "polkit mcp-sysmgmt" || rs[2].Status != OK {
		t.Errorf("systemd: %+v", rs[2])
	}

	// With systemd-mcp's read action known to polkit (before 0.3.5 it
	// checks every read with it), a rule must allow that too.
	actions := t.TempDir()
	old := polkitActionsDir
	polkitActionsDir = actions
	t.Cleanup(func() { polkitActionsDir = old })
	if err := os.WriteFile(filepath.Join(actions, "com.suse.gatekeeper.policy"), []byte("<policyconfig/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	rs = Polkit(backends, []string{dir})
	if rs[2].Status != Warn || !strings.Contains(rs[2].Summary, "none allows com.suse.gatekeeper.readlog") ||
		!strings.Contains(rs[2].Summary, "calling method was canceled by user") {
		t.Errorf("systemd without readlog: %+v", rs[2])
	}
	shipped, err := os.ReadFile(filepath.Join("..", "..", "profiles", "systemd", "polkit.rules"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "60-x.rules"), shipped, 0o644); err != nil {
		t.Fatal(err)
	}
	if rs = Polkit(backends, []string{dir}); rs[2].Status != OK {
		t.Errorf("systemd with the shipped rule: %+v", rs[2])
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
	if err := WriteText(&b, rs, false); err != nil {
		t.Fatal(err)
	}
	want := "OK    a: fine\nFAIL  b: broken\n        why\n\n1 ok, 0 warnings, 1 failed, 0 skipped\n"
	if b.String() != want {
		t.Errorf("got %q", b.String())
	}
	b.Reset()
	rs = append(rs, Result{Check: "c", Status: Warn, Summary: "hm"}, Result{Check: "d", Status: Skip, Summary: "later"})
	if err := WriteText(&b, rs, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\x1b[32mOK\x1b[0m    a: fine", "\x1b[31mFAIL\x1b[0m  b: broken", "\x1b[38;5;208mWARN\x1b[0m  c: hm", "\x1b[32mSKIP\x1b[0m  d: later"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("colored output lacks %q:\n%q", want, b.String())
		}
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

func TestSnapper(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("root", "SUBVOLUME=\"/\"\nALLOW_USERS=\"\"\nALLOW_GROUPS=\"\"\n")
	write("home", "# comment\nSUBVOLUME=\"/home\"\nALLOW_USERS=\"alice mcp-snapper\"\n")
	backends := map[string]*config.Backend{
		"snapper": {Name: "snapper", Command: []string{"/usr/bin/mcp-server-snapper"}, RunAs: "mcp-snapper"},
		"fs":      {Name: "fs", Command: []string{"/usr/bin/fs"}, RunAs: "principal"},
	}
	noGroups := func(string) []string { return nil }
	rs := Snapper(backends, dir, noGroups)
	if len(rs) != 1 || rs[0].Status != OK || !strings.Contains(rs[0].Summary, "configs home") {
		t.Fatalf("allowed by user: %+v", rs)
	}

	write("home", "ALLOW_USERS=\"alice\"\nALLOW_GROUPS=\"snap\"\n")
	rs = Snapper(backends, dir, func(string) []string { return []string{"snap"} })
	if rs[0].Status != OK {
		t.Fatalf("allowed by group: %+v", rs)
	}
	rs = Snapper(backends, dir, noGroups)
	if rs[0].Status != Warn || !strings.Contains(rs[0].Details[0], "set-config") {
		t.Fatalf("not allowed: %+v", rs)
	}

	// Root needs no ALLOW_USERS; a missing directory skips.
	backends["snapper"].RunAs = "root"
	if rs := Snapper(backends, dir, noGroups); len(rs) != 0 {
		t.Fatalf("root: %+v", rs)
	}
	backends["snapper"].RunAs = "mcp-snapper"
	if rs := Snapper(backends, filepath.Join(dir, "missing"), noGroups); rs[0].Status != Skip {
		t.Fatalf("missing dir: %+v", rs)
	}
	// The polkit check leaves the snapper server alone.
	if rs := Polkit(backends, []string{dir}); len(rs) != 0 {
		t.Fatalf("polkit: %+v", rs)
	}
}

func TestProgramLabels(t *testing.T) {
	backends := map[string]*config.Backend{
		"snapper": {Command: []string{"/usr/bin/mcp-server-snapper"}, SELinuxType: "mcpsrv_snapper_t"},
		"systemd": {Command: []string{"/usr/bin/systemd-mcp"}, SELinuxType: "mcpsrv_systemd_t"},
		"gone":    {Command: []string{"/usr/bin/gone"}, SELinuxType: "mcpsrv_generic_t"},
	}
	current := func(p string) (string, error) {
		switch p {
		case "/usr/bin/mcp-server-snapper":
			return "bin_t", nil
		case "/usr/bin/systemd-mcp":
			return "mcpsrv_systemd_exec_t", nil
		}
		return "", errors.New(p + ": not found")
	}
	expected := func(p string) (string, error) {
		return map[string]string{
			"/usr/bin/mcp-server-snapper": "mcpsrv_snapper_exec_t",
			"/usr/bin/systemd-mcp":        "mcpsrv_systemd_exec_t",
		}[p], nil
	}
	for _, ro := range []bool{false, true} {
		rs := ProgramLabels(backends, current, expected, func(string) bool { return ro })
		var snapper, gone *Result
		for i := range rs {
			switch rs[i].Check {
			case "program snapper":
				snapper = &rs[i]
			case "program gone":
				gone = &rs[i]
			case "program systemd":
				t.Errorf("systemd is labeled right: %+v", rs[i])
			}
		}
		if snapper == nil || snapper.Status != Fail || !strings.Contains(snapper.Summary, "labeled bin_t, the policy says mcpsrv_snapper_exec_t") {
			t.Fatalf("snapper: %+v", rs)
		}
		if want := map[bool]string{false: "relabel it: restorecon -v", true: "transactional-update run restorecon"}[ro]; !strings.Contains(snapper.Details[0], want) {
			t.Errorf("read-only %v: fix %q", ro, snapper.Details[0])
		}
		if gone == nil || gone.Status != Fail || !strings.Contains(gone.Summary, "not found") {
			t.Errorf("missing program: %+v", gone)
		}
	}
	// All right: one line.
	ok := map[string]*config.Backend{"systemd": backends["systemd"]}
	onlySystemd := func(p string) (string, error) {
		if p == "/usr/bin/systemd-mcp" {
			return current(p)
		}
		return "", errors.New(p + ": not found")
	}
	rs := ProgramLabels(ok, onlySystemd, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Status != OK {
		t.Errorf("all labeled: %+v", rs)
	}
}

// A helper a server starts (zypp's worker) is checked too, where it is
// installed: labeled bin_t, it would not run in rpm_t.
func TestProgramLabelsHelpers(t *testing.T) {
	const worker = "/usr/libexec/mcp-server-zypp/zypp-mcp-tool"
	backends := map[string]*config.Backend{
		"zypp": {Command: []string{"/usr/bin/mcp-server-zypp"}, SELinuxType: "mcpsrv_zypp_t"},
	}
	labels := map[string]string{"/usr/bin/mcp-server-zypp": "mcpsrv_zypp_exec_t", worker: "bin_t", "/usr/bin/mcp-gateway": "mcpgw_exec_t"}
	current := func(p string) (string, error) {
		if l, ok := labels[p]; ok {
			return l, nil
		}
		return "", errors.New(p + ": not found")
	}
	expected := func(p string) (string, error) {
		return map[string]string{"/usr/bin/mcp-server-zypp": "mcpsrv_zypp_exec_t", worker: "rpm_exec_t", "/usr/bin/mcp-gateway": "mcpgw_exec_t"}[p], nil
	}
	rs := ProgramLabels(backends, current, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Check != "program "+worker || rs[0].Status != Fail ||
		!strings.Contains(rs[0].Summary, "labeled bin_t, the policy says rpm_exec_t") || !strings.Contains(rs[0].Details[0], "restorecon -v "+worker) {
		t.Fatalf("worker: %+v", rs)
	}
	labels[worker] = "rpm_exec_t"
	rs = ProgramLabels(backends, current, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Status != OK || !strings.Contains(rs[0].Summary, "1 servers' programs and 2 other programs") {
		t.Errorf("all labeled: %+v", rs)
	}
}

// TypedPrograms names every program path the modules' file contexts give
// a type (plain paths of regular files below /usr).
func TestTypedProgramsMatchFileContexts(t *testing.T) {
	files, err := filepath.Glob("../../selinux/*.fc")
	if err != nil || len(files) == 0 {
		t.Fatalf("file contexts: %v %v", files, err)
	}
	var want []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[1] != "--" || !strings.HasPrefix(fields[0], "/usr/") || strings.ContainsAny(fields[0], "()|?*[") {
				continue
			}
			want = append(want, fields[0])
		}
	}
	got := slices.Clone(TypedPrograms)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("TypedPrograms %v\nfile contexts  %v", got, want)
	}
}

func TestReadOnlyRoot(t *testing.T) {
	backends := map[string]*config.Backend{
		"zypp":    {Privileged: true},
		"systemd": {},
	}
	if rs := ReadOnlyRoot(backends, false); len(rs) != 0 {
		t.Errorf("writable: %+v", rs)
	}
	rs := ReadOnlyRoot(backends, true)
	if len(rs) != 1 || rs[0].Status != OK || !strings.Contains(rs[0].Summary, "privileged servers zypp") || len(rs[0].Details) == 0 {
		t.Errorf("privileged on read-only /usr: %+v", rs)
	}
	delete(backends, "zypp")
	if rs := ReadOnlyRoot(backends, true); len(rs) != 1 || rs[0].Status != OK {
		t.Errorf("no privileged servers: %+v", rs)
	}
}

func TestIdentify(t *testing.T) {
	rs := []Result{{Check: "gateway status"}, {Check: "polkit mcp-fw"}, {Check: "SELinux type mcpsrv_x_t"},
		{Check: "SELinux mcpsrv_fs_t"}, {Check: "SELinux"}, {Check: "program /usr/bin/x"}, {Check: "program labels"},
		{Check: "mcp-opa.service"}, {Check: "server fs"}, {Check: "something new"}}
	Identify(rs)
	var got []string
	for _, r := range rs {
		got = append(got, r.ID+"|"+r.Subject)
	}
	want := "gateway-status|,polkit|mcp-fw,selinux-type|mcpsrv_x_t,selinux-denials|mcpsrv_fs_t,selinux-denials|," +
		"program|/usr/bin/x,program-labels|,unit|mcp-opa.service,server|fs,something new|"
	if strings.Join(got, ",") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, ","), want)
	}
	if Warned(rs) || !Warned([]Result{{Status: OK}, {Status: Warn}}) {
		t.Error("Warned")
	}
}
