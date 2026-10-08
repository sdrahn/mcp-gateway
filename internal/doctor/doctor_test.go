package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/landlock"
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
	rs := Polkit(backends, nil, []string{dir, filepath.Join(dir, "missing")})
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
	rs = Polkit(backends, nil, []string{dir})
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
	if rs = Polkit(backends, nil, []string{dir}); rs[2].Status != OK || len(rs[2].Details) != 0 {
		t.Errorf("systemd with the shipped rule: %+v", rs[2])
	}
	// systemd-mcp 0.3.5 and later allow reads over stdio: the rule's
	// readlog is no longer needed, and its absence is no warning.
	if rs = Polkit(backends, map[string]string{"systemd": "0.3.5"}, []string{dir}); rs[2].Status != OK ||
		len(rs[2].Details) != 1 || !strings.Contains(rs[2].Details[0], "no longer checks reads") {
		t.Errorf("systemd 0.3.5 with the shipped rule: %+v", rs[2])
	}
	if err := os.WriteFile(filepath.Join(dir, "60-x.rules"), []byte(`polkit.addRule(function(a, s) { if (s.user == "mcp-sysmgmt") return polkit.Result.YES; });`), 0o644); err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]Status{"0.3.5": OK, "v0.4.0": OK, "0.3.4": Warn, "": Warn, "dev": Warn} {
		if rs = Polkit(backends, map[string]string{"systemd": v}, []string{dir}); rs[2].Status != want || len(rs[2].Details) != 0 && want == OK {
			t.Errorf("systemd %q without readlog: %+v", v, rs[2])
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v    string
		want bool
	}{{"0.3.5", true}, {"0.3.5\n", true}, {"v0.3.5", true}, {"0.3.10", true}, {"0.4", true}, {"1.0.0-rc1", true},
		{"0.3.4", false}, {"0.3", false}, {"", false}, {"dev", false}, {"0.3.x", false}} {
		if got := versionAtLeast(c.v, "0.3.5"); got != c.want {
			t.Errorf("versionAtLeast(%q) = %v", c.v, got)
		}
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
	if rs := Polkit(backends, nil, []string{dir}); len(rs) != 0 {
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
		rs := ProgramLabels(backends, TypedPrograms, current, expected, func(string) bool { return ro })
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
	rs := ProgramLabels(ok, TypedPrograms, onlySystemd, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Status != OK {
		t.Errorf("all labeled: %+v", rs)
	}
}

// A program labeled as another server's (a definition written by hand with
// the systemd program and no selinux_type): the hint names the domain, not
// a relabel, which would only let it start where it lacks the system bus.
// gateway-docs runs the file server's program in its own domain.
func TestProgramLabelsOtherServer(t *testing.T) {
	const prog = "/usr/bin/mcp-server-systemd"
	backends := map[string]*config.Backend{
		"mysystemd":    {Command: []string{prog}, SELinuxType: "mcpsrv_generic_t"},
		"gateway-docs": {Command: []string{"/usr/libexec/mcp-servers/mcp-server-fs"}, SELinuxType: "mcpsrv_docs_t"},
	}
	current := func(p string) (string, error) {
		return map[string]string{prog: "mcpsrv_systemd_exec_t", "/usr/libexec/mcp-servers/mcp-server-fs": "mcpsrv_fs_exec_t"}[p], nil
	}
	policy := map[string]string{prog: "mcpsrv_systemd_exec_t", "/usr/libexec/mcp-servers/mcp-server-fs": "mcpsrv_fs_exec_t"}
	expected := func(p string) (string, error) { return policy[p], nil }
	notInstalled := func(p string) (string, error) {
		if p == prog || p == "/usr/libexec/mcp-servers/mcp-server-fs" {
			return current(p)
		}
		return "", errors.New(p + ": not found")
	}

	rs := ProgramLabels(backends, TypedPrograms, notInstalled, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Check != "program mysystemd" || rs[0].Status != Fail ||
		!strings.Contains(rs[0].Summary, "labeled mcpsrv_systemd_exec_t, the program of mcpsrv_systemd_t, but the server's definition says selinux_type mcpsrv_generic_t") {
		t.Fatalf("other server's program: %+v", rs)
	}
	if len(rs[0].Details) != 1 || !strings.Contains(rs[0].Details[0], "set selinux_type: mcpsrv_systemd_t") ||
		strings.Contains(rs[0].Details[0], "restorecon -v") {
		t.Errorf("hint: %q", rs[0].Details)
	}

	// A policy without a rule for the path (0.16 and older for this
	// name): the label is kept with semanage, not relabeled away.
	policy[prog] = "bin_t"
	for _, ro := range []bool{false, true} {
		rs = ProgramLabels(backends, TypedPrograms, notInstalled, expected, func(string) bool { return ro })
		want := "keep it with semanage fcontext -a -t mcpsrv_systemd_exec_t " + prog
		if ro {
			want = "keep it with transactional-update run semanage fcontext"
		}
		if len(rs) != 1 || len(rs[0].Details) != 2 || !strings.Contains(rs[0].Details[1], "the type bin_t") ||
			!strings.Contains(rs[0].Details[1], want) {
			t.Errorf("read-only %v: %+v", ro, rs)
		}
	}

	// The right domain: all labeled.
	backends["mysystemd"].SELinuxType = "mcpsrv_systemd_t"
	policy[prog] = "mcpsrv_systemd_exec_t"
	rs = ProgramLabels(backends, TypedPrograms, notInstalled, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Status != OK {
		t.Errorf("right domain: %+v", rs)
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
	rs := ProgramLabels(backends, TypedPrograms, current, expected, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Check != "program "+worker || rs[0].Status != Fail ||
		!strings.Contains(rs[0].Summary, "labeled bin_t, the policy says rpm_exec_t") || !strings.Contains(rs[0].Details[0], "restorecon -v "+worker) {
		t.Fatalf("worker: %+v", rs)
	}
	labels[worker] = "rpm_exec_t"
	rs = ProgramLabels(backends, TypedPrograms, current, expected, func(string) bool { return false })
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

// With one server, only its helpers are checked: zypp's worker for zypp,
// none for systemd.
func TestHelpersOf(t *testing.T) {
	zypp := map[string]*config.Backend{"zypp": {Command: []string{"/usr/bin/mcp-server-zypp"}}}
	if got := HelpersOf(zypp); len(got) != 1 || got[0] != "/usr/libexec/mcp-server-zypp/zypp-mcp-tool" {
		t.Errorf("zypp: %v", got)
	}
	systemd := map[string]*config.Backend{"systemd": {Command: []string{"/usr/bin/systemd-mcp"}, SELinuxType: "mcpsrv_systemd_t"}}
	if got := HelpersOf(systemd); len(got) != 0 {
		t.Errorf("systemd: %v", got)
	}
	labeled := func(string) (string, error) { return "mcpsrv_systemd_exec_t", nil }
	rs := ProgramLabels(systemd, nil, labeled, labeled, func(string) bool { return false })
	if len(rs) != 1 || rs[0].Summary != "the 1 servers' programs are labeled as the policy says" {
		t.Errorf("one server: %+v", rs)
	}
	for _, p := range HelpersOf(zypp) {
		if !slices.Contains(TypedPrograms, p) {
			t.Errorf("helper %s is not in TypedPrograms", p)
		}
	}
}

func TestLandlock(t *testing.T) {
	none := map[string]*config.Backend{"git": {Name: "git"}}
	with := map[string]*config.Backend{"git": {Name: "git"},
		"fs":   {Name: "fs", Landlock: &landlock.Rules{Write: []string{"${HOME}"}}},
		"docs": {Name: "docs", Landlock: &landlock.Rules{Required: true}}}
	fs := map[string]*config.Backend{"fs": with["fs"]}
	tcp := map[string]*config.Backend{"web": {Name: "web", Landlock: &landlock.Rules{TCPConnect: []int{443}}}}
	for _, c := range []struct {
		backends map[string]*config.Backend
		k        LandlockKernel
		launcher bool
		status   Status
		summary  string
	}{
		{none, LandlockKernel{ABI: 6}, true, OK, "Landlock ABI 6; no server definition"},
		{none, LandlockKernel{}, false, OK, "no Landlock in this kernel; no server definition asks for it"},
		{with, LandlockKernel{ABI: 6}, true, OK, "Landlock ABI 6: instances of docs, fs start restricted"},
		{with, LandlockKernel{ABI: 6}, false, Fail, "mcp-landlock is missing: instances of docs, fs cannot start"},
		{with, LandlockKernel{}, true, Fail, "instances of docs cannot start (landlock: required)"},
		{with, LandlockKernel{ABI: 5}, true, Fail, "Landlock ABI 5 cannot apply all the rules of docs"},
		{fs, LandlockKernel{}, true, Warn, "no Landlock in this kernel: instances of fs start without the restriction"},
		{fs, LandlockKernel{Disabled: true}, true, Warn, "Landlock is in the kernel but not in its LSM list: instances of fs"},
	} {
		rs := Landlock(c.backends, c.k, c.launcher)
		if len(rs) != 1 || rs[0].Status != c.status || !strings.Contains(rs[0].Summary, c.summary) {
			t.Errorf("%v %+v launcher %v: %+v", sortedKeys(c.backends), c.k, c.launcher, rs)
		}
	}
	if rs := Landlock(fs, LandlockKernel{ABI: 5}, true); rs[0].Status != OK || len(rs[0].Details) != 1 ||
		!strings.Contains(rs[0].Details[0], "fs: left out by the kernel: scoping") {
		t.Errorf("ABI 5: %+v", rs)
	}
	if rs := Landlock(tcp, LandlockKernel{ABI: 3}, true); rs[0].Status != OK || !strings.Contains(rs[0].Details[0], "web: left out by the kernel: TCP ports (ABI 4)") {
		t.Errorf("ABI 3, TCP: %+v", rs)
	}
	if rs := Landlock(fs, LandlockKernel{Disabled: true}, true); !strings.Contains(rs[0].Details[0], "lsm= boot parameter") {
		t.Errorf("disabled: %+v", rs)
	}
}

// A server that does not start and runs restricted, with no SELinux
// denial for its domain: Landlock is named. With a denial, SELinux is
// the suspect; a server without restriction is not named.
func TestLandlockSuspects(t *testing.T) {
	backends := map[string]*config.Backend{
		"fs":    {Name: "fs", SELinuxType: "mcpsrv_fs_t", Command: []string{"/usr/libexec/mcp-servers/mcp-server-fs"}},
		"tool":  {Name: "tool", Command: []string{"/opt/tool"}, Landlock: &landlock.Rules{Read: []string{"/srv"}}},
		"plain": {Name: "plain", Command: []string{"/opt/plain"}},
		"web":   {Name: "web", URL: "https://x/mcp", SELinuxType: "mcpsrv_http_t", Command: []string{"/usr/libexec/mcp-gateway/mcp-http-connector"}},
	}
	denials := []profile.Denial{{Source: "mcpsrv_http_t", Target: "cert_t"}}
	rs := LandlockSuspects(backends, []string{"fs", "plain", "tool", "web", "gone"}, denials, true)
	var got []string
	for _, r := range rs {
		got = append(got, r.Check)
		if r.Status != Warn || !strings.Contains(r.Summary, "Landlock is the likely cause") {
			t.Errorf("%+v", r)
		}
	}
	if strings.Join(got, ",") != "landlock fs,landlock tool" {
		t.Errorf("suspects %v", got)
	}
	if !strings.Contains(rs[1].Details[0], "read /srv") || !strings.Contains(rs[0].Details[0], "mcp-server-fs") ||
		!strings.Contains(rs[1].Summary, "mcpsrv_generic_t") {
		t.Errorf("details %+v", rs)
	}
	if rs := LandlockSuspects(backends, []string{"web"}, nil, false); len(rs) != 1 || !strings.Contains(rs[0].Summary, "if SELinux denied") {
		t.Errorf("denials unknown: %+v", rs)
	}
}
