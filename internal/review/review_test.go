package review

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// tree is a server in several languages, with code that must be left out.
var tree = map[string]string{
	"go.mod": "module example.com/srv\n\ngo 1.22\n",
	"main.go": `package main

import (
	"os"
	"os/exec"

	"example.com/srv/internal/journal"
)

func main() {
	if os.Geteuid() != 0 {
		return
	}
	// exec.Command("commented-out")
	_ = exec.CommandContext(ctx, "getfacl", "-p", path)
	journal.Read()
	_ = os.Getenv("SRV_DEBUG")
}
`,
	"internal/journal/journal.go": `package journal

import "os/exec"

const zypper = "/usr/bin/zypper"

func Read() {
	_ = exec.Command("rpm", "-qdf", exe)
	_, _ = os.Stat("/run/log/journal")
	_ = obj.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0)
	perm := "org.freedesktop.systemd1.manage-units"
	resp, _ := http.Get("https://scc.suse.com/connect")
}
`,
	"internal/journal/journal_test.go": `package journal
func x() { exec.Command("in-a-test") }
`,
	"unused/unused.go": `package unused
func y() { exec.Command("not-imported") }
`,
	"vendor/lib/lib.go":       `package lib; func z() { exec.Command("vendored") }`,
	"tool.py":                 "import subprocess, os\nsubprocess.run(['snapper', 'list'])\nif os.geteuid() == 0: pass\nx = os.environ.get('SNAPPER_CONFIG')\n",
	"web/server.ts":           "spawn('systemctl', ['status']);\nconst t = process.env.TOKEN;\nfetch(url);\n",
	"worker/main.cc":          "int main() { FILE *f = popen(\"zypper refresh\", \"r\"); const char *l = getenv(\"ZYPP_LOGFILE\"); }\n",
	"rs/src/main.rs":          "fn main() { Command::new(\"firewall-cmd\"); let v = env::var(\"FW_ZONE\"); }\n",
	"node_modules/x/index.js": "spawn('from-node-modules')\n",
}

func values(s *Scan, k Kind) []string {
	var out []string
	for _, f := range s.Findings {
		if f.Kind == k {
			out = append(out, f.Value)
		}
	}
	return out
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, tree)
	s, err := ScanDir(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[Kind]string{
		KindProgram: "/usr/bin/zypper firewall-cmd getfacl not-imported rpm snapper systemctl zypper",
		KindDBus:    "org.freedesktop.PolicyKit1.Authority.CheckAuthorization org.freedesktop.systemd1.manage-units",
		KindPath:    "/run/log/journal",
		KindNetwork: "https://scc.suse.com network calls (Go net/http) network calls (JavaScript)",
		KindRoot:    "root check",
		KindEnv:     "FW_ZONE SNAPPER_CONFIG SRV_DEBUG TOKEN ZYPP_LOGFILE",
	} {
		if got := strings.Join(values(s, kind), " "); got != want {
			t.Errorf("%s: %q, want %q", kind, got, want)
		}
	}
	if s.Files["Go"] != 3 || s.Files["Python"] != 1 || s.Files["JavaScript"] != 1 || s.Files["C/C++"] != 1 || s.Files["Rust"] != 1 {
		t.Errorf("files = %v", s.Files)
	}
	for _, f := range s.Findings {
		if f.Kind == KindProgram && f.Value == "rpm" {
			if l := f.Locations[0]; l.File != filepath.Join("internal", "journal", "journal.go") || l.Line != 8 || !strings.Contains(l.Text, `"-qdf"`) {
				t.Errorf("rpm location = %+v", l)
			}
		}
		if f.Kind == KindRoot && len(f.Locations) != 2 {
			t.Errorf("root checks in Go and Python: %+v", f.Locations)
		}
	}
}

func TestGoPackageDirs(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, tree)
	dirs, err := GoPackageDirs(dir, ".")
	if err != nil {
		t.Fatal(err)
	}
	if !dirs["."] || !dirs[filepath.Join("internal", "journal")] || dirs["unused"] || len(dirs) != 2 {
		t.Errorf("dirs = %v", dirs)
	}
	s, err := ScanDir(dir, Options{GoDirs: dirs})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(values(s, KindProgram), " "); strings.Contains(got, "not-imported") || !strings.Contains(got, "snapper") {
		t.Errorf("programs with --main: %s", got)
	}
	if _, err := GoPackageDirs(dir, "nope"); err == nil {
		t.Error("a missing main package was accepted")
	}
}

func TestReview(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, tree)
	s, err := ScanDir(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	locate := func(f Finding) Context {
		switch f.Value {
		case "rpm", "/usr/bin/zypper", "zypper":
			return Context{Path: "/usr/bin/" + strings.TrimPrefix(f.Value, "/usr/bin/"), Type: "rpm_exec_t"}
		case "getfacl":
			return Context{Path: "/usr/bin/getfacl", Type: "bin_t"}
		case "/run/log/journal":
			return Context{Path: f.Value, Type: "syslogd_var_run_t"}
		case "snapper":
			return Context{Missing: true}
		}
		return Context{}
	}
	prof := &Profile{Domain: "mcpsrv_x_t", Targets: map[string]bool{"bin_t": true}}
	items := Review(s, locate, prof)
	byValue := map[string]Item{}
	for _, it := range items {
		byValue[it.Value] = it
	}
	for value, want := range map[string]struct{ profiled, note string }{
		"getfacl":                               {"denied", "execute bin_t files"},
		"rpm":                                   {"none", "rpm_t"},
		"/run/log/journal":                      {"none", "runtime files"},
		"snapper":                               {"", "not installed here"},
		"org.freedesktop.systemd1.manage-units": {"", "a polkit action"},
		"org.freedesktop.PolicyKit1.Authority.CheckAuthorization": {"", "asks polkit itself"},
		"https://scc.suse.com": {"", "network: true"},
		"SRV_DEBUG":            {"", "$SRV_DEBUG"},
	} {
		it, ok := byValue[value]
		if !ok || it.Profiled != want.profiled || !strings.Contains(it.Note, want.note) {
			t.Errorf("%s: profiled %q, note %q; want %q, %q", value, it.Profiled, it.Note, want.profiled, want.note)
		}
	}
	var b bytes.Buffer
	if err := WriteReport(&b, dir, s, items, prof); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Compared with a profiling run of mcpsrv_x_t",
		"Programs it runs (8):",
		"  rpm  [/usr/bin/rpm; rpm_exec_t; no denial in the profiling run (not reached, or allowed already)]",
		"      internal/journal/journal.go:8  _ = exec.Command(\"rpm\", \"-qdf\", exe)",
		"  getfacl  [/usr/bin/getfacl; bin_t; denied in the profiling run]",
		"  snapper  [not found here]",
		"Environment variables (5):",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestLocate(t *testing.T) {
	if c := Locate(Finding{Kind: KindProgram, Value: "sh"}); c.Missing || c.Path == "" {
		t.Errorf("sh: %+v", c)
	}
	if c := Locate(Finding{Kind: KindProgram, Value: "no-such-program-here"}); !c.Missing {
		t.Errorf("missing program: %+v", c)
	}
	dir := t.TempDir()
	if c := Locate(Finding{Kind: KindPath, Value: filepath.Join(dir, "a", "b")}); c.Path != dir || !c.Parent {
		t.Errorf("missing path: %+v", c)
	}
	if c := Locate(Finding{Kind: KindPath, Value: "/proc/%d/stat"}); c.Path != "" {
		t.Errorf("format: %+v", c)
	}
}
