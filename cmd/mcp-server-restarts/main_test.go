package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// proc writes a process to a fake /proc.
func proc(t *testing.T, root, pid, comm, uid, cgroup, maps string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	write(t, filepath.Join(dir, "comm"), comm+"\n")
	write(t, filepath.Join(dir, "status"), "Name:\t"+comm+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n")
	write(t, filepath.Join(dir, "cgroup"), "0::"+cgroup+"\n")
	write(t, filepath.Join(dir, "cmdline"), comm+"\x00")
	write(t, filepath.Join(dir, "maps"), maps)
}

func testScanner(t *testing.T) (*scanner, *[]string) {
	t.Helper()
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	lib := "7f00-7f10 r-xp 00000000 fd:01 1234                       /usr/lib64/libfoo.so.1.2 (deleted)\n"
	// sshd maps the replaced libfoo twice and its own program; a user's
	// shell maps libfoo too; a temporary file and shared memory, deleted,
	// are no update's doing; nginx maps nothing deleted.
	proc(t, procRoot, "100", "sshd", "0", "/system.slice/sshd.service",
		"5600-5610 r-xp 00000000 fd:01 99 /usr/sbin/sshd\n"+lib+lib+
			"7f20-7f30 rw-s 00000000 00:05 77 /dev/shm/x (deleted)\n")
	proc(t, procRoot, "200", "bash", "1000", "/user.slice/user-1000.slice/session-2.scope", lib+
		"7f40-7f50 rw-p 00000000 fd:01 55 /tmp/scratch (deleted)\n")
	proc(t, procRoot, "300", "nginx", "0", "/system.slice/nginx.service", "5600-5610 r-xp 00000000 fd:01 98 /usr/sbin/nginx\n")
	proc(t, procRoot, "400", "worker", "0", "/system.slice/app.service/worker",
		"7f00-7f10 r-xp 00000000 fd:01 1 /opt/app/bin/worker (deleted)\n")
	// A kernel thread: empty map and command line.
	write(t, filepath.Join(procRoot, "2", "maps"), "")
	write(t, filepath.Join(procRoot, "2", "cmdline"), "")
	// One whose map cannot be read.
	write(t, filepath.Join(procRoot, "500", "cmdline"), "x\x00")
	// The server itself.
	proc(t, procRoot, "42", "mcp-server-rest", "0", "/system.slice/mcp-restarts-1.service", lib)
	write(t, filepath.Join(procRoot, "self"), "")

	modules := filepath.Join(root, "modules")
	write(t, filepath.Join(modules, "6.12.0-160000.5-default", "vmlinuz"), "")
	write(t, filepath.Join(modules, "6.12.0-160000.10-default", "vmlinuz"), "")
	write(t, filepath.Join(modules, "6.12.0-160000.9-default", "vmlinuz"), "")
	// Modules of a kernel that is gone: no image.
	write(t, filepath.Join(modules, "6.4.0-1-default", "modules.dep"), "")

	var asked []string
	s := &scanner{proc: procRoot, modules: modules, rebootFlag: filepath.Join(root, "reboot-needed"), self: 42,
		release: func() string { return "6.12.0-160000.9-default" },
		owner: func(_ context.Context, path string) string {
			asked = append(asked, path)
			return map[string]string{"/usr/lib64/libfoo.so.1.2": "libfoo1"}[path]
		},
		user: func(uid string) string { return map[string]string{"0": "root", "1000": "alice"}[uid] },
	}
	return s, &asked
}

func TestScan(t *testing.T) {
	s, asked := testScanner(t)
	r := s.scan(context.Background())
	if r.RebootNeeded || r.RebootNeededSince != "" {
		t.Errorf("reboot: %+v", r)
	}
	if !slices.Equal(r.InstalledKernels, []string{"6.12.0-160000.5-default", "6.12.0-160000.9-default", "6.12.0-160000.10-default"}) ||
		r.RunningKernel != "6.12.0-160000.9-default" || !r.NewerKernel {
		t.Errorf("kernels: running %s, installed %v, newer %v", r.RunningKernel, r.InstalledKernels, r.NewerKernel)
	}
	var pids []int
	for _, p := range r.Processes {
		pids = append(pids, p.PID)
	}
	if !slices.Equal(pids, []int{100, 200, 400}) {
		t.Fatalf("processes %+v", r.Processes)
	}
	sshd := r.Processes[0]
	if sshd.Command != "sshd" || sshd.User != "root" || sshd.Unit != "sshd.service" ||
		!slices.Equal(sshd.Files, []string{"/usr/lib64/libfoo.so.1.2"}) || !slices.Equal(sshd.Packages, []string{"libfoo1"}) {
		t.Errorf("sshd %+v", sshd)
	}
	if bash := r.Processes[1]; bash.User != "alice" || bash.Unit != "session-2.scope" || !slices.Equal(bash.Files, []string{"/usr/lib64/libfoo.so.1.2"}) {
		t.Errorf("bash %+v", bash)
	}
	if w := r.Processes[2]; w.Unit != "app.service" || len(w.Packages) != 0 || !slices.Equal(w.Files, []string{"/opt/app/bin/worker"}) {
		t.Errorf("worker %+v", w)
	}
	if len(r.Services) != 2 || r.Services[0].Unit != "app.service" || r.Services[1].Unit != "sshd.service" ||
		!slices.Equal(r.Services[1].Packages, []string{"libfoo1"}) || !slices.Equal(r.Services[1].PIDs, []int{100}) {
		t.Errorf("services %+v", r.Services)
	}
	if r.Unreadable != 1 {
		t.Errorf("unreadable %d", r.Unreadable)
	}
	// Each deleted file is looked up once.
	if !slices.Equal(*asked, []string{"/usr/lib64/libfoo.so.1.2", "/opt/app/bin/worker"}) {
		t.Errorf("asked rpm about %v", *asked)
	}

	write(t, s.rebootFlag, "")
	if r := s.scan(context.Background()); !r.RebootNeeded || r.RebootNeededSince == "" {
		t.Errorf("with the flag: %+v", r)
	}
}

func TestScanNothing(t *testing.T) {
	root := t.TempDir()
	s := &scanner{proc: root, modules: root, rebootFlag: filepath.Join(root, "x"), release: func() string { return "6.12" },
		owner: func(context.Context, string) string { return "" }, user: func(string) string { return "" }}
	r := s.scan(context.Background())
	b, _ := json.Marshal(r)
	// Empty lists, not null, for the output schema.
	if !strings.Contains(string(b), `"services":[]`) || !strings.Contains(string(b), `"processes":[]`) ||
		!strings.Contains(string(b), `"installed_kernels":[]`) || r.NewerKernel {
		t.Errorf("%s", b)
	}
	if txt := summary(r); !strings.Contains(txt, "No update waits for a reboot") || !strings.Contains(txt, "No process uses files") {
		t.Errorf("summary %q", txt)
	}
}

func TestVercmp(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"6.12.0-160000.10-default", "6.12.0-160000.9-default", 1},
		{"6.12.0-160000.9-default", "6.12.0-160000.9-default", 0},
		{"6.4.0-150600.23.25-default", "6.12.0-1-default", -1},
		{"6.12.0-1.1", "6.12.0-1", 1},
	} {
		got := vercmp(c.a, c.b)
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("vercmp(%s, %s) = %d, want sign of %d", c.a, c.b, got, c.want)
		}
	}
}

func TestUnitOf(t *testing.T) {
	dir := t.TempDir()
	for cg, want := range map[string]string{
		"0::/system.slice/sshd.service\n":                  "sshd.service",
		"0::/system.slice/app.service/worker\n":            "app.service",
		"0::/user.slice/user-1000.slice/session-2.scope\n": "session-2.scope",
		"0::/\n": "",
		"1:name=systemd:/x\n0::/system.slice/getty@tty1.service": "getty@tty1.service",
	} {
		p := filepath.Join(dir, "cgroup")
		write(t, p, cg)
		if got := unitOf(p); got != want {
			t.Errorf("unitOf(%q) = %q, want %q", cg, got, want)
		}
	}
}

// The server over MCP: one read-only tool without arguments.
func TestServer(t *testing.T) {
	s, _ := testScanner(t)
	reqs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pending_restarts","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pending_restarts","arguments":{"x":"y"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"restart","arguments":{}}}`,
	}
	// stdin stays open until every answer is in: at its end the server
	// cancels what still runs.
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errb bytes.Buffer
	done := make(chan int)
	go func() { done <- run(nil, inR, outW, &errb, s); _ = outW.Close() }()
	go func() {
		for _, r := range reqs {
			_, _ = io.WriteString(inW, r+"\n")
		}
	}()
	answers := map[float64]map[string]any{}
	sc := bufio.NewScanner(outR)
	sc.Buffer(nil, 1<<20)
	for len(answers) < len(reqs) && sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v", sc.Text(), err)
		}
		answers[m["id"].(float64)] = m
	}
	_ = inW.Close()
	if rc := <-done; rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	tools := answers[2]["result"].(map[string]any)["tools"].([]any)
	tool := tools[0].(map[string]any)
	ann := tool["annotations"].(map[string]any)
	if len(tools) != 1 || tool["name"] != "pending_restarts" || ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
		t.Errorf("tools %v", tools)
	}
	res := answers[3]["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] == true || !strings.Contains(text, "Services to restart: app.service (-); sshd.service (libfoo1);") ||
		!strings.Contains(text, "a newer kernel is installed") || strings.Contains(text, "nginx") {
		t.Errorf("call: %v", res)
	}
	if sc := res["structuredContent"].(map[string]any); sc["reboot_needed"] != false || len(sc["services"].([]any)) != 2 {
		t.Errorf("structuredContent %v", sc)
	}
	if answers[4]["result"].(map[string]any)["isError"] != true {
		t.Errorf("arguments accepted: %v", answers[4])
	}
	if answers[5]["error"] == nil {
		t.Errorf("unknown tool: %v", answers[5])
	}
}

// The definition the package installs: this program, as a throwaway
// account with CAP_SYS_PTRACE and nothing else, without network, in its
// own domain; accepted in the administrator's directory only, as a
// capability is.
func TestDefinition(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("..", "..", "packaging", "restarts-server", "restarts.yaml.in"))
	if err != nil {
		t.Fatal(err)
	}
	def := strings.NewReplacer("@LIBEXECDIR@", "/usr/libexec", "@DATADIR@", "/usr/share").Replace(string(in))
	vendor, admin := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(admin, "restarts.yaml"), []byte(def), 0o644); err != nil {
		t.Fatal(err)
	}
	backends, err := config.LoadBackends(vendor, admin)
	if err != nil {
		t.Fatal(err)
	}
	b := backends["restarts"]
	if b == nil || b.RunAs != "dynamic" || b.Privileged || b.Network || b.SELinuxType != "mcpsrv_restarts_t" ||
		!slices.Equal(b.Command, []string{"/usr/libexec/mcp-servers/mcp-server-restarts"}) ||
		!slices.Equal(b.Sandbox.Capabilities, []string{"CAP_SYS_PTRACE"}) || b.Sandbox.ProtectHome != "yes" {
		t.Fatalf("%+v", b)
	}
	if err := os.Rename(filepath.Join(admin, "restarts.yaml"), filepath.Join(vendor, "restarts.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadBackends(vendor, admin); err == nil || !strings.Contains(err.Error(), "capabilities") {
		t.Errorf("accepted from the vendor directory: %v", err)
	}
}
