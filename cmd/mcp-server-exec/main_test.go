package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// commands writes a command file and loads it.
func commands(t *testing.T, yaml string) map[string]*Command {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cmds, err := load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	return cmds
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"relative program":    {"version: 1\ncommands:\n  a: {argv: [echo]}\n", "absolute, clean path"},
		"program placeholder": {"version: 1\ncommands:\n  a: {argv: [\"/usr/bin/{p}\"], args: {p: {pattern: x}}}\n", "without placeholders"},
		"undeclared":          {"version: 1\ncommands:\n  a: {argv: [/bin/echo, \"{x}\"]}\n", "{x} is not in args"},
		"unused arg":          {"version: 1\ncommands:\n  a: {argv: [/bin/echo], args: {x: {pattern: a}}}\n", "x is not used"},
		"no pattern":          {"version: 1\ncommands:\n  a: {argv: [/bin/echo, \"{x}\"], args: {x: {}}}\n", "pattern is required"},
		"bad pattern":         {"version: 1\ncommands:\n  a: {argv: [/bin/echo, \"{x}\"], args: {x: {pattern: \"(\"}}}\n", "pattern:"},
		"bad default":         {"version: 1\ncommands:\n  a: {argv: [/bin/echo, \"{x}\"], args: {x: {pattern: \"[a-z]+\", default: \"1\"}}}\n", "default"},
		"bad name":            {"version: 1\ncommands:\n  Run-It: {argv: [/bin/echo]}\n", "the name must match"},
		"bad timeout":         {"version: 1\ncommands:\n  a: {argv: [/bin/echo], timeout: 2h}\n", "timeout"},
		"bad output":          {"version: 1\ncommands:\n  a: {argv: [/bin/echo], max_output: -1}\n", "max_output"},
		"bad env":             {"version: 1\ncommands:\n  a: {argv: [/bin/echo], env: {\"A=B\": x}}\n", "env"},
		"unknown key":         {"version: 1\ncommands:\n  a: {argv: [/bin/echo], shell: true}\n", "shell"},
		"version":             {"version: 2\ncommands:\n  a: {argv: [/bin/echo]}\n", "version: 2"},
		"empty command":       {"version: 1\ncommands:\n  a:\n", "empty"},
	} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(tc.yaml), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := load([]string{p}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", "version: 1\ncommands:\n  one: {argv: [/bin/true]}\n")
	write("b.yaml", "")
	write("c.txt", "not read")
	cmds, err := load([]string{dir, filepath.Join(dir, "missing")})
	if err != nil || len(cmds) != 1 || cmds["one"] == nil {
		t.Fatalf("%v %v", cmds, err)
	}
	write("d.yaml", "version: 1\ncommands:\n  one: {argv: [/bin/false]}\n")
	if _, err := load([]string{dir}); err == nil || !strings.Contains(err.Error(), "a.yaml and in "+filepath.Join(dir, "d.yaml")) {
		t.Errorf("duplicate: %v", err)
	}
}

// The examples the package installs are valid.
func TestExamples(t *testing.T) {
	cmds, err := load([]string{filepath.Join("..", "..", "packaging", "exec-server", "examples.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) < 5 || len(warnings(cmds)) > 0 {
		t.Errorf("%d commands, warnings %q", len(cmds), warnings(cmds))
	}
}

func TestArgv(t *testing.T) {
	cmds := commands(t, `version: 1
commands:
  unit:
    argv: [/bin/echo, "--unit={unit}", "-n", "{lines}"]
    args:
      unit: {pattern: "[a-z.@-]+"}
      lines: {pattern: "[0-9]{1,4}", default: "50"}
  opt:
    argv: [/bin/echo, "{flag}"]
    args:
      flag: {pattern: "-[a-z]", allow_dash: true}
  text:
    argv: [/bin/echo, "{text}"]
    args:
      text: {pattern: "[a-z ;$()]+"}
`)
	argv, err := cmds["unit"].argv(map[string]string{"unit": "sshd"})
	if err != nil || strings.Join(argv, "|") != "/bin/echo|--unit=sshd|-n|50" {
		t.Errorf("%q %v", argv, err)
	}
	for _, tc := range []struct {
		cmd  string
		args map[string]string
		want string
	}{
		{"unit", map[string]string{"unit": "sshd; id"}, "does not match"},
		{"unit", map[string]string{"unit": "-x"}, `must not start with "-"`},
		{"unit", map[string]string{"unit": "a", "lines": "12345"}, "does not match"},
		{"unit", map[string]string{"lines": "1"}, `"unit" is required`},
		{"unit", map[string]string{"unit": "a", "user": "root"}, `unknown argument "user"`},
		{"text", map[string]string{"text": "a\x00b"}, "NUL"},
	} {
		if _, err := cmds[tc.cmd].argv(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %v: %v, want %q", tc.cmd, tc.args, err, tc.want)
		}
	}
	if argv, err := cmds["opt"].argv(map[string]string{"flag": "-n"}); err != nil || argv[1] != "-n" {
		t.Errorf("allow_dash: %q %v", argv, err)
	}
	// Whatever the pattern lets through stays one argument: no shell.
	argv, err = cmds["text"].argv(map[string]string{"text": "a; echo $(id)"})
	if err != nil || len(argv) != 2 || argv[1] != "a; echo $(id)" {
		t.Errorf("text: %q %v", argv, err)
	}
	r := cmds["text"].run(context.Background(), argv)
	if r.Stdout != "a; echo $(id)\n" || r.ExitCode != 0 {
		t.Errorf("run: %+v", r)
	}
}

func TestRun(t *testing.T) {
	cmds := commands(t, `version: 1
commands:
  env: {argv: [/usr/bin/env], env: {MY_VAR: x}}
  fail: {argv: [/bin/sh, -c, "echo out; echo err >&2; exit 3"]}
  slow: {argv: [/bin/sh, -c, "sleep 30 & sleep 30"], timeout: 300ms}
  big: {argv: [/usr/bin/head, -c, "5000", /dev/zero], max_output: 100}
  missing: {argv: [/nonexistent/program]}
`)
	t.Setenv("SECRET_FROM_PARENT", "leak")
	r := cmds["env"].run(context.Background(), cmds["env"].Argv)
	for _, want := range []string{"PATH=" + basePath, "LANG=C.UTF-8", "MY_VAR=x"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("env: no %s in %q", want, r.Stdout)
		}
	}
	if strings.Contains(r.Stdout, "SECRET_FROM_PARENT") || strings.Count(r.Stdout, "\n") != 3 {
		t.Errorf("env leaks: %q", r.Stdout)
	}
	if r := cmds["fail"].run(context.Background(), cmds["fail"].Argv); r.ExitCode != 3 || r.Stdout != "out\n" || r.Stderr != "err\n" {
		t.Errorf("fail: %+v", r)
	}
	// The timeout kills the process group: the background sleep too.
	start := time.Now()
	if r := cmds["slow"].run(context.Background(), cmds["slow"].Argv); !r.TimedOut || time.Since(start) > 5*time.Second {
		t.Errorf("slow: %+v after %s", r, time.Since(start))
	}
	if r := cmds["big"].run(context.Background(), cmds["big"].Argv); !r.Truncated || len(r.Stdout) != 100 || r.ExitCode != 0 {
		t.Errorf("big: truncated %v, %d bytes, exit %d", r.Truncated, len(r.Stdout), r.ExitCode)
	}
	if r := cmds["missing"].run(context.Background(), cmds["missing"].Argv); r.ExitCode != -1 || r.Stderr == "" {
		t.Errorf("missing: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	cmds["slow"].timeout = time.Minute
	if r := cmds["slow"].run(ctx, cmds["slow"].Argv); !r.Cancelled || r.TimedOut {
		t.Errorf("cancelled: %+v", r)
	}
}

// The MCP side: the tool list with schemas, calls, errors as tool errors.
func TestServer(t *testing.T) {
	s := &server{cmds: commands(t, `version: 1
commands:
  greet:
    description: Say hello
    argv: [/bin/echo, "hello {name}"]
    args:
      name: {pattern: "[a-z]+", description: who}
    read_only: true
  status: {argv: [/bin/sh, -c, "exit 1"]}
`)}
	res, err := s.handle(context.Background(), "tools/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := res.(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 2 || tools[0]["name"] != "greet" {
		t.Fatalf("tools: %v", tools)
	}
	schema, _ := json.Marshal(tools[0]["inputSchema"])
	if !strings.Contains(string(schema), `"pattern":"^(?:[a-z]+)$"`) || !strings.Contains(string(schema), `"required":["name"]`) {
		t.Errorf("schema: %s", schema)
	}
	if tools[0]["annotations"].(map[string]any)["readOnlyHint"] != true || tools[1]["annotations"].(map[string]any)["destructiveHint"] != true {
		t.Errorf("annotations: %v %v", tools[0]["annotations"], tools[1]["annotations"])
	}
	// What the tool runs and its limits follow the administrator's
	// description; without one, they are the description.
	if d := tools[0]["description"]; d != "Say hello\n\nRuns: /bin/echo \"hello {name}\". Ends after 1 min; output (stdout and stderr together) up to 1 MiB." {
		t.Errorf("greet description: %q", d)
	}
	if d := tools[1]["description"]; d != `Runs: /bin/sh -c "exit 1". Ends after 1 min; output (stdout and stderr together) up to 1 MiB.` {
		t.Errorf("status description: %q", d)
	}
	if a := tools[0]["annotations"].(map[string]any); tools[0]["title"] != "Greet" || a["title"] != "Greet" || a["idempotentHint"] != true {
		t.Errorf("greet title, annotations: %v %v", tools[0]["title"], a)
	}
	if _, ok := tools[1]["annotations"].(map[string]any)["idempotentHint"]; ok || tools[0]["outputSchema"] == nil {
		t.Errorf("status annotations %v, outputSchema %v", tools[1]["annotations"], tools[0]["outputSchema"])
	}
	instr := s.instructions()
	if !strings.Contains(instr, "The commands: greet: Say hello; status.") || !strings.Contains(instr, "ask the administrator") {
		t.Errorf("instructions: %q", instr)
	}
	s.about = "Commands run as you."
	if got := s.instructions(); !strings.HasPrefix(got, "Commands run as you.\n\nRuns commands") {
		t.Errorf("instructions with -instructions: %q", got)
	}
	call := func(name, args string) map[string]any {
		res, err := s.handle(context.Background(), "tools/call", json.RawMessage(`{"name":"`+name+`","arguments":`+args+`}`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return res.(map[string]any)
	}
	text := func(m map[string]any) string { return m["content"].([]map[string]any)[0]["text"].(string) }
	if m := call("greet", `{"name":"ann"}`); m["isError"] != false || text(m) != "hello ann\n[exit status 0]" {
		t.Errorf("greet: %v", m)
	}
	if m := call("greet", `{"name":"ann; id"}`); m["isError"] != true || !strings.Contains(text(m), "does not match") {
		t.Errorf("injection: %v", m)
	}
	if m := call("greet", `{"name":7}`); m["isError"] != true || !strings.Contains(text(m), "must be a string") {
		t.Errorf("number: %v", m)
	}
	if m := call("status", `{}`); m["isError"] != true || !strings.Contains(text(m), "[exit status 1]") {
		t.Errorf("status: %v", m)
	}
	if _, err := s.handle(context.Background(), "tools/call", json.RawMessage(`{"name":"rm"}`)); err == nil {
		t.Error("unknown tool accepted")
	}
}

func TestFormats(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Minute: "1 min", 15 * time.Second: "15 s", 2 * time.Hour: "2 h",
		1500 * time.Millisecond: "1.5s"} {
		if got := duration(d); got != want {
			t.Errorf("duration(%v) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[int]string{1 << 20: "1 MiB", 64 << 10: "64 KiB", 1000: "1000 bytes"} {
		if got := bytesize(n); got != want {
			t.Errorf("bytesize(%d) = %q, want %q", n, got, want)
		}
	}
	if title("package_version") != "Package version" || firstLine("Disk use.\nMore.") != "Disk use" {
		t.Error("title, firstLine")
	}
}

func TestCheckAndStart(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("version: 1\ncommands:\n  get_time: {argv: [/bin/date]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := run([]string{"--check", "--commands", good}, nil, &out, &errb); rc != 0 ||
		!strings.Contains(out.String(), "get_time\t/bin/date") || !strings.Contains(out.String(), "warning: get_time") {
		t.Errorf("check: rc %d\n%s%s", rc, out.String(), errb.String())
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\ncommands:\n  x: {argv: [date]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	// A broken file keeps the server from starting.
	if rc := run([]string{"--commands", bad}, strings.NewReader(""), &out, &errb); rc != 1 || !strings.Contains(errb.String(), "bad.yaml") {
		t.Errorf("bad: rc %d %s", rc, errb.String())
	}
}

// The definition the package installs: this program on the command
// directory, as the calling user, without network, in its own domain.
func TestDefinition(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("..", "..", "packaging", "exec-server", "exec.yaml.in"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	def := strings.NewReplacer("@LIBEXECDIR@", "/usr/libexec", "@DATADIR@", "/usr/share").Replace(string(in))
	if err := os.WriteFile(filepath.Join(dir, "exec.yaml"), []byte(def), 0o644); err != nil {
		t.Fatal(err)
	}
	backends, err := config.LoadBackends(dir, filepath.Join(dir, "none"))
	if err != nil {
		t.Fatal(err)
	}
	b := backends["exec"]
	if b == nil || b.RunAs != "principal" || b.Privileged || b.Network || b.SELinuxType != "mcpsrv_exec_t" ||
		len(b.Command) != 5 || strings.Join(b.Command[:3], " ") != "/usr/libexec/mcp-servers/mcp-server-exec --commands "+defaultCommands ||
		b.Command[3] != "--instructions" {
		t.Fatalf("%+v", b)
	}
	// The instructions say what the definition sets, which the server
	// cannot know: as the user, without network, in its domain.
	for _, want := range []string{"run as you", "without network", b.SELinuxType, defaultCommands} {
		if !strings.Contains(b.Command[4], want) {
			t.Errorf("instructions without %q: %q", want, b.Command[4])
		}
	}
}
