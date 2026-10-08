package landlock

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A restriction cannot be undone: each case runs in a child, the test
// binary run again with childEnv set.
const childEnv = "LANDLOCK_TEST_CHILD"

type childCase struct {
	Rules Rules
	Root  string
	Port  int // a listening port to connect to
}

type childResult struct {
	Result  Result
	Err     string
	Outcome map[string]string // operation: "ok" or the error
}

func TestMain(m *testing.M) {
	if c := os.Getenv(childEnv); c != "" {
		runtime.LockOSThread()
		var cc childCase
		if err := json.Unmarshal([]byte(c), &cc); err != nil {
			panic(err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(child(cc))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, unix.EACCES) {
		return "EACCES"
	}
	if errors.Is(err, unix.EPERM) {
		return "EPERM"
	}
	return err.Error()
}

func child(cc childCase) childResult {
	// The checkout may lie below /tmp, which Base allows: only what the
	// test needs to run.
	Base = Rules{Exec: []string{"/usr", "/bin", "/lib", "/lib64"}, Write: []string{"/dev/null"}}
	res, err := Restrict(cc.Rules)
	out := childResult{Result: res, Outcome: map[string]string{}}
	if err != nil {
		out.Err = err.Error()
		return out
	}
	r := func(p string) error { _, err := os.ReadFile(filepath.Join(cc.Root, p)); return err }
	w := func(p string) error { return os.WriteFile(filepath.Join(cc.Root, p), []byte("x"), 0o600) }
	ls := func(p string) error { _, err := os.ReadDir(filepath.Join(cc.Root, p)); return err }
	out.Outcome["read mine"] = outcome(r("mine/f"))
	out.Outcome["write mine"] = outcome(w("mine/new"))
	out.Outcome["read theirs"] = outcome(r("theirs/g"))
	out.Outcome["list theirs"] = outcome(ls("theirs"))
	out.Outcome["read link out"] = outcome(r("mine/link"))
	out.Outcome["read docs"] = outcome(r("docs/h"))
	out.Outcome["write docs"] = outcome(w("docs/x"))
	out.Outcome["exec /bin/true"] = outcome(exec.Command("/bin/true").Run())
	out.Outcome["signal parent"] = outcome(unix.Kill(os.Getppid(), 0))
	if cc.Port != 0 {
		c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(cc.Port))
		if err == nil {
			_ = c.Close()
		}
		out.Outcome["connect"] = outcome(err)
	}
	return out
}

func runChild(t *testing.T, cc childCase) childResult {
	t.Helper()
	b, _ := json.Marshal(cc)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+string(b))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v: %s", err, out)
	}
	var res childResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("child output %q: %v", out, err)
	}
	return res
}

func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"mine", "theirs", "docs"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for f, s := range map[string]string{"mine/f": "a", "theirs/g": "b", "docs/h": "c"} {
		// World-readable: only Landlock keeps the instance out.
		if err := os.WriteFile(filepath.Join(root, f), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "theirs", "g"), filepath.Join(root, "mine", "link")); err != nil {
		t.Fatal(err)
	}
	return root
}

// An instance reads and writes its own tree, reads a read-only one, and
// nothing else: not world-readable files elsewhere, not through a link.
func TestRestrict(t *testing.T) {
	abi := ABI()
	if abi == 0 {
		t.Skip("no Landlock in this kernel")
	}
	root := tree(t)
	res := runChild(t, childCase{Root: root, Rules: Rules{
		Write: []string{filepath.Join(root, "mine")},
		Read:  []string{filepath.Join(root, "docs"), filepath.Join(root, "absent")},
	}})
	if res.Err != "" {
		t.Fatal(res.Err)
	}
	want := map[string]string{
		"read mine": "ok", "write mine": "ok", "read theirs": "EACCES", "list theirs": "EACCES",
		"read link out": "EACCES", "read docs": "ok", "write docs": "EACCES", "exec /bin/true": "ok",
	}
	for op, w := range want {
		if got := res.Outcome[op]; got != w {
			t.Errorf("%s: %s, want %s", op, got, w)
		}
	}
	if res.Result.ABI != abi || len(res.Result.Missing) != 1 || res.Result.Missing[0] != filepath.Join(root, "absent") {
		t.Errorf("result %+v", res.Result)
	}
	// ABI 6: signals to processes outside the instance's domain.
	if abi >= 6 && (res.Outcome["signal parent"] != "EPERM" || !res.Result.Scoped) {
		t.Errorf("scoping: %s, %+v", res.Outcome["signal parent"], res.Result)
	}
}

// tcp_connect: the ports listed, none for an empty list; unset leaves
// TCP alone.
func TestTCP(t *testing.T) {
	if ABI() < 4 {
		t.Skip("no Landlock TCP rules in this kernel (ABI 4)")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	for _, c := range []struct {
		ports []int
		want  string
	}{{nil, "ok"}, {[]int{}, "EACCES"}, {[]int{port}, "ok"}, {[]int{port + 1}, "EACCES"}} {
		res := runChild(t, childCase{Root: t.TempDir(), Port: port, Rules: Rules{TCPConnect: c.ports}})
		if res.Err != "" || res.Outcome["connect"] != c.want {
			t.Errorf("tcp_connect %v: %q %s, want %s", c.ports, res.Err, res.Outcome["connect"], c.want)
		}
	}
}

// Without the kernel support it needs, a required ruleset refuses.
func TestRequired(t *testing.T) {
	abi := ABI()
	if abi == 0 {
		res := runChild(t, childCase{Root: t.TempDir(), Rules: Rules{Required: true}})
		if !strings.Contains(res.Err, "required") {
			t.Errorf("no Landlock, required: %+v", res)
		}
		return
	}
	if abi >= 6 {
		t.Skip("the kernel supports everything a ruleset asks for")
	}
	res := runChild(t, childCase{Root: t.TempDir(), Rules: Rules{Required: true}})
	if !strings.Contains(res.Err, "scoping") {
		t.Errorf("ABI %d, required: %+v", abi, res)
	}
}

func TestHandledFS(t *testing.T) {
	if handledFS(1)&unix.LANDLOCK_ACCESS_FS_REFER != 0 || handledFS(2)&unix.LANDLOCK_ACCESS_FS_REFER == 0 ||
		handledFS(2)&unix.LANDLOCK_ACCESS_FS_TRUNCATE != 0 || handledFS(3)&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0 ||
		handledFS(4)&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 || handledFS(5)&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV == 0 {
		t.Error("rights by ABI")
	}
}

func TestValidateExpand(t *testing.T) {
	for _, ok := range []Rules{{}, {Write: []string{"${HOME}"}, Read: []string{"/srv/${USER}/x", "/usr/share/doc"}, TCPConnect: []int{443}}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Rules{{Read: []string{"etc"}}, {Write: []string{"/home/../etc"}}, {Exec: []string{"/opt/"}},
		{Read: []string{"${XDG}/x"}}, {TCPConnect: []int{0}}, {TCPBind: []int{70000}}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	r := Rules{Write: []string{"${HOME}"}, Read: []string{"/srv/${USER}"}}.Expand(func(s string) string {
		return strings.NewReplacer("${HOME}", "/home/alice", "${USER}", "alice").Replace(s)
	})
	if r.Write[0] != "/home/alice" || r.Read[0] != "/srv/alice" || r.Exec != nil {
		t.Errorf("expanded %+v", r)
	}
}

func TestResultString(t *testing.T) {
	if s := (Result{}).String(); !strings.Contains(s, "not available") {
		t.Error(s)
	}
	s := Result{ABI: 5, Unsupported: []string{"x"}, Missing: []string{"/m"}}.String()
	if s != "Landlock ABI 5; not supported by the kernel: x; missing, left out: /m" {
		t.Error(s)
	}
}
