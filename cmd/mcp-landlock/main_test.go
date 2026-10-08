package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
)

func TestUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	never := func(string, []string, []string) error { t.Fatal("executed"); return nil }
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{nil, 2, "usage:"},
		{[]string{"-rules", "{", "/bin/true"}, 2, "-rules:"},
		{[]string{"-rules", `{"read":["etc"]}`, "/bin/true"}, 2, "not an absolute, clean path"},
		{[]string{"no-such-program-x"}, 127, "executable file not found"},
	} {
		errOut.Reset()
		if code := run(c.args, &out, &errOut, never); code != c.code || !strings.Contains(errOut.String(), c.msg) {
			t.Errorf("%v: %d %q", c.args, code, errOut.String())
		}
	}
}

// The program is executed with its arguments, after one line on stderr;
// a failed exec is reported. (What the restriction does is tested in
// internal/landlock; this test process stays restricted when Landlock
// is there, so it runs in a child.)
func TestExec(t *testing.T) {
	if os.Getenv("MCP_LANDLOCK_TEST_CHILD") == "1" {
		var errOut bytes.Buffer
		var got []string
		code := run([]string{"--", "true", "a"}, &bytes.Buffer{}, &errOut, func(p string, argv, env []string) error {
			got = append([]string{p}, argv...)
			return errors.New("not really")
		})
		if code != 127 || len(got) != 3 || filepath.Base(got[0]) != "true" || got[2] != "a" ||
			!strings.Contains(errOut.String(), "mcp-landlock: ") || !strings.Contains(errOut.String(), "not really") {
			_, _ = os.Stdout.WriteString("FAIL " + errOut.String())
			os.Exit(1)
		}
		_, _ = os.Stdout.WriteString("OK " + errOut.String())
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExec$")
	cmd.Env = append(os.Environ(), "MCP_LANDLOCK_TEST_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "OK ") {
		t.Fatalf("%v: %s", err, out)
	}
	if landlock.ABI() > 0 && !strings.Contains(string(out), "Landlock ABI") {
		t.Errorf("no report: %s", out)
	}
}
