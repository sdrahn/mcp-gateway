// Command mcp-landlock restricts itself with Landlock to the trees and
// TCP ports it is given (and landlock.Base), then executes a program, an
// MCP server, which keeps the restriction: the supervisor puts it in
// front of the command of every instance whose definition has landlock
// (docs/architecture.md, roadmap step 30). One line on stderr (the
// journal) says what the kernel applied.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const name = "mcp-landlock"

// Landlock restricts a thread: main restricts and executes on the thread
// it starts on.
func init() { runtime.LockOSThread() }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, unix.Exec))
}

func run(args []string, stdout, stderr io.Writer, execve func(string, []string, []string) error) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", "{}", `the rules as JSON: {"read": [...], "write": [...], "exec": [...], "tcp_connect": [...], "tcp_bind": [...], "required": false}`)
	showVersion := fs.Bool("version", false, "print the version and the kernel's Landlock ABI, and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [-rules JSON] [--] PROGRAM [ARG...]\n\nRestricts itself with Landlock, then executes PROGRAM.\n\n", name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "%s %s (Landlock ABI %d)\n", name, version.Version, landlock.ABI())
		return 0
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fs.Usage()
		return 2
	}
	var r landlock.Rules
	if err := json.Unmarshal([]byte(*rules), &r); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: -rules: %v\n", name, err)
		return 2
	}
	if err := r.Validate(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 2
	}
	program := argv[0]
	if !filepath.IsAbs(program) {
		p, err := exec.LookPath(program)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return 127
		}
		program = p
	}
	res, err := landlock.Restrict(r)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v (%s)\n", name, err, res)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, res)
	err = execve(program, argv, os.Environ())
	_, _ = fmt.Fprintf(stderr, "%s: %s: %v\n", name, program, err)
	return 127
}
