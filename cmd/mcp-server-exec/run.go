package main

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"
)

// basePath is the PATH programs see (argv[0] is absolute; this is for
// what they start themselves).
const basePath = "/usr/sbin:/usr/bin:/sbin:/bin"

// result is what running a command gave.
type result struct {
	Argv      []string `json:"argv"`
	ExitCode  int      `json:"exit_code"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Truncated bool     `json:"truncated,omitempty"`
	TimedOut  bool     `json:"timed_out,omitempty"`
	Cancelled bool     `json:"cancelled,omitempty"`
	Seconds   float64  `json:"seconds"`
}

// limit is the output a command may still give, shared by its stdout
// and stderr, which os/exec copies in goroutines of their own.
type limit struct {
	mu        sync.Mutex
	left      int
	truncated bool
}

// capped keeps what one stream writes while the shared limit allows.
type capped struct {
	lim *limit
	buf []byte
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	c.lim.mu.Lock()
	defer c.lim.mu.Unlock()
	if len(p) > c.lim.left {
		p = p[:c.lim.left]
		c.lim.truncated = true
	}
	c.buf = append(c.buf, p...)
	c.lim.left -= len(p)
	return n, nil
}

// run runs argv without a shell: stdin is /dev/null, the environment is
// a fixed PATH and LANG plus the command's env, stdout and stderr
// together are kept up to the command's max_output. The program runs in
// a process group of its own, which is killed when the command's timeout
// passes or ctx ends (the client cancelled), so that what it started
// ends too.
func (c *Command) run(ctx context.Context, argv []string) result {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + basePath, "LANG=C.UTF-8"}
	keys := make([]string, 0, len(c.Env))
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cmd.Env = append(cmd.Env, k+"="+c.Env[k])
	}
	cmd.Dir = c.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	// After the kill, output still held by pipes is not waited for long.
	cmd.WaitDelay = 2 * time.Second

	lim := &limit{left: c.MaxOutput}
	stdout, stderr := &capped{lim: lim}, &capped{lim: lim}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	start := time.Now()
	err := cmd.Run()
	r := result{
		Argv:      argv,
		Stdout:    string(stdout.buf),
		Stderr:    string(stderr.buf),
		Truncated: lim.truncated,
		Seconds:   time.Since(start).Round(time.Millisecond).Seconds(),
	}
	var exitErr *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		r.TimedOut, r.ExitCode = true, -1
	case ctx.Err() != nil:
		r.Cancelled, r.ExitCode = true, -1
	case errors.As(err, &exitErr):
		r.ExitCode = exitErr.ExitCode()
	case err != nil:
		r.ExitCode = -1
		r.Stderr += err.Error()
	}
	return r
}
