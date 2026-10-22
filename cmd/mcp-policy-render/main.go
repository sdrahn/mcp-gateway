// Command mcp-policy-render writes the role data in force below
// /etc/mcp-gateway/policy/rbac (data.yaml before data.json, in every
// directory) as JSON to /run/mcp-opa/rbac, which OPA loads as
// data.mcp.rbac (docs/architecture.md, roadmap step 37). With -watch it
// runs as root as mcp-policy-render.service, renders, tells systemd it is
// ready (OPA starts after it) and renders again on every change below
// the role data's directory (inotify, and a check every minute). Role
// data that does not parse is not rendered: the last rendering stays in
// force. What it did goes to stderr (the journal).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

	"github.com/sdrahn/mcp-gateway/internal/fswatch"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const name = "mcp-policy-render"

// settle is how long changes must stop before a render (an editor's
// several writes, a tree being copied); recheck is the fallback for
// changes inotify did not tell.
var settle, recheck = 50 * time.Millisecond, time.Minute

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	r := renderer{}
	fs.StringVar(&r.src, "source", policydata.DefaultDir, "the role data's directory")
	fs.StringVar(&r.out, "out", policydata.RenderDir, "the directory OPA loads as data.mcp.rbac")
	fs.StringVar(&r.shipped, "shipped", policydata.DefaultShippedDir, "the shipped policy, for the setups' roles")
	check := fs.Bool("check", false, "only report whether the rendering is current (exit status 1 if not)")
	watch := fs.Bool("watch", false, "render, then again on every change, until stopped (mcp-policy-render.service)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [options]\n\nWrites the role data in force as JSON for OPA.\n\n", name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "%s %s\n", name, version.Version)
		return 0
	}
	if fs.NArg() > 0 || *check && *watch {
		fs.Usage()
		return 2
	}
	r.say = func(format string, a ...any) { _, _ = fmt.Fprintf(stderr, format+"\n", a...) }
	switch {
	case *check:
		return r.check()
	case *watch:
		return r.watch(ctx, sdNotify)
	}
	return r.render(true)
}

// sdNotify tells systemd a state (a no-op outside a Type=notify unit).
func sdNotify(state string) error {
	_, err := daemon.SdNotify(false, state)
	return err
}

type renderer struct {
	src, out, shipped string
	say               func(format string, a ...any)
}

// plan reads the role data in force and reports what is ignored, not
// loaded or not valid.
func (r renderer) plan() (policydata.Plan, bool) {
	p, err := policydata.PlanRender(r.src, r.shipped)
	if err != nil {
		r.say("%s: %v", name, err)
		r.say("%s: role data not rendered; the last rendering in %s stays in force", name, r.out)
		return p, false
	}
	for _, s := range p.Sources {
		for _, ig := range s.Ignored {
			r.say("%s is ignored: %s is in force", ig, s.File)
		}
	}
	for _, f := range p.Unloaded {
		r.say("%s is not loaded: only data.yaml or data.json is role data", f)
	}
	for _, pr := range p.Problems {
		r.say("warning: %s", pr)
	}
	return p, true
}

// render writes the role data in force to r.out and returns the exit
// status; verbose also says when there is no role data (the watcher's
// renders after the first do not).
func (r renderer) render(verbose bool) int {
	p, ok := r.plan()
	if !ok {
		return 1
	}
	written, removed, err := p.Render(r.out)
	for _, f := range written {
		r.say("rendered %s", f)
	}
	for _, f := range removed {
		r.say("removed %s", f)
	}
	if err != nil {
		r.say("%s: %v", name, err)
		return 1
	}
	if verbose && len(p.Sources) == 0 {
		r.say("no role data in %s", r.src)
	}
	return 0
}

func (r renderer) check() int {
	p, ok := r.plan()
	if !ok {
		return 1
	}
	write, remove, err := p.Stale(r.out)
	if err != nil {
		r.say("%s: %v", name, err)
		return 1
	}
	for _, f := range write {
		r.say("not current: %s", f)
	}
	for _, f := range remove {
		r.say("left over: %s", f)
	}
	if len(write)+len(remove) > 0 {
		return 1
	}
	r.say("%s is current", r.out)
	return 0
}

// watch renders, tells systemd it is ready, and renders again after each
// change below r.src (and of r.src itself, watched in its parent) until
// ctx ends. A change during a render is not lost: the watcher keeps it
// for the next round. Role data that does not parse is reported and
// waited out.
func (r renderer) watch(ctx context.Context, notify func(string) error) int {
	fsw, err := fswatch.New()
	if err != nil {
		r.say("%s: %v; changes are noticed every %s only", name, err, recheck)
	}
	defer func() { _ = fsw.Close() }()
	dirs := func() []string { return append(fswatch.Tree(r.src), filepath.Dir(r.src)) }
	if fsw != nil {
		fsw.Set(dirs())
	}
	status := func(rc int) {
		s := "STATUS=role data rendered to " + r.out
		if rc != 0 {
			s = "STATUS=role data not rendered (journalctl -u mcp-policy-render.service); the last rendering stays in force"
		}
		_ = notify(s)
	}
	rc := r.render(true)
	_ = notify(daemon.SdNotifyReady)
	status(rc)
	tick := time.NewTicker(recheck)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = notify(daemon.SdNotifyStopping)
			return 0
		case <-tick.C:
		case <-fsw.Events():
			if !settled(ctx, fsw.Events()) {
				continue // ctx ended
			}
			fsw.Set(dirs()) // directories created or removed
		}
		rc = r.render(false)
		status(rc)
	}
}

// settled waits until events stay quiet for settle, and reports false if
// ctx ends first.
func settled(ctx context.Context, events <-chan struct{}) bool {
	t := time.NewTimer(settle)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-events:
			t.Reset(settle)
		case <-t.C:
			return true
		}
	}
}
