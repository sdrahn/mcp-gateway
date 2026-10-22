// Command mcp-policy-render writes the role data in force below
// /etc/mcp-gateway/policy/rbac (data.yaml before data.json, in every
// directory) as JSON to /run/mcp-opa/rbac, which OPA loads as
// data.mcp.rbac (docs/architecture.md, roadmap step 37). It runs as root
// from mcp-policy-render.service, which mcp-policy-render.path starts on
// every change of the role data. Role data that does not parse renders
// nothing: the last rendering stays in force. What it did goes to stderr
// (the journal).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const name = "mcp-policy-render"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	src := fs.String("source", policydata.DefaultDir, "the role data's directory")
	out := fs.String("out", policydata.RenderDir, "the directory OPA loads as data.mcp.rbac")
	shipped := fs.String("shipped", policydata.DefaultShippedDir, "the shipped policy, for the setups' roles")
	check := fs.Bool("check", false, "only report whether the rendering is current (exit status 1 if not)")
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
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(stderr, format+"\n", a...) }

	p, err := policydata.PlanRender(*src, *shipped)
	if err != nil {
		say("%s: %v", name, err)
		say("%s: role data not rendered; the last rendering in %s stays in force", name, *out)
		return 1
	}
	for _, s := range p.Sources {
		for _, ig := range s.Ignored {
			say("%s is ignored: %s is in force", ig, s.File)
		}
	}
	for _, f := range p.Unloaded {
		say("%s is not loaded: only data.yaml or data.json is role data", f)
	}
	for _, pr := range p.Problems {
		say("warning: %s", pr)
	}
	if *check {
		write, remove, err := p.Stale(*out)
		if err != nil {
			say("%s: %v", name, err)
			return 1
		}
		for _, f := range write {
			say("not current: %s", f)
		}
		for _, f := range remove {
			say("left over: %s", f)
		}
		if len(write)+len(remove) > 0 {
			return 1
		}
		say("%s is current", *out)
		return 0
	}
	// A change while this runs may not start the service again
	// (mcp-policy-render.path): render until the role data stays put.
	for i := 0; ; i++ {
		written, removed, err := p.Render(*out)
		for _, f := range written {
			say("rendered %s", f)
		}
		for _, f := range removed {
			say("removed %s", f)
		}
		if err != nil {
			say("%s: %v", name, err)
			return 1
		}
		if len(written)+len(removed) == 0 || i == 2 {
			break
		}
		next, err := policydata.PlanRender(*src, *shipped)
		if err != nil {
			break // reported by the run the next change starts
		}
		if w, r, err := next.Stale(*out); err != nil || len(w)+len(r) == 0 {
			break
		}
		p = next
	}
	if len(p.Sources) == 0 {
		say("no role data in %s", *src)
	}
	return 0
}
