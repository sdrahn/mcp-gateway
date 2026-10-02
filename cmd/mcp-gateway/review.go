package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sdrahn/mcp-gateway/internal/profile"
	"github.com/sdrahn/mcp-gateway/internal/review"
)

const reviewUsage = `usage: mcp-gateway review [options] --source DIR

Scans an MCP server's source for what it does to the system: programs it
runs, D-Bus services and polkit actions it names, paths, network access,
root checks and environment variables, each with file and line, and with
the program's or path's SELinux type on this system. Given the output of
a profiling run (--profile), it marks what that run recorded a denial
for, so that code paths the run did not reach stand out.

The scan is textual (Go, Python, JavaScript/TypeScript, C/C++, Rust):
it shows what the code mentions, not what each tool does. Tests and
vendored code are left out.

Options:
`

// runReview implements "mcp-gateway review"; it returns the exit code.
func runReview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway review", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, reviewUsage)
		fs.PrintDefaults()
	}
	source := fs.String("source", "", "the server's source tree")
	mainPkg := fs.String("main", "", "Go: the server's main package, relative to the module root (--source); only the packages it imports are scanned")
	profDir := fs.String("profile", "", "drafts directory of a profiling run (mcp-gateway profile --out), for its denials.json")
	asJSON := fs.Bool("json", false, "print the review as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *source == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	var opts review.Options
	if *mainPkg != "" {
		dirs, err := review.GoPackageDirs(*source, *mainPkg)
		if err != nil {
			say(stderr, err)
			return 1
		}
		opts.GoDirs = dirs
	}
	var prof *review.Profile
	if *profDir != "" {
		var err error
		if prof, err = loadProfile(filepath.Join(*profDir, "denials.json")); err != nil {
			say(stderr, err)
			return 1
		}
	}
	scan, err := review.ScanDir(*source, opts)
	if err != nil {
		say(stderr, err)
		return 1
	}
	items := review.Review(scan, review.Locate, prof)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"source": *source, "files": scan.Files, "items": items}); err != nil {
			say(stderr, err)
			return 1
		}
		return 0
	}
	if err := review.WriteReport(stdout, *source, scan, items, prof); err != nil {
		say(stderr, err)
		return 1
	}
	return 0
}

// loadProfile reads denials.json of a profiling run: the types on the
// other side of the domain's denials.
func loadProfile(path string) (*review.Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f profile.DenialsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p := &review.Profile{Domain: f.Domain, Targets: map[string]bool{}}
	for _, d := range f.Denials {
		switch {
		case d.Source == f.Domain:
			p.Targets[d.Target] = true
		case d.Target == f.Domain:
			p.Targets[d.Source] = true
		}
	}
	return p, nil
}
