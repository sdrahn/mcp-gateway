package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/inspect"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/profile"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

const profileUsage = `usage: mcp-gateway profile [options] --server NAME --out DIR
       mcp-gateway profile [options] --server NAME --verify

Runs a registered MCP server in a permissive SELinux domain (only that
domain), calls its tools and records the SELinux denials of the run.
From them it drafts a policy module (a new domain mcpsrv_NAME_t for a
server that has none yet, or additions to its domain) and a definition,
with a report of what else the run suggests (network, polkit, programs
it runs). The drafts are proposals to review; they cover what the run
reached and nothing else.

Without --calls, only tools that read (by their annotations or names)
are called, with arguments made up from their schemas. --call-all calls
every tool: only on a system that may be changed, such as a test VM.

--verify runs the same calls with SELinux enforcing, loads nothing and
fails if there is a denial.

Needs root, the systemd supervisor, SELinux and, to build modules,
selinux-policy-devel. While it runs, it loads a temporary module
mcpprof_NAME; it removes it at the end.

Options:
`

// runProfile implements "mcp-gateway profile"; it returns the exit code.
func runProfile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway profile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, profileUsage)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "gateway configuration (registry and supervisor)")
	serverName := fs.String("server", "", "server of the registry to profile")
	outDir := fs.String("out", "", "directory for the drafts and the report")
	callsFile := fs.String("calls", "", "JSON file mapping tool names to arguments (an object, or a list of them)")
	callAll := fs.Bool("call-all", false, "call every tool, also those that change things (throwaway systems only)")
	verify := fs.Bool("verify", false, "run the calls with SELinux enforcing and fail on denials; load and draft nothing")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long the run may take")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *serverName == "" || fs.NArg() > 0 || (!*verify && *outDir == "") {
		fs.Usage()
		return 2
	}
	if os.Geteuid() != 0 {
		say(stderr, "mcp-gateway profile needs root")
		return 1
	}
	if !supervisor.SELinuxEnabled() {
		say(stderr, "SELinux is not enabled: there is nothing to profile")
		return 1
	}
	gw, _, err := config.Resolve(*configPath)
	if err != nil {
		say(stderr, "loading configuration:", err)
		return 1
	}
	if gw.Supervisor.Mode != "systemd" {
		say(stderr, "profiling needs the systemd supervisor (supervisor.mode)")
		return 1
	}
	backends, err := config.LoadBackends(gw.VendorServersDir, gw.ServersDir)
	if err != nil {
		say(stderr, "loading backend registry:", err)
		return 1
	}
	orig := backends[*serverName]
	if orig == nil {
		sayf(stderr, "no server %q in %s or %s", *serverName, gw.VendorServersDir, gw.ServersDir)
		return 1
	}
	var given map[string][]map[string]any
	if *callsFile != "" {
		data, err := os.ReadFile(*callsFile)
		if err == nil {
			given, err = profile.ParseCalls(data)
		}
		if err != nil {
			sayf(stderr, "%s: %v", *callsFile, err)
			return 1
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	// Cleanup runs even when the run was interrupted or timed out.
	cleanup := context.Background()

	b := *orig
	d := profile.Domain{Server: b.Name, Type: b.SELinuxType, Exec: b.Command[0]}
	if !*verify {
		d = profile.NewDomain(b.Name, b.SELinuxType, config.DefaultSELinuxType, b.Command[0])
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			say(stderr, err)
			return 1
		}
		if d.New && profile.Interpreter(d.Exec) {
			sayf(stderr, "%s is an interpreter: labelling it would put every script it runs into %s; start the server through its own program", d.Exec, d.Type)
			return 1
		}
		b.SELinuxType = d.Type
		tmp, err := os.MkdirTemp("", "mcpprof-")
		if err != nil {
			say(stderr, err)
			return 1
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		name, te, fc := d.ProfilingModule()
		pp, err := profile.Build(ctx, tmp, name, te, fc)
		if err == nil {
			err = profile.Install(ctx, pp)
		}
		if err != nil {
			say(stderr, err)
			return 1
		}
		defer func() {
			if err := profile.Remove(cleanup, name); err != nil {
				say(stderr, err)
			}
			if d.New {
				_ = profile.Relabel(cleanup, d.Exec)
			}
		}()
		if d.New {
			if err := profile.Relabel(ctx, d.Exec); err != nil {
				say(stderr, err)
				return 1
			}
		}
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	launcher, err := newLauncher(log, gw.Supervisor)
	if err != nil {
		say(stderr, err)
		return 1
	}
	since := time.Now()
	rep := &profile.Report{Server: b.Name, Domain: d, Verify: *verify, ExecPath: d.Exec}
	failed := false
	if err := exercise(ctx, launcher, &b, given, *callAll, rep); err != nil {
		sayf(stderr, "%s: %v", b.Name, err)
		failed = true
	}
	for _, o := range rep.Calls {
		if o.Err != "" {
			failed = true
		}
	}

	// Audit records arrive asynchronously.
	time.Sleep(2 * time.Second)
	raw, err := profile.ReadAudit(cleanup)
	if err != nil {
		say(stderr, "reading the audit records:", err)
		return 1
	}
	all, errs := profile.Parse(raw, since)
	rep.Denials, rep.Errs = profile.Involving(all, errs, d.Type)
	draft := profile.DraftModule(d, rep.Denials, rep.Errs)
	rep.Hints = append(draft.Hints, profile.CallHints(rep.Calls)...)

	if !*verify {
		if _, err := profile.Build(cleanup, *outDir, draft.Module, draft.TE, draft.FC); err != nil {
			rep.Hints = append(rep.Hints, "the drafted module does not build as it is: "+oneLineErr(err))
		}
		rep.Files = append(rep.Files, draft.Module+".te")
		if draft.FC != "" {
			rep.Files = append(rep.Files, draft.Module+".fc")
		}
		def, err := definition(orig, d, draft.Hints)
		if err == nil {
			err = os.WriteFile(filepath.Join(*outDir, b.Name+".yaml"), def, 0o644)
		}
		if err != nil {
			say(stderr, err)
			return 1
		}
		rep.Files = append(rep.Files, b.Name+".yaml", "report.txt", "calls.json")
		calls, _ := json.MarshalIndent(rep.Calls, "", "  ")
		if err := os.WriteFile(filepath.Join(*outDir, "calls.json"), append(calls, '\n'), 0o644); err != nil {
			say(stderr, err)
			return 1
		}
		f, err := os.Create(filepath.Join(*outDir, "report.txt"))
		if err == nil {
			err = rep.Write(f)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			say(stderr, err)
			return 1
		}
	}
	if err := rep.Write(stdout); err != nil {
		say(stderr, err)
		return 1
	}
	if *verify && (len(rep.Denials) > 0 || len(rep.Errs) > 0) {
		failed = true
	}
	if failed {
		return 1
	}
	return 0
}

// exercise starts an instance of b, lists what it offers and makes the
// planned calls, recording them in rep.
func exercise(ctx context.Context, l supervisor.Launcher, b *config.Backend, given map[string][]map[string]any, all bool, rep *profile.Report) error {
	inst, err := l.Start(ctx, b, principal.Discovery, randomID())
	if err != nil {
		return fmt.Errorf("starting: %w", err)
	}
	defer func() { _ = inst.Close() }()
	sess, res, err := inspect.Open(ctx, inst)
	if err != nil {
		return err
	}
	defer sess.Close()
	rep.Program = res.Server.Name
	if res.Server.Version != "" {
		rep.Program += " " + res.Server.Version
	}
	verdicts := inspect.Classify(res.Tools, inspect.Options{})
	calls, unknown := profile.Plan(res.Tools, verdicts, given, all)
	rep.Unknown = unknown
	for _, c := range calls {
		o := profile.Outcome{Call: c}
		r, err := sess.Call(c.Tool, c.Args)
		if err != nil {
			o.Err = err.Error()
			rep.Calls = append(rep.Calls, o)
			return nil // the session is gone; the denials so far still count
		}
		o.IsError, o.Text = r.IsError, r.Text
		rep.Calls = append(rep.Calls, o)
	}
	return nil
}

// definition drafts the server's definition with the profiled domain and
// what the run suggests (network).
func definition(orig *config.Backend, d profile.Domain, hints []string) ([]byte, error) {
	b := *orig
	b.SELinuxType = d.Type
	for _, h := range hints {
		if strings.HasPrefix(h, "network:") {
			b.Network = true
		}
	}
	body, err := yaml.Marshal(&b)
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("# Draft by mcp-gateway profile: the definition of %s with selinux_type %s\n"+
		"# (and network: true if the run connected to the network). Compare it with the\n"+
		"# definition in use before installing it in /etc/mcp-gateway/servers.d.\n", b.Name, d.Type)
	return append([]byte(head), body...), nil
}

func oneLineErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
