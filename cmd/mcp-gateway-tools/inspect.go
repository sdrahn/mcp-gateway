package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/inspect"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

const inspectUsage = `usage: mcp-gateway-admin inspect [options] -server NAME
       mcp-gateway-admin inspect [options] -name NAME -- COMMAND [ARG...]

Starts an MCP server, lists its tools, prompts and resource templates,
classifies the tools (read or change, from the server's annotations and
the tool names) and drafts roles for it: a reader role and an operator
role that asks for approval. With -roles it checks role data against the
tools the server has. The drafts are proposals to review, not policy.

-server starts a server of the registry as the gateway would for shared
discovery (through systemd, in its sandbox and SELinux domain; needs
root). With a command, the server runs as a plain child process of yours,
without sandbox: only for servers you trust.

Options:
`

// stringList collects a repeatable flag.
type stringList []string

func (l *stringList) String() string     { return fmt.Sprint(*l) }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

// runInspect implements "mcp-gateway-admin inspect"; it returns the exit code.
func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway-admin inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, inspectUsage)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "gateway configuration (for -server: registry and supervisor)")
	serverName := fs.String("server", "", "server of the registry to start")
	name := fs.String("name", "", "server name for a command (as in its definition)")
	useExec := fs.Bool("exec", false, "start a -server definition as a plain child process, without sandbox")
	var roles stringList
	fs.Var(&roles, "roles", "role data or shipped roles to check against the server (repeatable)")
	outDir := fs.String("out", "", "write the drafts to this directory (roles.json; NAME.yaml for a command)")
	readByName := fs.Bool("read-by-name", false, "put tools that read by their name alone into the reader role")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	timeout := fs.Duration("timeout", 60*time.Second, "how long to wait for the server")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	command := fs.Args()
	if (*serverName == "") == (len(command) == 0) || (len(command) > 0 && *name == "") {
		fs.Usage()
		return 2
	}
	if (*useExec || len(command) > 0) && os.Geteuid() == 0 {
		say(stderr, "a server without sandbox would run as root: run this as an unprivileged user, or use -server without -exec")
		return 1
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var b *config.Backend
	var launcher supervisor.Launcher
	p := principal.Discovery
	if *serverName != "" {
		gw, _, err := config.Resolve(*configPath)
		if err != nil {
			say(stderr, "loading configuration:", err)
			return 1
		}
		backends, err := config.LoadBackends(gw.VendorServersDir, gw.ServersDir)
		if err != nil {
			say(stderr, "loading backend registry:", err)
			return 1
		}
		if b = backends[*serverName]; b == nil {
			sayf(stderr, "no server %q in %s or %s", *serverName, gw.VendorServersDir, gw.ServersDir)
			return 1
		}
		mode := gw.Supervisor
		if *useExec {
			mode.Mode = "exec"
		} else if mode.Mode == "systemd" && os.Geteuid() != 0 {
			say(stderr, "starting a server through systemd needs root (or -exec, without sandbox)")
			return 1
		}
		if launcher, err = supervisor.NewLauncher(log, mode); err != nil {
			say(stderr, err)
			return 1
		}
	} else {
		path, err := exec.LookPath(command[0])
		if err != nil {
			say(stderr, err)
			return 1
		}
		if path, err = filepath.Abs(path); err != nil {
			say(stderr, err)
			return 1
		}
		b = &config.Backend{Name: *name, Command: append([]string{path}, command[1:]...)}
		b.ApplyDefaults()
		if err := b.Validate(); err != nil {
			say(stderr, err)
			return 2
		}
		launcher = &supervisor.Exec{Log: log}
		// The server runs as you; give it your home, as a principal's
		// instance would have (system accounts may have none).
		if u, err := user.Current(); err == nil {
			p = principal.Principal{Sub: u.Username, Home: "/", Transport: principal.TransportInternal, SessionID: "inspect"}
			if fi, err := os.Stat(u.HomeDir); err == nil && fi.IsDir() {
				p.Home = u.HomeDir
			}
		}
	}

	res, err := inspect.Start(ctx, launcher, b, p)
	if err != nil {
		sayf(stderr, "%s: %v", b.Name, err)
		return 1
	}
	verdicts := inspect.Classify(res.Tools, inspect.Options{ReadByName: *readByName})
	var findings []inspect.Finding
	if len(roles) > 0 {
		files := make([]inspect.RoleFile, 0, len(roles))
		for _, path := range roles {
			data, err := os.ReadFile(path)
			if err != nil {
				say(stderr, err)
				return 1
			}
			files = append(files, inspect.RoleFile{Name: path, Data: data})
		}
		var err error
		if findings, err = inspect.CheckRoles(files, b.Name, res); err != nil {
			say(stderr, err)
			return 1
		}
	}
	draftRoles := inspect.Roles(b.Name, verdicts)

	if *outDir != "" {
		if err := writeDrafts(*outDir, b.Name, command, b, res, draftRoles); err != nil {
			say(stderr, err)
			return 1
		}
	}
	if *asJSON {
		out := map[string]any{
			"server":   b.Name,
			"result":   res,
			"verdicts": verdicts,
			"roles":    draftRoles,
		}
		if findings != nil {
			out["findings"] = findings
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			say(stderr, err)
			return 1
		}
	} else {
		if err := inspect.Report(stdout, b.Name, res, verdicts, findings); err != nil {
			say(stderr, err)
			return 1
		}
		if *outDir != "" {
			sayf(stdout, "\nDrafts written to %s; review them before use.", *outDir)
		}
	}
	if inspect.Errors(findings) > 0 {
		return 1
	}
	return 0
}

// writeDrafts writes roles.json and, for a server started by command, a
// draft definition. Existing files are not overwritten.
func writeDrafts(dir, name string, command []string, b *config.Backend, res *inspect.Result, roles map[string]any) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(roles, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{"roles.json": append(data, '\n')}
	if len(command) > 0 {
		files[name+".yaml"] = []byte(inspect.Definition(name, b.Command, res))
	}
	for f, content := range files {
		path := filepath.Join(dir, f)
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = fh.Write(content)
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// say and sayf write a line of output; a failed write to the terminal
// leaves nothing to report it on.
func say(w io.Writer, a ...any) { _, _ = fmt.Fprintln(w, a...) }

func sayf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }

// randomID returns an instance id (lower-case hex).
func randomID() string {
	id := make([]byte, 8)
	_, _ = rand.Read(id) // never fails (crypto/rand)
	return hex.EncodeToString(id)
}
