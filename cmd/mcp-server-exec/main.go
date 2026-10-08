// Command mcp-server-exec is an MCP server that runs commands an
// administrator allows, run by mcp-gateway as the server "exec" (package
// mcp-gateway-exec-server). Each command in the command files (by
// default /etc/mcp-gateway/exec.d/*.yaml) is one tool: a fixed program
// and argument vector, with placeholders for the arguments the caller
// gives, each checked against its pattern. Commands run without a shell
// (execve), with a timeout and an output limit, in the server's sandbox
// and SELinux domain; who may run which command, and with whose
// approval, is the gateway's policy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
	"github.com/sdrahn/mcp-gateway/internal/mcpserver"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const (
	serverName      = "mcp-server-exec"
	defaultCommands = "/etc/mcp-gateway/exec.d"
)

type pathFlags []string

func (p *pathFlags) String() string     { return strings.Join(*p, ",") }
func (p *pathFlags) Set(v string) error { *p = append(*p, v); return nil }

// restrict is landlock.Self in the program, nil in tests that call run.
var restrict func(landlock.Rules) (landlock.Result, error)

func main() {
	restrict = landlock.Self
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(serverName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var paths pathFlags
	fs.Var(&paths, "commands", "a command file, or a directory of *.yaml command files (repeatable; default "+defaultCommands+")")
	check := fs.Bool("check", false, "check the command files, list the commands and exit")
	about := fs.String("instructions", "", "how the commands run here, for the client's model (opens the server's instructions)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [options]\n\nAn MCP server for allowed commands, on stdin/stdout.\n\n", serverName)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, serverName, version.Version)
		return 0
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	if len(paths) == 0 {
		paths = pathFlags{defaultCommands}
	}
	cmds, err := load(paths)
	if err != nil {
		// Refuse to start: a broken file must not leave some commands
		// running and others silently missing.
		_, _ = fmt.Fprintln(stderr, serverName+":", err)
		return 1
	}
	warns := warnings(cmds)
	if *check {
		for _, name := range sortedNames(cmds) {
			_, _ = fmt.Fprintf(stdout, "%s\t%s\n", name, strings.Join(cmds[name].Argv, " "))
		}
		for _, w := range warns {
			_, _ = fmt.Fprintln(stdout, "warning:", w)
		}
		_, _ = fmt.Fprintf(stdout, "%d commands\n", len(cmds))
		return 0
	}
	// The kernel keeps the server and its commands to the trees they
	// name (Landlock, D19), whatever starts it. Before any output: the
	// program runs again restricted.
	ll := "not restricted"
	if restrict != nil {
		rules := landlockRules(cmds)
		// The command files, which the program reads again.
		for _, p := range paths {
			if abs, err := filepath.Abs(p); err == nil {
				rules.Read = append(rules.Read, abs)
			}
		}
		res, err := restrict(rules)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, serverName+":", err)
			return 1
		}
		ll = res.String()
	}
	for _, w := range warns {
		_, _ = fmt.Fprintln(stderr, serverName+": warning:", w)
	}
	// A log line on stderr, which goes to the journal.
	_, _ = fmt.Fprintf(stderr, "%s: %d commands from %s; %s\n", serverName, len(cmds), strings.Join(paths, ", "), ll)
	s := &server{cmds: cmds, about: *about}
	// Requests carry only arguments, which are short.
	if err := mcpserver.New(s.handle, stdout).Serve(stdin, 1<<20); err != nil {
		_, _ = fmt.Fprintln(stderr, serverName+":", err)
		return 1
	}
	return 0
}

type server struct {
	cmds map[string]*Command
	// about, if set, opens the instructions: what the server's
	// definition knows and the server does not (the account, network,
	// SELinux domain the commands run in).
	about string
}

// maxListed bounds the commands the instructions name.
const maxListed = 40

func (s *server) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{
			"protocolVersion": mcpserver.Negotiate(p.ProtocolVersion),
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "title": "Commands", "version": version.Version},
			"instructions":    s.instructions(),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.toolList()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "invalid params"}
		}
		c := s.cmds[p.Name]
		if c == nil {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "unknown tool " + strconv.Quote(p.Name)}
		}
		return s.call(ctx, c, p.Arguments), nil
	}
	return nil, &mcpserver.Error{Code: mcpserver.CodeMethodNotFound, Message: "method not found"}
}

func (s *server) instructions() string {
	var out string
	if len(s.cmds) == 0 {
		out = "Runs commands an administrator allows. None are configured (" + defaultCommands + ")."
	} else {
		out = "Runs commands an administrator allows, one tool each: a fixed program with the arguments the tool's schema describes. " +
			"There is no shell: arguments are passed as they are, and each must match its pattern. " +
			"A result has the output and the exit status; a command that runs too long is ended. " +
			"Only these commands can be run; for anything else, ask the administrator, who adds commands. The commands: "
		names := sortedNames(s.cmds)
		var parts []string
		for i, name := range names {
			if i == maxListed {
				parts = append(parts, fmt.Sprintf("and %d more", len(names)-i))
				break
			}
			part := name
			if d := firstLine(s.cmds[name].Description); d != "" {
				part += ": " + d
			}
			parts = append(parts, part)
		}
		out += strings.Join(parts, "; ") + "."
	}
	if s.about != "" {
		out = s.about + "\n\n" + out
	}
	return out
}

// firstLine is the first line of s, without a final period.
func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

// details says what a tool runs and within which limits, from its
// definition: the description is the administrator's, and agents
// should not need to guess the program or the limits.
func details(c *Command) string {
	argv := make([]string, len(c.Argv))
	for i, a := range c.Argv {
		argv[i] = a
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			argv[i] = strconv.Quote(a)
		}
	}
	out := "Runs: " + strings.Join(argv, " ")
	if c.Dir != "" {
		out += " (in " + c.Dir + ")"
	}
	return out + fmt.Sprintf(". Ends after %s; output (stdout and stderr together) up to %s.",
		duration(c.timeout), bytesize(c.MaxOutput))
}

func duration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%d min", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%d s", d/time.Second)
	}
	return d.String()
}

func bytesize(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// title is a tool's name as words: package_version → Package version.
func title(name string) string {
	s := strings.ReplaceAll(name, "_", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// outputSchema describes structuredContent: the run's result.
var outputSchema = map[string]any{"type": "object", "properties": map[string]any{
	"argv":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "the program and its arguments as run"},
	"exit_code": map[string]any{"type": "integer"},
	"stdout":    map[string]any{"type": "string"},
	"stderr":    map[string]any{"type": "string"},
	"truncated": map[string]any{"type": "boolean", "description": "the output was cut at the tool's limit"},
	"timed_out": map[string]any{"type": "boolean", "description": "the command was ended after its timeout"},
	"cancelled": map[string]any{"type": "boolean"},
	"seconds":   map[string]any{"type": "number"},
}, "required": []string{"argv", "exit_code", "stdout", "stderr", "seconds"}}

func (s *server) toolList() []map[string]any {
	tools := make([]map[string]any, 0, len(s.cmds))
	for _, name := range sortedNames(s.cmds) {
		c := s.cmds[name]
		props := map[string]any{}
		var required []string
		for argName, a := range c.Args {
			p := map[string]any{"type": "string", "pattern": "^(?:" + a.Pattern + ")$"}
			if a.Description != "" {
				p["description"] = a.Description
			}
			if a.Default != nil {
				p["default"] = *a.Default
			} else {
				required = append(required, argName)
			}
			props[argName] = p
		}
		schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			sort.Strings(required)
			schema["required"] = required
		}
		desc := details(c)
		if d := strings.TrimSpace(c.Description); d != "" {
			desc = d + "\n\n" + desc
		}
		annotations := map[string]any{"title": title(name), "readOnlyHint": c.ReadOnly, "destructiveHint": !c.ReadOnly,
			"openWorldHint": false}
		if c.ReadOnly {
			annotations["idempotentHint"] = true
		}
		tools = append(tools, map[string]any{
			"name": name, "title": title(name), "description": desc, "inputSchema": schema,
			"outputSchema": outputSchema, "annotations": annotations,
		})
	}
	return tools
}

func (s *server) call(ctx context.Context, c *Command, raw json.RawMessage) map[string]any {
	values := map[string]string{}
	if len(raw) > 0 && string(raw) != "null" {
		var anyValues map[string]any
		if err := json.Unmarshal(raw, &anyValues); err != nil {
			return toolError("arguments: %v", err)
		}
		for k, v := range anyValues {
			str, ok := v.(string)
			if !ok {
				return toolError("argument %q: must be a string", k)
			}
			values[k] = str
		}
	}
	argv, err := c.argv(values)
	if err != nil {
		return toolError("%v", err)
	}
	r := c.run(ctx, argv)
	var b strings.Builder
	b.WriteString(r.Stdout)
	if r.Stderr != "" {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteByte('\n')
		}
		b.WriteString("[stderr]\n" + r.Stderr)
	}
	if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	switch {
	case r.TimedOut:
		fmt.Fprintf(&b, "[ended after the timeout of %s]", c.timeout)
	case r.Cancelled:
		b.WriteString("[cancelled]")
	default:
		fmt.Fprintf(&b, "[exit status %d]", r.ExitCode)
	}
	if r.Truncated {
		fmt.Fprintf(&b, " [output cut at %d bytes]", c.MaxOutput)
	}
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": b.String()}},
		"structuredContent": r,
		"isError":           r.ExitCode != 0,
	}
}

func toolError(format string, a ...any) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf(format, a...)}}, "isError": true}
}
