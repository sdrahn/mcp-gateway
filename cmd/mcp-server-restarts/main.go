// Command mcp-server-restarts is an MCP server, run by mcp-gateway as the
// server "restarts" (package mcp-gateway-restarts-server), with one tool:
// what an update left waiting. It lists the services and processes that
// still use files an update replaced or removed, as zypper ps -s does,
// with the packages that own those files now; whether an update waits for
// a reboot (/run/reboot-needed); and the running and installed kernels.
// It reads only and takes no arguments. Reading other users' memory maps
// needs CAP_SYS_PTRACE, which its definition names: nothing else.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
	"github.com/sdrahn/mcp-gateway/internal/mcpserver"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const (
	serverName = "mcp-server-restarts"
	toolName   = "pending_restarts"
)

// restrict is landlock.Self in the program, nil in tests that call run.
var restrict func(landlock.Rules) (landlock.Result, error)

// landlockRules: besides landlock.Base (the system's configuration and
// programs, /proc, /sys; the rpm database and the kernels are below
// /usr), the reboot flag and the rpm database's old place. Nothing is
// written.
var landlockRules = landlock.Rules{Read: []string{"/run", "/var/lib/rpm"}}

func main() {
	restrict = landlock.Self
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, newScanner()))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, sc *scanner) int {
	fs := flag.NewFlagSet(serverName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	once := fs.Bool("once", false, "print what the tool returns (JSON) and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [options]\n\nAn MCP server, on stdin/stdout, with one tool: what an update left waiting\n(services to restart, a pending reboot, the kernels).\n\n", serverName)
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
	ll := "not restricted"
	if restrict != nil {
		res, err := restrict(landlockRules)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, serverName+":", err)
			return 1
		}
		ll = res.String()
	}
	if *once {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sc.scan(context.Background())); err != nil {
			return 1
		}
		return 0
	}
	// A log line on stderr, which goes to the journal.
	_, _ = fmt.Fprintf(stderr, "%s: ready; %s\n", serverName, ll)
	s := &server{scan: sc}
	if err := mcpserver.New(s.handle, stdout).Serve(stdin, 1<<20); err != nil {
		_, _ = fmt.Fprintln(stderr, serverName+":", err)
		return 1
	}
	return 0
}

type server struct {
	scan *scanner
}

const instructions = "What an update left waiting on this host, read only: the tool " + toolName +
	" lists the services and processes that still use files an update replaced or removed (they run the old code until restarted), " +
	"with the packages that own those files now; whether an update waits for a reboot (" + RebootFlag + "); " +
	"and the running and installed kernels. It changes nothing: restarting a service or rebooting is for other tools, or the administrator."

const description = "What an update left waiting: the systemd services and processes that still use files an update replaced or removed " +
	"(as zypper ps -s lists them), with the packages that own those files now; whether an update waits for a reboot (" + RebootFlag +
	", left by zypper and transactional-update); and the running and installed kernels, and whether a newer one is installed. " +
	"Reads only; takes no arguments."

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
			"serverInfo":      map[string]any{"name": serverName, "title": "Pending restarts", "version": version.Version},
			"instructions":    instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": []map[string]any{{
			"name":         toolName,
			"title":        "Pending restarts",
			"description":  description,
			"inputSchema":  map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
			"outputSchema": outputSchema,
			"annotations": map[string]any{"title": "Pending restarts", "readOnlyHint": true, "destructiveHint": false,
				"idempotentHint": true, "openWorldHint": false},
		}}}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "invalid params"}
		}
		if p.Name != toolName {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "unknown tool " + strconv.Quote(p.Name)}
		}
		if len(p.Arguments) > 0 {
			return toolError("%s takes no arguments", toolName), nil
		}
		r := s.scan.scan(ctx)
		return map[string]any{
			"content":           []map[string]any{{"type": "text", "text": summary(r)}},
			"structuredContent": r,
		}, nil
	}
	return nil, &mcpserver.Error{Code: mcpserver.CodeMethodNotFound, Message: "method not found"}
}

var stringList = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}

// outputSchema describes structuredContent: a Report.
var outputSchema = map[string]any{"type": "object", "properties": map[string]any{
	"reboot_needed":          map[string]any{"type": "boolean", "description": "an update waits for a reboot (" + RebootFlag + " exists)"},
	"reboot_needed_since":    map[string]any{"type": "string", "description": "when the flag was set (RFC 3339)"},
	"running_kernel":         map[string]any{"type": "string"},
	"installed_kernels":      stringList,
	"newer_kernel_installed": map[string]any{"type": "boolean"},
	"services": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
		"unit": map[string]any{"type": "string"}, "pids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
		"packages": stringList}}},
	"processes": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
		"pid": map[string]any{"type": "integer"}, "command": map[string]any{"type": "string"}, "user": map[string]any{"type": "string"},
		"unit": map[string]any{"type": "string"}, "files": stringList, "packages": stringList}}},
	"unreadable": map[string]any{"type": "integer", "description": "processes whose memory maps could not be read"},
}, "required": []string{"reboot_needed", "running_kernel", "installed_kernels", "newer_kernel_installed", "services", "processes"}}

// maxListed bounds the processes the text names.
const maxListed = 50

// summary is the report as text.
func summary(r Report) string {
	var b strings.Builder
	if r.RebootNeeded {
		fmt.Fprintf(&b, "A reboot is pending: %s exists (since %s).\n", RebootFlag, r.RebootNeededSince)
	} else {
		fmt.Fprintf(&b, "No update waits for a reboot (%s does not exist).\n", RebootFlag)
	}
	fmt.Fprintf(&b, "Running kernel: %s; installed: %s", orNone(r.RunningKernel), orNone(strings.Join(r.InstalledKernels, ", ")))
	if r.NewerKernel {
		b.WriteString(" (a newer kernel is installed: a reboot would start it)")
	}
	b.WriteString(".\n")
	if len(r.Processes) == 0 {
		b.WriteString("No process uses files an update replaced or removed.\n")
	} else {
		if len(r.Services) > 0 {
			b.WriteString("Services to restart:")
			for _, s := range r.Services {
				fmt.Fprintf(&b, " %s (%s);", s.Unit, orNone(strings.Join(s.Packages, ", ")))
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Processes that use files an update replaced or removed (%d):\n", len(r.Processes))
		for i, p := range r.Processes {
			if i == maxListed {
				fmt.Fprintf(&b, "  and %d more (structuredContent has all)\n", len(r.Processes)-i)
				break
			}
			fmt.Fprintf(&b, "  %d %s (user %s", p.PID, p.Command, orNone(p.User))
			if p.Unit != "" {
				fmt.Fprintf(&b, ", %s", p.Unit)
			}
			fmt.Fprintf(&b, "): %s\n", orNone(strings.Join(p.Packages, ", ")))
		}
	}
	if r.Unreadable > 0 {
		fmt.Fprintf(&b, "%d processes could not be read (ended, or not allowed): the list may be incomplete.\n", r.Unreadable)
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func toolError(format string, a ...any) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf(format, a...)}}, "isError": true}
}

// kernelRelease is the running kernel's release (uname -r).
func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}
