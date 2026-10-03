package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/mcpserver"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const adminUsage = `usage: mcp-gateway-admin serve [flags]

The MCP server gateway-admin, which the gateway starts (servers.d/
gateway-admin.yaml): the checks of mcp-gateway-admin doctor, the configuration
with secrets masked, what the policy decides for a user and why, the
gateway's audit records and SELinux denials, for an agent debugging the
gateway's setup. It speaks MCP on stdin/stdout and changes nothing.

It runs as root in the sandbox (no capabilities) and its own SELinux
domain, and like every server cannot reach the gateway's sockets or OPA:
it evaluates the policy files itself and does not start servers.

`

// adminServer is the MCP server gateway-admin.
type adminServer struct {
	configPath string
	policyData string // the role data
	shipped    string // the shipped policy: Rego and the setups' roles
	etcPolicy  string // the administrator's policy directory (data.mcp)
	opa        string // the opa program, for explain_decision
	// journal runs journalctl with args (a variable for tests).
	journal func(ctx context.Context, args ...string) ([]byte, error)
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway-admin serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, adminUsage)
		fs.PrintDefaults()
	}
	a := &adminServer{journal: journalctl}
	fs.StringVar(&a.configPath, "config", "", "gateway configuration")
	fs.StringVar(&a.policyData, "policy-data", policydata.DefaultPath, "role data")
	fs.StringVar(&a.shipped, "shipped-policy", policydata.DefaultShippedDir, "shipped policy (Rego, roles of the server setups)")
	fs.StringVar(&a.etcPolicy, "etc-policy", filepath.Dir(filepath.Dir(policydata.DefaultPath)), "the administrator's policy directory, loaded below data.mcp")
	fs.StringVar(&a.opa, "opa", "/usr/bin/opa", "the opa program, to evaluate the policy")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	// Answers are bounded by what the tools return; requests are small.
	if err := mcpserver.New(a.handle, stdout).Serve(os.Stdin, 1<<20); err != nil {
		say(stderr, err)
		return 1
	}
	return 0
}

const adminInstructions = `Diagnostics of the MCP gateway on this machine, for finding out why a server, tool or permission does not work. Nothing here changes the system.

- doctor: the checks of "mcp-gateway-admin doctor" (configuration, role data, services, state files, SELinux types, labels and denials, polkit, snapper, users without a role). Start here.
- check_config: only whether the configuration and the role data are valid.
- explain_decision: what the policy decides for a user calling a tool (or reading a resource, getting a prompt), with the roles the user holds and the permissions that match.
- show_config: the configuration files (gateway.yaml, server definitions, role data), secrets masked.
- recent_audit: the gateway's recent decisions and events.
- selinux_denials: SELinux denials for the gateway and its servers.

How things should be configured is in the gateway's documentation (the server gateway-docs, if installed). Changes are the administrator's: suggest them, with the file and the command to apply them.`

func (a *adminServer) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{
			"protocolVersion": mcpserver.Negotiate(p.ProtocolVersion),
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "gateway-admin", "title": "MCP gateway diagnostics", "version": version.Version},
			"instructions":    adminInstructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": adminTools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "invalid params"}
		}
		return a.call(ctx, p.Name, p.Arguments)
	}
	return nil, &mcpserver.Error{Code: mcpserver.CodeMethodNotFound, Message: "method not found"}
}

func adminTool(name, title, description string, props map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	if props == nil {
		schema["properties"] = map[string]any{}
	}
	return map[string]any{
		"name": name, "title": title, "description": description, "inputSchema": schema,
		"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": false},
	}
}

var adminTools = []map[string]any{
	adminTool("doctor", "Check the gateway",
		"Runs the checks of mcp-gateway-admin doctor and returns each with its status (ok, warn, fail, skip) and what to do. "+
			"Servers are not started and OPA is not asked (run mcp-gateway-admin doctor as root for those).",
		map[string]any{
			"server": map[string]any{"type": "string", "description": "check only this server"},
			"since":  map[string]any{"type": "string", "description": "how far back to look for SELinux denials within the current boot, e.g. 24h (default) or 30m"},
		}),
	adminTool("check_config", "Check the configuration",
		"Whether gateway.yaml, the server definitions and the role data are valid, with deprecation warnings.", nil),
	adminTool("explain_decision", "Explain a policy decision",
		"What the policy decides when a user calls a tool, reads a resource or gets a prompt of a server, "+
			"with the roles the user holds and the permissions that match. Approvals already given are not taken into account.",
		map[string]any{
			"user":      map[string]any{"type": "string", "description": "the local user name"},
			"server":    map[string]any{"type": "string", "description": "the server name"},
			"name":      map[string]any{"type": "string", "description": "the tool or prompt name, or the resource URI"},
			"kind":      map[string]any{"type": "string", "enum": []string{"tool", "resource", "prompt"}, "description": "default tool"},
			"arguments": map[string]any{"type": "object", "description": "the call's arguments, for permissions that constrain them"},
		}, "user", "server", "name"),
	adminTool("show_config", "Read the configuration",
		"Without file: the configuration files (gateway.yaml, server definitions, role data, roles of the server setups). "+
			"With file: its content, values of keys that look like secrets masked.",
		map[string]any{"file": map[string]any{"type": "string", "description": "a path as the list without file shows it"}}),
	adminTool("recent_audit", "Recent decisions",
		"The gateway's audit records from its journal, newest last: decisions (who, server, tool, allow/deny/ask, reason) and events (approvals, grants, policy changes).",
		map[string]any{
			"since":  map[string]any{"type": "string", "description": "how far back, e.g. 1h (default) or 15m"},
			"user":   map[string]any{"type": "string", "description": "only this principal"},
			"server": map[string]any{"type": "string", "description": "only this server"},
			"effect": map[string]any{"type": "string", "enum": []string{"allow", "deny", "ask"}, "description": "only decisions with this effect"},
			"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "description": "at most this many records (default 100)"},
		}),
	adminTool("selinux_denials", "SELinux denials",
		"SELinux denials for the gateway, OPA and the servers (from the audit log), with what usually fixes them.",
		map[string]any{"since": map[string]any{"type": "string", "description": "how far back within the current boot, e.g. 24h (default)"}}),
}

// toolError is a tool result reporting a failure to the model.
func toolError(format string, args ...any) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf(format, args...)}}, "isError": true}
}

func textResult(text string, structured any) map[string]any {
	r := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	if structured != nil {
		r["structuredContent"] = structured
	}
	return r
}

func (a *adminServer) call(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage("{}")
	}
	switch name {
	case "doctor":
		var p struct {
			Server string `json:"server"`
			Since  string `json:"since"`
		}
		if err := strictArgs(raw, &p); err != nil {
			return toolError("%v", err), nil
		}
		since, err := duration(p.Since, 24*time.Hour)
		if err != nil {
			return toolError("since: %v", err), nil
		}
		return a.results(a.doctorRun(p.Server, since).run(a.configPath)), nil
	case "check_config":
		if err := strictArgs(raw, &struct{}{}); err != nil {
			return toolError("%v", err), nil
		}
		d := a.doctorRun("", 0)
		rs := []doctor.Result{d.configuration(a.configPath)}
		if d.gw != nil {
			rs = append(rs, d.roleData())
		}
		return a.results(rs), nil
	case "explain_decision":
		var p explainArgs
		if err := strictArgs(raw, &p); err != nil {
			return toolError("%v", err), nil
		}
		return a.explain(ctx, p), nil
	case "show_config":
		var p struct {
			File string `json:"file"`
		}
		if err := strictArgs(raw, &p); err != nil {
			return toolError("%v", err), nil
		}
		return a.readConfig(p.File), nil
	case "recent_audit":
		var p auditArgs
		if err := strictArgs(raw, &p); err != nil {
			return toolError("%v", err), nil
		}
		return a.recentAudit(ctx, p), nil
	case "selinux_denials":
		var p struct {
			Since string `json:"since"`
		}
		if err := strictArgs(raw, &p); err != nil {
			return toolError("%v", err), nil
		}
		since, err := duration(p.Since, 24*time.Hour)
		if err != nil {
			return toolError("since: %v", err), nil
		}
		d := a.doctorRun("", since)
		return a.results(d.selinux()), nil
	}
	return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "unknown tool " + strconv.Quote(name)}
}

// strictArgs decodes a tool's arguments, refusing unknown ones (a
// misspelt filter would otherwise silently match everything).
func strictArgs(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments: %v", err)
	}
	return nil
}

func duration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err == nil && d <= 0 {
		err = errors.New("must be positive")
	}
	return d, err
}

// doctorRun is the doctor as the server runs it: without starting servers
// and without the gateway's sockets and OPA, which no server may reach.
func (a *adminServer) doctorRun(only string, since time.Duration) *doctorRun {
	return &doctorRun{
		root:       os.Geteuid() == 0,
		isolated:   true,
		policyData: a.policyData,
		shipped:    a.shipped,
		only:       only,
		noStart:    true,
		since:      since,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (a *adminServer) results(rs []doctor.Result) map[string]any {
	var b strings.Builder
	_ = doctor.WriteText(&b, rs, false)
	return textResult(b.String(), map[string]any{"results": rs, "failed": doctor.Failed(rs)})
}

type explainArgs struct {
	User      string         `json:"user"`
	Server    string         `json:"server"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Arguments map[string]any `json:"arguments"`
}

// explain evaluates the policy files with opa, as OPA does with them
// (mcp-opa.service): the shipped policy as is, the administrator's below
// data.mcp.
func (a *adminServer) explain(ctx context.Context, p explainArgs) map[string]any {
	if p.User == "" || p.Server == "" || p.Name == "" {
		return toolError("user, server and name are required")
	}
	actions := map[string]string{"": "tools.call", "tool": "tools.call", "resource": "resources.read", "prompt": "prompts.get"}
	action, ok := actions[p.Kind]
	if !ok {
		return toolError("kind: %q is not tool, resource or prompt", p.Kind)
	}
	kind := p.Kind
	if kind == "" {
		kind = "tool"
	}
	pr, err := localPrincipal(p.User)
	if err != nil {
		return toolError("%v", err)
	}
	res := pep.Resource{Server: p.Server, Kind: kind, Name: p.Name}
	var notes []string
	if gw, _, err := config.Resolve(a.configPath); err == nil {
		if backends, err := config.LoadBackends(gw.VendorServersDir, gw.ServersDir); err == nil {
			if b := backends[p.Server]; b == nil {
				notes = append(notes, "no server "+strconv.Quote(p.Server)+" is registered: the gateway would refuse before asking the policy")
			} else {
				res.Privileged = b.Privileged
			}
		}
	}
	in := pep.Input{
		Principal: pr,
		Action:    action,
		Resource:  res,
		Args:      p.Arguments,
		Context:   pep.Context{Time: time.Now().UTC().Format(time.RFC3339), Transport: principal.TransportUnix},
	}
	out, err := a.evaluate(ctx, in)
	if err != nil {
		return toolError("evaluating the policy: %v", err)
	}
	notes = append(notes, "evaluated from the policy files ("+a.shipped+", "+a.etcPolicy+
		"); with signed policy bundles the active policy is the bundle's", "approvals already given (grants) are not taken into account")
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s/%s: %s", p.User, action, p.Server, p.Name, out.Decision.Effect)
	if out.Decision.Reason != "" {
		fmt.Fprintf(&b, " (%s)", out.Decision.Reason)
	}
	b.WriteString("\nroles: ")
	if len(out.Roles) == 0 {
		b.WriteString("none (no binding names the user or one of their groups)")
	} else {
		b.WriteString(strings.Join(out.Roles, ", "))
	}
	b.WriteString("\nmatching permissions:")
	if len(out.Matching) == 0 {
		b.WriteString(" none")
	}
	for _, m := range out.Matching {
		var c bytes.Buffer
		if json.Compact(&c, m) != nil {
			c.Write(m)
		}
		b.WriteString("\n  " + c.String())
	}
	for _, n := range notes {
		b.WriteString("\nnote: " + n)
	}
	return textResult(b.String(), map[string]any{"input": in, "decision": out.Decision, "roles": out.Roles,
		"matching": out.Matching, "notes": notes})
}

type explanation struct {
	Decision pep.Decision      `json:"decision"`
	Roles    []string          `json:"roles"`
	Matching []json.RawMessage `json:"matching"`
}

const explainQuery = `{"decision": data.mcp.authz.decision, "roles": data.mcp.authz.roles, "matching": data.mcp.authz.matching}`

func (a *adminServer) evaluate(ctx context.Context, in pep.Input) (*explanation, error) {
	// The OPA client adds the input's version to every query.
	input, err := json.Marshal(struct {
		Version int `json:"version"`
		pep.Input
	}{pep.InputVersion, in})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.opa, "eval", "--format", "json", "--stdin-input",
		"--data", a.shipped, "--data", "mcp:"+a.etcPolicy, explainQuery)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	var res struct {
		Result []struct {
			Expressions []struct {
				Value explanation `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if jerr := json.Unmarshal(raw, &res); jerr != nil {
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil, jerr
	}
	if len(res.Errors) > 0 {
		var msgs []string
		for _, e := range res.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, errors.New(strings.Join(msgs, "; "))
	}
	if len(res.Result) == 0 || len(res.Result[0].Expressions) == 0 {
		return nil, errors.New("the policy gave no result (is the gateway's policy installed?)")
	}
	e := res.Result[0].Expressions[0].Value
	sort.Strings(e.Roles)
	return &e, nil
}

// localPrincipal is the principal the gateway makes of a local user's
// connection.
func localPrincipal(name string) (principal.Principal, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("no local user %q", name)
	}
	uid64, _ := strconv.ParseUint(u.Uid, 10, 32)
	uid := uint32(uid64)
	p := principal.Principal{Sub: u.Username, UID: &uid, Home: u.HomeDir, Groups: userGroups(u.Username),
		Transport: principal.TransportUnix, SessionID: "explain"}
	return p, nil
}

// configFiles are the files show_config shows: the gateway's
// configuration, the server definitions, the role data and the setups'
// roles.
func (a *adminServer) configFiles() []string {
	var files []string
	gw, used, err := config.Resolve(a.configPath)
	if used != "" {
		files = append(files, used)
	}
	if err == nil {
		for _, dir := range []string{gw.VendorServersDir, gw.ServersDir} {
			paths, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
			files = append(files, paths...)
		}
	}
	files = append(files, a.policyData)
	shipped, _ := filepath.Glob(filepath.Join(a.shipped, "mcp", "profiles", "*", "data.json"))
	files = append(files, shipped...)
	var out []string
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// secretKey matches YAML and JSON keys whose values are secrets.
var secretKey = regexp.MustCompile(`(?i)^(\s*(?:-\s*)?"?[a-z0-9_.-]*(?:secret|token|passw|private|api_?key)[a-z0-9_.-]*"?\s*:\s*)(\S.*)$`)

// maskSecrets replaces the values of keys that look like secrets.
func maskSecrets(content string) (string, int) {
	var b strings.Builder
	n := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := secretKey.FindStringSubmatch(line); m != nil {
			line = m[1] + "<masked>"
			n++
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), n
}

const maxConfigFile = 1 << 20

func (a *adminServer) readConfig(file string) map[string]any {
	files := a.configFiles()
	if file == "" {
		var b strings.Builder
		for _, f := range files {
			b.WriteString(f + "\n")
		}
		return textResult(b.String(), map[string]any{"files": files})
	}
	if !slices.Contains(files, filepath.Clean(file)) {
		return toolError("%s is not one of the configuration files (call show_config without file for the list)", file)
	}
	f, err := os.Open(file)
	if err != nil {
		return toolError("%v", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFile+1))
	if err != nil {
		return toolError("%v", err)
	}
	if len(data) > maxConfigFile {
		return toolError("%s: larger than %d bytes", file, maxConfigFile)
	}
	masked, n := maskSecrets(string(data))
	text := masked
	if n > 0 {
		text = fmt.Sprintf("# %d values masked\n%s", n, masked)
	}
	return textResult(text, nil)
}

type auditArgs struct {
	Since  string `json:"since"`
	User   string `json:"user"`
	Server string `json:"server"`
	Effect string `json:"effect"`
	Limit  int    `json:"limit"`
}

func journalctl(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("journalctl: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// recentAudit reads the gateway's audit records (JSON lines with
// "audit": true on its stderr) from the journal.
func (a *adminServer) recentAudit(ctx context.Context, p auditArgs) map[string]any {
	since, err := duration(p.Since, time.Hour)
	if err != nil {
		return toolError("since: %v", err)
	}
	switch {
	case p.Limit == 0:
		p.Limit = 100
	case p.Limit < 0 || p.Limit > 1000:
		return toolError("limit: between 1 and 1000")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	from := time.Now().Add(-since).UTC().Format("2006-01-02 15:04:05") + " UTC"
	out, err := a.journal(ctx, "--unit", "mcp-gateway.service", "--since", from, "--output", "cat", "--no-pager", "--quiet")
	if err != nil {
		return toolError("%v", err)
	}
	var records []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r map[string]any
		if json.Unmarshal(sc.Bytes(), &r) != nil || r["audit"] != true {
			continue
		}
		if !matches(r, "sub", p.User) || !matches(r, "server", p.Server) || !matches(r, "effect", p.Effect) {
			continue
		}
		delete(r, "audit")
		delete(r, "level")
		delete(r, "msg")
		records = append(records, r)
	}
	if len(records) > p.Limit {
		records = records[len(records)-p.Limit:]
	}
	var b strings.Builder
	if len(records) == 0 {
		fmt.Fprintf(&b, "no audit records since %s", from)
	}
	for _, r := range records {
		b.WriteString(auditLine(r) + "\n")
	}
	return textResult(b.String(), map[string]any{"records": records})
}

func matches(r map[string]any, key, want string) bool {
	if want == "" {
		return true
	}
	s, _ := r[key].(string)
	return s == want
}

// auditLine renders a record as "time key=value ...", the time first and
// the rest in a fixed order.
func auditLine(r map[string]any) string {
	parts := []string{fmt.Sprint(r["time"])}
	order := []string{"event", "sub", "action", "server", "name", "effect", "reason", "grant", "privileged"}
	for _, k := range order {
		if v, ok := r[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(r)) {
		if k != "time" && !slices.Contains(order, k) {
			parts = append(parts, fmt.Sprintf("%s=%v", k, r[k]))
		}
	}
	return strings.Join(parts, " ")
}
