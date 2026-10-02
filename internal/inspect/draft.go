package inspect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// Class is how a tool appears to act.
type Class string

const (
	ClassRead    Class = "read"
	ClassChange  Class = "change"
	ClassUnknown Class = "unknown"
)

// Verdict is the classification of one tool, with the evidence for it.
type Verdict struct {
	Tool  string `json:"tool"`
	Class Class  `json:"class"`
	// Reader: the tool goes into the draft reader role (allowed without
	// approval). Only tools the server marks read-only qualify, unless
	// names are trusted (Options.ReadByName).
	Reader   bool     `json:"reader"`
	Evidence []string `json:"evidence"`
	// PathArgs are arguments that look like paths: candidates for an
	// args constraint in a permission.
	PathArgs []string `json:"path_args,omitempty"`
}

// Options control drafting.
type Options struct {
	// ReadByName puts tools that read by their name alone (the server
	// gives no annotations) into the reader role.
	ReadByName bool
}

// Verbs the first word of a tool name is checked against. A name is only
// a hint, like the annotations.
var (
	readVerbs = words("get list show search find read describe check is has query view lookup count inspect info status fetch print dump")
	// "plan", "validate", "test" and the like stay unknown.
	changeVerbs = words("set create add delete remove update install uninstall enable disable start stop restart reload " +
		"change write put register deregister unregister activate deactivate apply confirm kill move rename edit patch " +
		"reset run exec execute mount unmount umount upgrade downgrade refresh rollback revert send upload import mask unmask")
)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// firstWord returns the lower-cased first word of a tool name in
// snake_case, kebab-case, dot.case or CamelCase.
func firstWord(name string) string {
	var b strings.Builder
	for i, r := range name {
		if r == '_' || r == '-' || r == '.' || r == ' ' || r == '/' {
			if b.Len() > 0 {
				break
			}
			continue
		}
		if i > 0 && unicode.IsUpper(r) && b.Len() > 0 {
			break
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// Classify classifies each tool from its annotations and its name.
func Classify(tools []Tool, opts Options) []Verdict {
	out := make([]Verdict, 0, len(tools))
	for _, t := range tools {
		out = append(out, classify(t, opts))
	}
	return out
}

func classify(t Tool, opts Options) Verdict {
	v := Verdict{Tool: t.Name, Class: ClassUnknown, PathArgs: pathArgs(t.InputSchema)}
	var ro, destructive *bool
	if a := t.Annotations; a != nil {
		ro, destructive = a.ReadOnlyHint, a.DestructiveHint
	}
	switch {
	case ro != nil && *ro:
		v.Evidence = append(v.Evidence, "annotations: read-only")
	case ro != nil:
		v.Evidence = append(v.Evidence, "annotations: not read-only")
	default:
		v.Evidence = append(v.Evidence, "annotations: no read-only hint")
	}
	if destructive != nil && *destructive {
		v.Evidence = append(v.Evidence, "annotations: destructive")
	}
	verb := firstWord(t.Name)
	nameRead, nameChange := readVerbs[verb], changeVerbs[verb]
	switch {
	case nameRead:
		v.Evidence = append(v.Evidence, fmt.Sprintf("name: %q reads", verb))
	case nameChange:
		v.Evidence = append(v.Evidence, fmt.Sprintf("name: %q changes", verb))
	default:
		v.Evidence = append(v.Evidence, fmt.Sprintf("name: %q says neither", verb))
	}
	annRead := ro != nil && *ro
	annChange := (ro != nil && !*ro) || (destructive != nil && *destructive && !annRead)
	switch {
	case annRead && nameChange:
		v.Evidence = append(v.Evidence, "the annotations and the name disagree")
	case annChange || nameChange:
		v.Class = ClassChange
	case annRead:
		v.Class = ClassRead
		v.Reader = true
	case nameRead:
		v.Class = ClassRead
		v.Reader = opts.ReadByName
	}
	return v
}

// pathArg matches argument names that usually carry a path.
var pathArg = regexp.MustCompile(`(?i)(^|_)(path|paths|file|files|filename|dir|directory|folder)$|^(path|file|dir)`)

// pathArgs returns the input schema's top-level properties that look like
// paths (by name, or by format "uri"), sorted.
func pathArgs(schema json.RawMessage) []string {
	var s struct {
		Properties map[string]struct {
			Format string `json:"format"`
		} `json:"properties"`
	}
	if len(schema) == 0 || json.Unmarshal(schema, &s) != nil {
		return nil
	}
	var out []string
	for name, p := range s.Properties {
		if pathArg.MatchString(name) || p.Format == "uri" || p.Format == "uri-reference" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Roles drafts role data for server: "<server>-reader" with the reader
// tools by exact name, and "<server>-operator" with those plus every
// other tool after an out-of-band approval. The reader role is left out
// when no tool qualifies.
func Roles(server string, verdicts []Verdict) map[string]any {
	var reads []map[string]any
	for _, v := range verdicts {
		if v.Reader {
			reads = append(reads, map[string]any{"server": server, "tool": globEscape(v.Tool)})
		}
	}
	roles := map[string]any{}
	opDesc := fmt.Sprintf("%s, with approval: every tool (draft by mcp-gateway inspect)", server)
	if len(reads) > 0 {
		roles[server+"-reader"] = map[string]any{
			"description": fmt.Sprintf("%s: the tools it marks read-only (draft by mcp-gateway inspect)", server),
			"permissions": reads,
		}
		opDesc = fmt.Sprintf("%s-reader, and with approval: every other tool (draft by mcp-gateway inspect)", server)
	}
	op := append([]map[string]any{}, reads...)
	op = append(op, map[string]any{
		"server":           server,
		"tool":             "*",
		"require_approval": true,
		"approval_channel": "oob",
		"approval_scopes":  []string{"once", "session", "1h"},
	})
	roles[server+"-operator"] = map[string]any{"description": opDesc, "permissions": op}
	return map[string]any{"version": policydata.Version, "roles": roles}
}

// globEscape escapes the characters the policy's globs give a meaning, so
// a permission names exactly one tool.
func globEscape(s string) string { return globMeta.ReplaceAllString(s, `\$0`) }

var globMeta = regexp.MustCompile(`[*?\[\]{}\\]`)

// Definition drafts a server definition (YAML, with comments) for a
// server started by command.
func Definition(server string, command []string, res *Result) string {
	cmd, _ := json.Marshal(command)
	var b strings.Builder
	fmt.Fprintf(&b, "# Draft by mcp-gateway inspect from %s", res.Server.Name)
	if res.Server.Version != "" {
		fmt.Fprintf(&b, " %s", res.Server.Version)
	}
	b.WriteString(`; review before use.
# Install as /etc/mcp-gateway/servers.d/` + server + `.yaml, then
# mcp-gateway --check && systemctl restart mcp-gateway.service.
version: 1
name: ` + server + `
command: ` + string(cmd) + `
# Who the server runs as: each user (principal, the default), a system
# account (e.g. mcp-sysmgmt, for servers that act on the system through
# polkit), or root (sandboxed; privileged: true only for servers that
# change the system as a whole, in /etc/mcp-gateway/servers.d).
# run_as: principal
# Its SELinux domain: the default mcpsrv_generic_t has no system bus and
# no network. A server that needs more gets its own domain from a module
# with mcp_gateway_backend_template(` + strings.ReplaceAll(server, "-", "_") + `) (user guide, chapter 13).
# selinux_type: mcpsrv_` + strings.ReplaceAll(server, "-", "_") + `_t
# network: true      # if it talks to the network
# discovery: instance   # if its lists depend on the user
`)
	return b.String()
}
