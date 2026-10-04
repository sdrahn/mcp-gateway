// Package doctor holds the checks of "mcp-gateway-admin doctor", which finds
// what had to be debugged by hand when setting up MCP servers: servers
// that do not start, role data that does not validate or names tools a
// server does not have, SELinux denials for the gateway and its servers,
// servers running as an account no polkit rule names, and users who may
// connect but hold no role. The checks here take their input as data;
// cmd/mcp-gateway gathers it from the system.
//
// See docs/architecture.md, section 11, step 13.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/profile"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// Status is the outcome of a check.
type Status string

const (
	OK Status = "ok"
	// Warn is for something an administrator can change, and the details
	// say what; the gateway works otherwise. What a check cannot tell is
	// wrong is OK, with a note.
	Warn Status = "warn"
	Fail Status = "fail" // something does not work
	Skip Status = "skip" // could not be checked (e.g. needs root)
)

// Result is the outcome of one check. Check is the line's label; ID and
// Subject (what it is about: a server, an account, a path), which
// Identify sets from it, stay the same across releases for monitoring.
type Result struct {
	Check   string   `json:"check"`
	ID      string   `json:"id"`
	Subject string   `json:"subject,omitempty"`
	Status  Status   `json:"status"`
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
}

// checkIDs are the IDs of the checks with a fixed label.
var checkIDs = map[string]string{
	"configuration":       "configuration",
	"role data":           "role-data",
	"policy":              "policy",
	"state files":         "state-files",
	"gateway status":      "gateway-status",
	"servers":             "servers",
	"principals":          "principals",
	"program labels":      "program-labels",
	"read-only /usr":      "read-only-usr",
	"SELinux":             "selinux-denials",
	"SELinux types":       "selinux-types",
	"SELinux transitions": "selinux-transitions",
}

// checkPrefixes are the IDs of the checks labeled "<prefix><subject>",
// longest prefix first.
var checkPrefixes = []struct{ prefix, id string }{
	{"SELinux type ", "selinux-type"},
	{"approver group ", "approver-group"},
	{"SELinux ", "selinux-denials"},
	{"polkit ", "polkit"},
	{"program ", "program"},
	{"roles ", "roles"},
	{"server ", "server"},
	{"snapper ", "snapper"},
}

// Identify sets each result's ID and Subject from its Check label (see
// Result); a systemd unit's state has the ID "unit".
func Identify(rs []Result) {
	for i := range rs {
		r := &rs[i]
		if id, ok := checkIDs[r.Check]; ok {
			r.ID = id
			continue
		}
		if strings.HasSuffix(r.Check, ".service") {
			r.ID, r.Subject = "unit", r.Check
			continue
		}
		r.ID = r.Check
		for _, p := range checkPrefixes {
			if s, ok := strings.CutPrefix(r.Check, p.prefix); ok {
				r.ID, r.Subject = p.id, s
				break
			}
		}
	}
}

// Warned reports whether any result warns.
func Warned(rs []Result) bool {
	for _, r := range rs {
		if r.Status == Warn {
			return true
		}
	}
	return false
}

// Failed reports whether any result failed.
func Failed(rs []Result) bool {
	for _, r := range rs {
		if r.Status == Fail {
			return true
		}
	}
	return false
}

// WriteText writes the results, one line each with the status in capitals,
// and their details indented below; with color, the statuses are colored
// for a terminal.
func WriteText(w io.Writer, rs []Result, color bool) error {
	var b strings.Builder
	for _, r := range rs {
		word := strings.ToUpper(string(r.Status))
		pad := strings.Repeat(" ", max(0, 4-len(word)))
		if c := statusColors[r.Status]; color && c != "" {
			word = c + word + "\x1b[0m"
		}
		fmt.Fprintf(&b, "%s%s  %s: %s\n", word, pad, r.Check, r.Summary)
		for _, d := range r.Details {
			fmt.Fprintf(&b, "        %s\n", d)
		}
	}
	n := map[Status]int{}
	for _, r := range rs {
		n[r.Status]++
	}
	fmt.Fprintf(&b, "\n%d ok, %d warnings, %d failed, %d skipped\n", n[OK], n[Warn], n[Fail], n[Skip])
	_, err := io.WriteString(w, b.String())
	return err
}

// statusColors are the terminal colors of the statuses in WriteText:
// green (OK, SKIP), orange (WARN, 256-color 208) and red (FAIL).
var statusColors = map[Status]string{
	OK:   "\x1b[32m",
	Skip: "\x1b[32m",
	Warn: "\x1b[38;5;208m",
	Fail: "\x1b[31m",
}

// WriteJSON writes the results as a JSON list.
func WriteJSON(w io.Writer, rs []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rs)
}

// maxDetails bounds the lines listed under one result.
const maxDetails = 15

func capped(lines []string) []string {
	if len(lines) <= maxDetails {
		return lines
	}
	return append(lines[:maxDetails:maxDetails], fmt.Sprintf("… and %d more", len(lines)-maxDetails))
}

// gatewayType reports SELinux types of the gateway, OPA and MCP servers.
func gatewayType(t string) bool {
	return strings.HasPrefix(t, "mcpgw_") || strings.HasPrefix(t, "mcpopa_") ||
		strings.HasPrefix(t, "mcpsrv_") || t == "mcp_port_t" || t == "mcp_metrics_port_t"
}

// Denials checks the SELinux denials (and SELINUX_ERR records) that
// involve the gateway's types: one result per domain, failing when one
// was enforced. Denials in a permissive domain (a profiling run) only
// warn.
func Denials(denials []profile.Denial, errs []profile.Record, since string) []Result {
	byDomain := map[string][]profile.Denial{}
	for _, d := range denials {
		switch {
		case gatewayType(d.Source):
			byDomain[d.Source] = append(byDomain[d.Source], d)
		case gatewayType(d.Target):
			byDomain[d.Target] = append(byDomain[d.Target], d)
		}
	}
	var out []Result
	for _, dom := range sortedKeys(byDomain) {
		ds := byDomain[dom]
		status := Warn
		for _, d := range ds {
			if !d.Permissive {
				status = Fail
			}
		}
		sum := profile.Summary(ds)
		r := Result{Check: "SELinux " + dom, Status: status,
			Summary: fmt.Sprintf("%d denials (%d distinct) since %s", len(ds), len(sum), since), Details: capped(sum)}
		if status == Warn {
			r.Summary += ", all in permissive mode (a profiling run?)"
		}
		out = append(out, r)
	}
	var selErrs []string
	for _, e := range errs {
		for _, f := range strings.Fields(e.Text) {
			if strings.Contains(f, "context=") && gatewayType(contextTypeOf(f)) {
				selErrs = append(selErrs, e.Text)
				break
			}
		}
	}
	if len(selErrs) > 0 {
		out = append(out, Result{Check: "SELinux transitions", Status: Fail,
			Summary: fmt.Sprintf("%d SELINUX_ERR records (refused transitions; no allow rule fixes these)", len(selErrs)),
			Details: capped(selErrs)})
	}
	if len(out) == 0 {
		out = append(out, Result{Check: "SELinux", Status: OK, Summary: "no denials involving the gateway, OPA or MCP servers since " + since})
	}
	return out
}

// contextTypeOf returns the type of a field like scontext=u:r:t:s0.
func contextTypeOf(field string) string {
	_, ctx, _ := strings.Cut(field, "=")
	parts := strings.SplitN(strings.Trim(ctx, `"'`), ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// polkitRuleDirs are where polkit reads JavaScript rules.
var polkitRuleDirs = []string{"/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"}

// polkitTypes are the SELinux domains of servers that act through polkit
// (the system bus): the setups' systemd and firewalld servers. Other
// shipped domains cannot reach the bus; a domain of another module may.
var polkitTypes = map[string]bool{"mcpsrv_systemd_t": true, "mcpsrv_firewalld_t": true}

// Polkit checks the servers that run as a system account (not each
// principal, not root, not a dynamic user, which gets a new name for each
// instance): servers like systemd-mcp and firewalld-mcp act through
// polkit, which refuses an account without a session unless a rule
// allows it. For each account no rule file under dirs (polkit's, if nil)
// names, it warns if one of its servers runs in a domain that acts
// through polkit (polkitTypes), and otherwise reports OK with a note: it
// cannot tell whether such a server uses polkit at all. It never fails.
func Polkit(backends map[string]*config.Backend, dirs []string) []Result {
	if dirs == nil {
		dirs = polkitRuleDirs
	}
	var rules []string // file contents
	for _, d := range dirs {
		files, _ := filepath.Glob(filepath.Join(d, "*.rules"))
		for _, f := range files {
			if data, err := os.ReadFile(f); err == nil {
				rules = append(rules, string(data))
			}
		}
	}
	accounts := map[string][]string{} // account to servers
	users := map[string]bool{}        // accounts with a server that acts through polkit
	for _, name := range sortedKeys(backends) {
		b := backends[name]
		if b.RunAs == "principal" || b.RunAs == "root" || b.RunAs == "dynamic" || isSnapper(b) {
			continue
		}
		accounts[b.RunAs] = append(accounts[b.RunAs], name)
		users[b.RunAs] = users[b.RunAs] || polkitTypes[b.SELinuxType]
	}
	var out []Result
	for _, acct := range sortedKeys(accounts) {
		named := false
		for _, r := range rules {
			if strings.Contains(r, `"`+acct+`"`) || strings.Contains(r, `'`+acct+`'`) {
				named = true
				break
			}
		}
		servers := strings.Join(accounts[acct], ", ")
		switch {
		case named:
			out = append(out, Result{Check: "polkit " + acct, Status: OK,
				Summary: fmt.Sprintf("a polkit rule names %s (servers %s)", acct, servers)})
		case users[acct]:
			out = append(out, Result{Check: "polkit " + acct, Status: Warn,
				Summary: fmt.Sprintf("servers %s act through polkit as %s, which no polkit rule names: polkit refuses them", servers, acct),
				Details: []string{"there is no session to ask in; install the server's setup package, which brings the rule,",
					"or add a rule for the account (user guide, chapter 13)"}})
		default:
			out = append(out, Result{Check: "polkit " + acct, Status: OK,
				Summary: fmt.Sprintf("no polkit rule names %s (servers %s): needed only if they act through polkit", acct, servers),
				Details: []string{"if one does (systemd, firewalld, ...), add a rule for the account (user guide, chapter 13)"}})
		}
	}
	return out
}

// ProgramLabels checks that each server's program, and the other
// TypedPrograms that are installed, carry the SELinux type the loaded
// policy gives their path (current: the file's type,
// expected: the policy's, as matchpathcon tells; readOnly: whether the
// path is on a read-only file system). A program installed or copied
// before the module that labels it keeps, e.g., bin_t; systemd then
// cannot start it in the server's domain (entrypoint denied), and the
// server shows no tools. On a transactional system /usr is read-only and
// the fix needs a new snapshot.
func ProgramLabels(backends map[string]*config.Backend, current, expected func(path string) (string, error), readOnly func(path string) bool) []Result {
	var out []Result
	checked := 0
	for _, name := range sortedKeys(backends) {
		b := backends[name]
		if len(b.Command) == 0 || !filepath.IsAbs(b.Command[0]) {
			continue
		}
		path := b.Command[0]
		r := Result{Check: "program " + name}
		cur, err := current(path)
		if err != nil {
			r.Status, r.Summary = Fail, err.Error()
			out = append(out, r)
			continue
		}
		exp, err := expected(path)
		if err != nil {
			r.Status, r.Summary = Skip, "the policy's label for "+path+": "+err.Error()
			out = append(out, r)
			continue
		}
		if exp == "" || strings.HasPrefix(exp, "<<") { // matchpathcon: <<none>>
			continue
		}
		checked++
		if cur == exp {
			continue
		}
		fix := "restorecon -v " + path
		if readOnly(path) {
			fix = "transactional-update run restorecon -v " + path + ", then reboot (read-only file system)"
		}
		r.Status = Fail
		r.Summary = fmt.Sprintf("%s is labeled %s, the policy says %s: systemd cannot start it in %s", path, cur, exp, b.SELinuxType)
		r.Details = []string{"relabel it: " + fix}
		out = append(out, r)
	}
	// The other programs the modules give a type (the gateway's own, and
	// helpers a server starts, like zypp's worker), where installed.
	seen := map[string]bool{}
	for _, b := range backends {
		if len(b.Command) > 0 {
			seen[b.Command[0]] = true
		}
	}
	helpers := 0
	for _, path := range TypedPrograms {
		if seen[path] {
			continue
		}
		cur, err := current(path)
		if err != nil {
			continue // not installed
		}
		exp, err := expected(path)
		if err != nil || exp == "" || strings.HasPrefix(exp, "<<") || cur == exp {
			if err == nil && cur == exp {
				helpers++
			}
			continue
		}
		fix := "restorecon -v " + path
		if readOnly(path) {
			fix = "transactional-update run restorecon -v " + path + ", then reboot (read-only file system)"
		}
		out = append(out, Result{Check: "program " + path, Status: Fail,
			Summary: fmt.Sprintf("%s is labeled %s, the policy says %s: it does not run in its domain", path, cur, exp),
			Details: []string{"relabel it: " + fix}})
	}
	if len(out) == 0 && checked+helpers > 0 {
		out = append(out, Result{Check: "program labels", Status: OK,
			Summary: fmt.Sprintf("the %d servers' programs and %d other programs are labeled as the policy says", checked, helpers)})
	}
	return out
}

// TypedPrograms are the programs the SELinux modules of the gateway and
// the setups (selinux/*.fc) give a type of their own; a test keeps the
// list in step with the file contexts.
var TypedPrograms = []string{
	"/usr/bin/mcp-gateway",
	"/usr/bin/mcp-gateway-admin",
	"/usr/bin/firewalld-mcp",
	"/usr/bin/mcp-server-snapper",
	"/usr/bin/mcp-server-zypp",
	"/usr/bin/suseconnect-mcp",
	"/usr/bin/systemd-mcp",
	"/usr/lib/mcp-gateway/opa",
	"/usr/libexec/mcp-gateway/opa",
	"/usr/lib/mcp-servers/mcp-server-exec",
	"/usr/libexec/mcp-servers/mcp-server-exec",
	"/usr/lib/mcp-servers/mcp-server-fs",
	"/usr/libexec/mcp-servers/mcp-server-fs",
	"/usr/libexec/mcp-server-zypp/zypp-mcp-tool",
}

// ReadOnlyRoot reports privileged servers on a system whose /usr is
// read-only (readOnly: a transactional system such as MicroOS or SLE
// Micro): they run without the sandbox to change the system, but cannot
// change /usr; packages are installed with transactional-update into a
// new snapshot instead.
func ReadOnlyRoot(backends map[string]*config.Backend, readOnly bool) []Result {
	if !readOnly {
		return nil
	}
	var priv []string
	for _, name := range sortedKeys(backends) {
		if backends[name].Privileged {
			priv = append(priv, name)
		}
	}
	r := Result{Check: "read-only /usr", Status: OK,
		Summary: "a transactional system: programs and their labels change only in a new snapshot (transactional-update)"}
	if len(priv) > 0 {
		// Nothing to change: how such a system works. A note, not a
		// warning.
		r.Summary = fmt.Sprintf("a transactional system: privileged servers %s cannot change /usr (e.g. install packages)", strings.Join(priv, ", "))
		r.Details = []string{"install with transactional-update pkg install and reboot; see the user guide, chapter 13"}
	}
	return []Result{r}
}

// SnapperConfigsDir holds snapper's configs (KEY="value" lines).
const SnapperConfigsDir = "/etc/snapper/configs"

// isSnapper reports whether b runs mcp-server-snapper, which snapperd
// authorizes by uid (Snapper), not through polkit.
func isSnapper(b *config.Backend) bool {
	return len(b.Command) > 0 && filepath.Base(b.Command[0]) == "mcp-server-snapper"
}

// Snapper checks the servers that run mcp-server-snapper as a system
// account: snapperd answers such an account (not root) only for configs
// whose ALLOW_USERS name it or whose ALLOW_GROUPS name one of its groups
// (groupsOf). dir is SnapperConfigsDir outside tests.
func Snapper(backends map[string]*config.Backend, dir string, groupsOf func(user string) []string) []Result {
	var out []Result
	for _, name := range sortedKeys(backends) {
		b := backends[name]
		if !isSnapper(b) || b.RunAs == "principal" || b.RunAs == "root" {
			continue
		}
		r := Result{Check: "snapper " + name}
		files, err := os.ReadDir(dir)
		if err != nil {
			r.Status, r.Summary = Skip, "reading snapper's configs: "+err.Error()
			out = append(out, r)
			continue
		}
		groups := map[string]bool{}
		for _, g := range groupsOf(b.RunAs) {
			groups[g] = true
		}
		var allowed, all []string
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			vars, err := readShellVars(filepath.Join(dir, f.Name()))
			if err != nil {
				r.Status, r.Summary = Skip, "reading snapper's configs: "+err.Error()
				break
			}
			all = append(all, f.Name())
			ok := false
			for _, u := range strings.Fields(vars["ALLOW_USERS"]) {
				ok = ok || u == b.RunAs
			}
			for _, g := range strings.Fields(vars["ALLOW_GROUPS"]) {
				ok = ok || groups[g]
			}
			if ok {
				allowed = append(allowed, f.Name())
			}
		}
		switch {
		case r.Status == Skip:
		case len(allowed) > 0:
			r.Status, r.Summary = OK, fmt.Sprintf("snapperd allows %s the configs %s", b.RunAs, strings.Join(allowed, ", "))
		case len(all) == 0:
			r.Status, r.Summary = Warn, "no snapper configs: the server has nothing to work on"
			r.Details = []string{"create one (snapper -c root create-config /), or remove the server's definition"}
		default:
			r.Status = Warn
			r.Summary = fmt.Sprintf("snapperd allows %s none of the configs (%s): the server can list them, nothing else", b.RunAs, strings.Join(all, ", "))
			r.Details = []string{fmt.Sprintf("add it to ALLOW_USERS, keeping the users there: snapper -c %s set-config \"ALLOW_USERS=... %s\"", all[0], b.RunAs),
				"(user guide, chapter 13); changing configs and rolling back need the privileged definition"}
		}
		out = append(out, r)
	}
	return out
}

// readShellVars reads KEY="value" lines, as snapper writes its configs.
func readShellVars(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		vars[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return vars, nil
}

// SELinuxTypes checks that the loaded policy knows each server's
// selinux_type (valid: supervisor.ContextValid). A server whose type it
// does not know cannot start, also in permissive mode; the usual cause
// is a server definition installed without its SELinux module.
func SELinuxTypes(backends map[string]*config.Backend, valid func(string) (bool, error)) []Result {
	missing, err := supervisor.MissingSELinuxTypes(backends, valid)
	if err != nil {
		return []Result{{Check: "SELinux types", Status: Skip, Summary: "checking contexts: " + err.Error()}}
	}
	if len(missing) == 0 {
		return []Result{{Check: "SELinux types", Status: OK, Summary: "the loaded policy knows every server's selinux_type"}}
	}
	var out []Result
	for _, t := range sortedKeys(missing) {
		out = append(out, Result{Check: "SELinux type " + t, Status: Fail,
			Summary: fmt.Sprintf("%s is not in the loaded policy: servers %s cannot start", t, strings.Join(missing[t], ", ")),
			Details: []string{"install the SELinux module that defines it (semodule -l lists the loaded ones),",
				"or remove selinux_type from the definition to use mcpsrv_generic_t"}})
	}
	return out
}

// Bindings is the part of the role data that binds principals to roles.
type Bindings struct {
	Users  map[string][]string `json:"users"`
	Groups map[string][]string `json:"groups"`
}

// Unbound returns the users (of members) bound to no role, neither by
// name nor through one of their groups (groupsOf). Such users may
// connect to the gateway but see no server.
func Unbound(members []string, groupsOf func(user string) []string, b Bindings) []string {
	var out []string
	for _, u := range members {
		if len(b.Users[u]) > 0 {
			continue
		}
		bound := false
		for _, g := range groupsOf(u) {
			if len(b.Groups[g]) > 0 {
				bound = true
				break
			}
		}
		if !bound {
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
