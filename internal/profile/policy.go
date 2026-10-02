package profile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Domain names the SELinux types of a server's domain.
type Domain struct {
	Server string // server name, e.g. "my-srv"
	Type   string // domain type, e.g. "mcpsrv_my_srv_t"
	// New: the domain does not exist yet and is created from the
	// gateway's template (the server ran in mcpsrv_generic_t).
	New bool
	// Exec is the server's program, labelled with the domain's
	// entrypoint type when the domain is new.
	Exec string
}

// NewDomain returns the domain for server: its own type if it has one,
// else a new one named after it.
func NewDomain(server, selinuxType, genericType, exec string) Domain {
	if selinuxType != "" && selinuxType != genericType {
		return Domain{Server: server, Type: selinuxType, Exec: exec}
	}
	return Domain{Server: server, Type: "mcpsrv_" + Ident(server) + "_t", New: true, Exec: exec}
}

// Ident turns a server name into an SELinux identifier part.
func Ident(server string) string { return strings.ReplaceAll(server, "-", "_") }

// ExecType is the entrypoint type of a new domain.
func (d Domain) ExecType() string { return strings.TrimSuffix(d.Type, "_t") + "_exec_t" }

// ModuleName is the name of the drafted module: mcp_<server> for a new
// domain, mcp_<server>_local for additions to an existing one.
func (d Domain) ModuleName() string {
	if d.New {
		return "mcp_" + Ident(d.Server)
	}
	return "mcp_" + Ident(d.Server) + "_local"
}

// ProfilingModule is the temporary module loaded while profiling: it
// makes the domain permissive (creating it first if it is new, with its
// program's label). Returns the module name, .te and .fc.
func (d Domain) ProfilingModule() (name, te, fc string) {
	name = "mcpprof_" + Ident(d.Server)
	var b strings.Builder
	fmt.Fprintf(&b, "policy_module(%s, 1.0)\n\n# Temporary, while mcp-gateway profile runs: %s is permissive.\n", name, d.Type)
	if d.New {
		fmt.Fprintf(&b, "mcp_gateway_backend_template(%s)\n", Ident(d.Server))
	} else {
		fmt.Fprintf(&b, "gen_require(`\n\ttype %s;\n')\n", d.Type)
	}
	fmt.Fprintf(&b, "permissive %s;\n", d.Type)
	return name, b.String(), d.FileContexts()
}

// FileContexts labels the program of a new domain.
func (d Domain) FileContexts() string {
	if !d.New || d.Exec == "" {
		return ""
	}
	return fmt.Sprintf("%s\t--\tgen_context(system_u:object_r:%s,s0)\n", fcPath(d.Exec), d.ExecType())
}

// fcPath escapes the regular expression characters of a path for a file
// context specification.
func fcPath(p string) string {
	return regexp.MustCompile(`[.+*?()\[\]{}|^$\\]`).ReplaceAllString(p, `\$0`)
}

// Interpreter reports whether a program looks like an interpreter, whose
// label would put every script it runs into the domain.
func Interpreter(path string) bool {
	return regexp.MustCompile(`/(python[0-9.]*|node|nodejs|perl|ruby|bash|sh|java|uv|uvx|npx|deno|bun)$`).MatchString(path)
}

// Draft is a drafted policy module and what the denials suggest beyond
// allow rules.
type Draft struct {
	Module string // module name
	TE     string
	FC     string
	Hints  []string
}

type ruleKey struct{ src, tgt, class string }

// DraftModule drafts a module from the denials involving d.Type: plain
// allow rules (both directions: the domain's accesses and other domains'
// accesses to it, such as D-Bus replies), with the paths and programs
// seen as comments. Rules are a starting point: interfaces of the
// reference policy usually say the same more portably and more narrowly.
func DraftModule(d Domain, denials []Denial, errs []Record) Draft {
	perms := map[ruleKey]map[string]bool{}
	seen := map[ruleKey][]string{}
	types := map[string]bool{}
	classes := map[string]map[string]bool{}
	hints := map[string]bool{}
	for _, x := range denials {
		if templateDontaudit(d, x) {
			continue
		}
		k := ruleKey{x.Source, x.Target, x.Class}
		if perms[k] == nil {
			perms[k] = map[string]bool{}
		}
		if classes[x.Class] == nil {
			classes[x.Class] = map[string]bool{}
		}
		for _, p := range x.Perms {
			perms[k][p] = true
			classes[x.Class][p] = true
		}
		if ex := example(x); ex != "" && !contains(seen[k], ex) && len(seen[k]) < 3 {
			seen[k] = append(seen[k], ex)
		}
		for _, t := range []string{x.Source, x.Target} {
			if t != d.Type {
				types[t] = true
			}
		}
		for _, h := range hintsFor(d, x) {
			hints[h] = true
		}
	}
	keys := make([]ruleKey, 0, len(perms))
	for k := range perms {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.src != b.src {
			return a.src == d.Type // the domain's own accesses first
		}
		if a.tgt != b.tgt {
			return a.tgt < b.tgt
		}
		return a.class < b.class
	})

	var b strings.Builder
	mod := d.ModuleName()
	fmt.Fprintf(&b, "policy_module(%s, 1.0.0)\n\n", mod)
	fmt.Fprintf(&b, "# Draft by mcp-gateway profile for the MCP server %s. Review every\n", d.Server)
	b.WriteString("# rule: it allows what one run did, which may be more than the server\n")
	b.WriteString("# needs, and misses what the run did not reach. Prefer interfaces of the\n")
	b.WriteString("# reference policy where one says the same (sesearch, audit2allow -R).\n\n")
	if d.New {
		fmt.Fprintf(&b, "mcp_gateway_backend_template(%s)\n\n", Ident(d.Server))
	}
	if len(keys) == 0 {
		b.WriteString("# The run caused no denials.\n")
	} else {
		b.WriteString("gen_require(`\n")
		if !d.New {
			fmt.Fprintf(&b, "\ttype %s;\n", d.Type)
		}
		for _, t := range sortedSet(types) {
			fmt.Fprintf(&b, "\ttype %s;\n", t)
		}
		for _, c := range sortedKeys(classes) {
			fmt.Fprintf(&b, "\tclass %s %s;\n", c, braced(sortedSet(classes[c])))
		}
		b.WriteString("')\n")
		for _, k := range keys {
			b.WriteString("\n")
			for _, ex := range seen[k] {
				fmt.Fprintf(&b, "# %s\n", ex)
			}
			tgt := k.tgt
			if k.tgt == k.src {
				tgt = "self"
			}
			fmt.Fprintf(&b, "allow %s %s:%s %s;\n", k.src, tgt, k.class, braced(sortedSet(perms[k])))
		}
	}
	for _, e := range errs {
		hints["SELINUX_ERR (no allow rule fixes it): "+trimRecord(e.Text)] = true
	}
	return Draft{Module: mod, TE: b.String(), FC: d.FileContexts(), Hints: sortedSet(hints)}
}

// templateDontaudit reports a denial the backend template keeps silent on
// purpose (the Go runtime's probe of the huge page size in sysfs): with
// dontaudit rules off while profiling it is logged, but the server does
// without the access.
func templateDontaudit(d Domain, x Denial) bool {
	return x.Source == d.Type && x.Target == "sysfs_t" && (x.Class == "file" || x.Class == "dir")
}

// hintsFor says what a denial means for the server's definition and for
// the module beyond its allow rule.
func hintsFor(d Domain, x Denial) []string {
	has := func(p string) bool { return contains(x.Perms, p) }
	if x.Class == "dbus" && has("send_msg") {
		peer := x.Target
		if peer == d.Type {
			peer = x.Source // a reply or signal from the service
		}
		return []string{fmt.Sprintf("D-Bus: it talks to %s; if that service checks polkit, the account needs a polkit rule", peer)}
	}
	if x.Source != d.Type {
		return nil
	}
	var h []string
	switch {
	case (x.Class == "tcp_socket" || x.Class == "udp_socket") && (has("name_connect") || has("name_bind")):
		h = append(h, fmt.Sprintf("network: it connects to or binds %s ports (%s): the definition needs network: true", x.Target, x.Class))
	case x.Class == "capability" || x.Class == "capability2" || x.Class == "cap_userns":
		h = append(h, fmt.Sprintf("capabilities: it used %s; check that run_as is right (a server that needs root runs as root, sandboxed)", strings.Join(x.Perms, ", ")))
	case x.Class == "file" && (has("execute") || has("execute_no_trans")):
		h = append(h, fmt.Sprintf("programs: it runs files of type %s (%s); a helper that should run in its own domain (zypper and rpm: rpm_t) needs a transition, e.g. mcp_gateway_backend_rpm", x.Target, exampleOr(x, "?")))
	case x.Class == "process" && (has("transition") || has("dyntransition")):
		h = append(h, fmt.Sprintf("transition: it starts programs in %s; an allow rule alone does not make that work (it needs the entrypoint and, under no_new_privs, nnp_transition)", x.Target))
	}
	return h
}

func example(x Denial) string {
	var parts []string
	if x.Path != "" {
		parts = append(parts, x.Path)
	}
	if x.Comm != "" {
		parts = append(parts, "("+x.Comm+")")
	}
	return strings.Join(parts, " ")
}

func exampleOr(x Denial, def string) string {
	if e := example(x); e != "" {
		return e
	}
	return def
}

func trimRecord(s string) string {
	if i := strings.Index(s, "op="); i >= 0 {
		s = s[i:]
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func braced(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "{ " + strings.Join(items, " ") + " }"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
