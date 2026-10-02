package review

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Item is a finding with what the system and a profiling run say about it.
type Item struct {
	Finding
	Context Context `json:"context"`
	// Profiled: "denied" (the profiling run recorded a denial on the
	// finding's type), "none" (it did not: not reached, or allowed
	// already), or empty without a profiling run or a type to match.
	Profiled string `json:"profiled,omitempty"`
	Note     string `json:"note"`
}

// Profile is what review needs of a profiling run: the domain and the
// types its denials were about.
type Profile struct {
	Domain  string
	Targets map[string]bool // types the domain was denied access to, or that were denied access to it
}

// Review annotates the scan's findings: context on this system (locate,
// usually Locate), the profiling run (if any) and a note on what each
// may need.
func Review(s *Scan, locate func(Finding) Context, prof *Profile) []Item {
	items := make([]Item, 0, len(s.Findings))
	for _, f := range s.Findings {
		it := Item{Finding: f, Context: locate(f)}
		if prof != nil && it.Context.Type != "" {
			it.Profiled = "none"
			if prof.Targets[it.Context.Type] {
				it.Profiled = "denied"
			}
		}
		it.Note = note(it)
		items = append(items, it)
	}
	return items
}

// note says what a finding may need from the definition, the SELinux
// module or polkit.
func note(it Item) string {
	v := it.Value
	switch it.Kind {
	case KindProgram:
		switch {
		case it.Context.Missing:
			return "not installed here: if a tool needs it, the package must be installed"
		case it.Context.Type == "rpm_exec_t":
			return "a package manager: it belongs in rpm_t (mcp_gateway_backend_rpm, and nnp_transition for a sandboxed server)"
		case it.Context.Type != "":
			return fmt.Sprintf("the domain needs to execute %s files (execute, execute_no_trans; corecmd_exec_bin for bin_t), or a transition if the program has a domain of its own", it.Context.Type)
		}
		return "the domain needs to execute it, or a transition if the program has a domain of its own"
	case KindDBus:
		switch {
		case strings.Contains(v, "PolicyKit1"):
			return "it asks polkit itself: it needs to talk to polkit (policykit_dbus_chat), and the account needs a rule for the actions it checks"
		case strings.ContainsRune(lastSegment(v), '-'):
			return "a polkit action: the account the server runs as needs a polkit rule for it, without a login session"
		}
		return "a D-Bus service or interface: the domain needs to talk to that service (dbus chat); if the service checks polkit, the account needs a rule"
	case KindPath:
		switch {
		case strings.HasPrefix(v, "/proc/") || v == "/proc" || strings.HasPrefix(v, "/sys/"):
			return "system information (kernel_read_system_state, dev_read_sysfs); other processes' entries need more"
		case strings.HasPrefix(v, "/etc/"):
			return "configuration: reading it needs the file's type; writing it, much more (and is a change)"
		case strings.HasPrefix(v, "/var/lib/") || strings.HasPrefix(v, "/var/cache/"):
			return "state: the sandbox needs sandbox.state_directory or read_write_paths, and the module write access"
		case strings.HasPrefix(v, "/var/log/"):
			return "logs: reading or writing them needs the log type; a writable path in the sandbox for writing"
		case strings.HasPrefix(v, "/run/"):
			return "runtime files or sockets: connecting to a service's socket needs its type"
		case strings.HasPrefix(v, "/home/") || strings.HasPrefix(v, "/root"):
			return "home directories: sandbox.protect_home, and run_as principal for each user's own"
		case strings.HasPrefix(v, "/tmp"):
			return "temporary files: each instance has a private /tmp"
		}
		return "a path it uses: the domain needs access to its type"
	case KindNetwork:
		return "network access: the definition needs network: true, the module connect rules (corenet_tcp_connect_*_port)"
	case KindRoot:
		return "it decides by its uid: as another account than root some tools may fail or not be offered (mcp-server-zypp hides its installing tools); check run_as"
	case KindEnv:
		return fmt.Sprintf("reads $%s: set it in the definition's env if the default does not fit", v)
	}
	return ""
}

func lastSegment(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

var kindTitle = map[Kind]string{
	KindProgram: "Programs it runs",
	KindDBus:    "D-Bus services, interfaces and polkit actions",
	KindPath:    "Paths",
	KindNetwork: "Network",
	KindRoot:    "Root checks",
	KindEnv:     "Environment variables",
}

// WriteReport writes the review as text.
func WriteReport(out io.Writer, dir string, s *Scan, items []Item, prof *Profile) error {
	w := &strings.Builder{}
	langs := make([]string, 0, len(s.Files))
	for l, n := range s.Files {
		langs = append(langs, fmt.Sprintf("%s %d", l, n))
	}
	sort.Strings(langs)
	fmt.Fprintf(w, "Source review of %s (files: %s)\n", dir, orNone(strings.Join(langs, ", ")))
	if prof != nil {
		fmt.Fprintf(w, "Compared with a profiling run of %s (%d types in its denials).\n", prof.Domain, len(prof.Targets))
	}
	for _, k := range Kinds {
		var list []Item
		for _, it := range items {
			if it.Kind == k {
				list = append(list, it)
			}
		}
		if len(list) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s (%d):\n", kindTitle[k], len(list))
		for _, it := range list {
			fmt.Fprintf(w, "  %s", it.Value)
			var ctx []string
			if it.Context.Missing {
				ctx = append(ctx, "not found here")
			}
			if it.Context.Path != "" && it.Context.Path != it.Value {
				p := it.Context.Path
				if it.Context.Parent {
					p = "missing, under " + p
				}
				ctx = append(ctx, p)
			}
			if it.Context.Type != "" {
				ctx = append(ctx, it.Context.Type)
			}
			switch it.Profiled {
			case "denied":
				ctx = append(ctx, "denied in the profiling run")
			case "none":
				ctx = append(ctx, "no denial in the profiling run (not reached, or allowed already)")
			}
			if len(ctx) > 0 {
				fmt.Fprintf(w, "  [%s]", strings.Join(ctx, "; "))
			}
			w.WriteString("\n")
			for _, l := range it.Locations {
				fmt.Fprintf(w, "      %s:%d  %s\n", l.File, l.Line, l.Text)
			}
			fmt.Fprintf(w, "      → %s\n", it.Note)
		}
	}
	if len(items) == 0 {
		w.WriteString("\nNothing found. The scan knows the usual ways to run programs, use D-Bus,\npaths and the network; a server that does these differently is not covered.\n")
	} else {
		w.WriteString("\nThe scan is textual: it shows what the code mentions, not what each tool\n")
		w.WriteString("does, and misses what is built at run time. Use it to find code paths the\n")
		w.WriteString("profiling run did not reach, then give calls for them (profile --calls).\n")
	}
	_, err := io.WriteString(out, w.String())
	return err
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
