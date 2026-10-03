package profile

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Outcome is what a call did.
type Outcome struct {
	Call
	// Result is the tool's answer; Err is set instead when the session
	// failed during the call.
	IsError bool   `json:"is_error"`
	Text    string `json:"text"`
	Err     string `json:"err,omitempty"`
}

// polkitHint matches tool errors that come from a refused authorization.
var polkitHint = regexp.MustCompile(`(?i)polkit|not authori[sz]ed|interactive authentication|access denied|AccessDenied`)

// CallHints says what the tool answers suggest: refused authorizations
// (polkit), missing permissions as the account the server runs as.
func CallHints(outcomes []Outcome) []string {
	var h []string
	for _, o := range outcomes {
		if !o.IsError {
			continue
		}
		switch {
		case polkitHint.MatchString(o.Text):
			h = append(h, fmt.Sprintf("authorization: %s was refused (%s); the account may need a polkit rule", o.Tool, oneLine(o.Text, 120)))
		case regexp.MustCompile(`(?i)permission denied|operation not permitted|EACCES|EPERM`).MatchString(o.Text):
			h = append(h, fmt.Sprintf("permissions: %s failed (%s); with SELinux permissive this is file modes, the account (run_as) or the sandbox", o.Tool, oneLine(o.Text, 120)))
		}
	}
	return h
}

// Report is the account of a profiling (or verification) run.
type Report struct {
	Server   string
	Program  string // server name and version as it reports them
	Domain   Domain
	Verify   bool
	Calls    []Outcome
	Unknown  []string // tools of the calls file the server does not have
	Denials  []Denial
	Errs     []Record
	Hints    []string
	Files    []string
	ExecPath string
	// DontauditOff: dontaudit rules were off during the run.
	DontauditOff bool
	// SessionFailed: the server could not be started or exercised.
	SessionFailed bool
}

// Write writes the report as text.
func (r *Report) Write(out io.Writer) error {
	w := &strings.Builder{}
	mode := "permissive (profiling)"
	if r.Verify {
		mode = "enforcing (verification)"
	}
	kind := "existing domain"
	if r.Domain.New {
		kind = "new domain"
	}
	fmt.Fprintf(w, "Server %s (%s): %s, %s, %s\n", r.Server, orDash(r.Program), r.Domain.Type, kind, mode)

	fmt.Fprintf(w, "\nCalls (%d):\n", len(r.Calls))
	for _, o := range r.Calls {
		args, _ := json.Marshal(o.Args)
		status := "ok"
		text := o.Text
		switch {
		case o.Err != "":
			status, text = "failed", o.Err
		case o.IsError:
			status = "error"
		}
		src := "sample"
		if o.Given {
			src = "given"
		}
		fmt.Fprintf(w, "  %-6s %s %s (%s args): %s\n", status, o.Tool, args, src, oneLine(text, 100))
	}
	if len(r.Calls) == 0 {
		w.WriteString("  none (no reading tools; give calls with --calls, or --call-all on a throwaway system)\n")
	}
	if len(r.Unknown) > 0 {
		fmt.Fprintf(w, "  not called, the server has no such tool: %s\n", strings.Join(r.Unknown, ", "))
	}

	sum := Summary(r.Denials)
	fmt.Fprintf(w, "\nSELinux denials involving %s (%d distinct):\n", r.Domain.Type, len(sum))
	for _, s := range sum {
		fmt.Fprintf(w, "  %s\n", s)
	}
	if len(sum) == 0 {
		w.WriteString("  none\n")
	}
	for _, e := range r.Errs {
		fmt.Fprintf(w, "  SELINUX_ERR %s\n", trimRecord(e.Text))
	}

	if len(r.Hints) > 0 {
		w.WriteString("\nHints:\n")
		for _, h := range r.Hints {
			fmt.Fprintf(w, "  - %s\n", h)
		}
	}
	if r.Verify && r.SessionFailed && len(sum) == 0 {
		w.WriteString("\nThe server failed without a recorded denial. dontaudit rules may hide the\n")
		w.WriteString("cause: semodule -DB, run --verify again, semodule -B.\n")
	}
	if !r.Verify {
		if r.DontauditOff {
			w.WriteString("\ndontaudit rules were off during the run, so the denials include accesses\n")
			w.WriteString("the policy keeps silent; some are harmless probes the server does without.\n")
		}
		w.WriteString("\nWhat the run did not reach is not in the drafts: tools that were not\n")
		w.WriteString("called, branches the sample arguments did not take. Give real arguments\n")
		w.WriteString("with --calls to cover more.\n")
	}
	if len(r.Files) > 0 {
		fmt.Fprintf(w, "\nDrafts: %s\n", strings.Join(r.Files, ", "))
		mod := r.Domain.ModuleName()
		w.WriteString("\nNext steps (as root, in the drafts directory):\n")
		fmt.Fprintf(w, "  1. review %s.te (and %s.fc), then: make -f %s %s.pp && semodule -i %s.pp\n",
			mod, mod, DevelMakefile, mod, mod)
		if r.Domain.New && r.ExecPath != "" {
			fmt.Fprintf(w, "  2. restorecon -F %s\n", r.ExecPath)
		} else {
			w.WriteString("  2. -\n")
		}
		fmt.Fprintf(w, "  3. compare %s.yaml with the definition and install it in /etc/mcp-gateway/servers.d;\n", r.Server)
		w.WriteString("     mcp-gateway --check && systemctl restart mcp-gateway.service\n")
		fmt.Fprintf(w, "  4. mcp-gateway-admin profile --server %s --verify\n", r.Server)
	}
	_, err := io.WriteString(out, w.String())
	return err
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
