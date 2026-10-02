package inspect

import (
	"fmt"
	"io"
	"strings"
)

// Report writes a readable account of what the server offers, how its
// tools were classified and the findings of a role check.
func Report(out io.Writer, server string, res *Result, verdicts []Verdict, findings []Finding) error {
	w := &strings.Builder{}
	fmt.Fprintf(w, "Server %s: %s", server, orDash(res.Server.Name))
	if res.Server.Version != "" {
		fmt.Fprintf(w, " %s", res.Server.Version)
	}
	fmt.Fprintf(w, " (MCP %s)\n", orDash(res.ProtocolVersion))
	caps := sortedKeys(res.Capabilities)
	fmt.Fprintf(w, "Capabilities: %s\n", orDash(strings.Join(caps, ", ")))

	fmt.Fprintf(w, "\nTools (%d):\n", len(res.Tools))
	var candidates []string
	for i, t := range res.Tools {
		v := verdicts[i]
		mark := " "
		if v.Reader {
			mark = "R"
		}
		fmt.Fprintf(w, "  %s %-28s %-7s %s\n", mark, t.Name, v.Class, strings.Join(v.Evidence, "; "))
		if len(v.PathArgs) > 0 {
			fmt.Fprintf(w, "    path arguments: %s (consider an \"args\" constraint)\n", strings.Join(v.PathArgs, ", "))
		}
		if v.Class == ClassRead && !v.Reader {
			candidates = append(candidates, t.Name)
		}
	}
	fmt.Fprintln(w, "  R: in the draft reader role (allowed without approval)")
	if len(candidates) > 0 {
		fmt.Fprintf(w, "\nRead by their name only, so they need approval in the draft: %s.\n", strings.Join(candidates, ", "))
		fmt.Fprintln(w, "Check what they do; move them to the reader role, or use --read-by-name.")
	}
	if len(res.Prompts) > 0 {
		fmt.Fprintf(w, "\nPrompts (%d): %s\n", len(res.Prompts), names(res.Prompts, false))
	}
	if len(res.ResourceTemplates) > 0 {
		fmt.Fprintf(w, "\nResource templates (%d): %s\n", len(res.ResourceTemplates), names(res.ResourceTemplates, true))
	}
	if findings != nil {
		fmt.Fprintln(w, "\nRole check:")
		if len(findings) == 0 {
			fmt.Fprintln(w, "  no problems")
		}
		for _, f := range findings {
			fmt.Fprintf(w, "  %s: %s\n", f.Level, f.Message)
		}
	}
	_, err := io.WriteString(out, w.String())
	return err
}

func names(items []Item, uri bool) string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if uri && it.URITemplate != "" {
			out = append(out, it.URITemplate)
		} else {
			out = append(out, it.Name)
		}
	}
	return strings.Join(out, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Errors counts the findings of level "error".
func Errors(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.Level == "error" {
			n++
		}
	}
	return n
}
