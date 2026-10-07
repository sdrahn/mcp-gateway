package inspect

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Tool notes (tool_notes in a server definition) tell agents what a
// tool's schema does not. NoteHints finds the arguments that likely need
// one, from the schemas alone: no tool is called. A Go time.Time, for
// example, has the schema {"type": "string"} and accepts RFC 3339 only,
// which agents cannot know.

// NoteHint is a tool whose arguments may need a note.
type NoteHint struct {
	Tool string `json:"tool"`
	// Times are string arguments that look like times or dates and whose
	// schema does not say the format.
	Times []string `json:"times,omitempty"`
	// RFC3339 marks times whose schema has format date-time (RFC 3339)
	// but does not say so in words.
	RFC3339 bool `json:"rfc3339,omitempty"`
	// Undescribed are string arguments with no description, enum,
	// pattern or format: agents only have their names.
	Undescribed []string `json:"undescribed,omitempty"`
	// Noted: the definition has a note for the tool already.
	Noted bool `json:"noted,omitempty"`
	// Draft is a note to start from, for Times ("" without).
	Draft string `json:"draft,omitempty"`
}

var (
	// timeName are argument names that are times by themselves: since,
	// start_time, createdAt; not update or candidate.
	timeName = regexp.MustCompile(`(?i:^(since|until|time|timestamp|datetime|date)$|[_-](time|date|at|timestamp)$)|[a-z](Time|Date|At|Timestamp)$`)
	// timeWord in a description: the argument is (or bounds) a time.
	timeWord = regexp.MustCompile(`(?i)\b(time|date|timestamp|datetime)\b`)
	// formatStated in a description: it says how to write the value.
	formatStated = regexp.MustCompile(`(?i)rfc ?3339|iso ?8601|yyyy|hh:mm|unix|epoch|seconds|milliseconds|minutes|duration|format|e\.g\.|for example|relative|ago`)
)

type propSchema struct {
	Type        json.RawMessage `json:"type"`
	Format      string          `json:"format"`
	Description string          `json:"description"`
	Pattern     string          `json:"pattern"`
	Enum        []any           `json:"enum"`
}

// isString: the property's type is string, or a union with string.
func (p propSchema) isString() bool {
	var one string
	if json.Unmarshal(p.Type, &one) == nil {
		return one == "string"
	}
	var many []string
	return json.Unmarshal(p.Type, &many) == nil && slices.Contains(many, "string")
}

// NoteHints returns the tools whose arguments may need a note, in the
// order of tools; notes are the definition's tool_notes (nil for none).
func NoteHints(tools []Tool, notes map[string]string) []NoteHint {
	var out []NoteHint
	for _, t := range tools {
		var schema struct {
			Properties map[string]propSchema `json:"properties"`
		}
		_ = json.Unmarshal(t.InputSchema, &schema)
		h := NoteHint{Tool: t.Name, RFC3339: true}
		for _, name := range sortedKeys(schema.Properties) {
			p := schema.Properties[name]
			if !p.isString() {
				continue
			}
			switch {
			case p.Format == "date-time" || p.Format == "date" || p.Format == "time":
				if !formatStated.MatchString(p.Description) {
					h.Times = append(h.Times, name)
					h.RFC3339 = h.RFC3339 && p.Format == "date-time"
				}
			case len(p.Enum) > 0 || p.Pattern != "" || p.Format != "":
			case timeName.MatchString(name) || timeWord.MatchString(p.Description):
				if !formatStated.MatchString(p.Description) {
					h.Times = append(h.Times, name)
					h.RFC3339 = false
				}
			case strings.TrimSpace(p.Description) == "":
				h.Undescribed = append(h.Undescribed, name)
			}
		}
		if len(h.Times) == 0 && len(h.Undescribed) == 0 {
			continue
		}
		h.Noted = notes[t.Name] != ""
		if len(h.Times) > 0 {
			args := strings.Join(h.Times, ", ")
			if h.RFC3339 {
				h.Draft = args + ": RFC 3339 times with a time zone, e.g. 2026-10-07T11:00:00+02:00"
			} else {
				h.Draft = args + ": <the format the server takes, e.g. RFC 3339 2026-10-07T11:00:00+02:00; " +
					"whether relative times such as -1h work>"
			}
		} else {
			h.RFC3339 = false
		}
		out = append(out, h)
	}
	return out
}

// UnknownNotes are the tools that notes name and the server does not
// offer, sorted.
func UnknownNotes(tools []Tool, notes map[string]string) []string {
	var out []string
	for name := range notes {
		if !slices.ContainsFunc(tools, func(t Tool) bool { return t.Name == name }) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// draftNotes is the commented tool_notes block of a draft definition, or
// "" when no tool needs one.
func draftNotes(hints []NoteHint) string {
	var b strings.Builder
	for _, h := range hints {
		if h.Draft != "" {
			fmt.Fprintf(&b, "#   %s: %q\n", h.Tool, h.Draft)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "# What the tools' schemas do not tell the agent, added to their\n" +
		"# descriptions (tool_notes). Find out what the server takes, then:\n" +
		"# tool_notes:\n" + b.String()
}

// NotesReport writes the hints and the notes naming tools the server
// does not offer, if there are any.
func NotesReport(out io.Writer, hints []NoteHint, unknown []string) error {
	w := &strings.Builder{}
	var drafts []string
	if len(hints) > 0 {
		fmt.Fprintln(w, "\nTool notes to consider (tool_notes in the definition: what the schema does not tell agents):")
		for _, h := range hints {
			var parts []string
			if len(h.Times) > 0 {
				parts = append(parts, "times without a format: "+strings.Join(h.Times, ", "))
			}
			if len(h.Undescribed) > 0 {
				parts = append(parts, "no description: "+strings.Join(h.Undescribed, ", "))
			}
			line := "  " + h.Tool + ": " + strings.Join(parts, "; ")
			if h.Noted {
				line += " (has a note)"
			} else if h.Draft != "" {
				drafts = append(drafts, fmt.Sprintf("    %s: %q", h.Tool, h.Draft))
			}
			fmt.Fprintln(w, line)
		}
		if len(drafts) > 0 {
			fmt.Fprintln(w, "  Find out what the server takes (its documentation or source), then, for example:")
			fmt.Fprintln(w, "  tool_notes:")
			fmt.Fprintln(w, strings.Join(drafts, "\n"))
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(w, "\nTool notes for tools the server does not offer: %s\n", strings.Join(unknown, ", "))
	}
	_, err := io.WriteString(out, w.String())
	return err
}
