package inspect

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// listLogSchema is the schema google/jsonschema-go 0.4.2 makes of
// systemd-mcp 0.3.5's ListLogParams: its time.Time fields are plain
// strings.
const listLogSchema = `{"type":"object","properties":{
	"count":{"type":"integer","description":"Number of log lines to output","default":100},
	"from":{"type":"string","description":"Start time for filtering logs"},
	"to":{"type":"string","description":"End time for filtering logs "},
	"pattern":{"type":"string","description":"Regular expression pattern to filter log messages or units."},
	"unit":{"type":"array","items":{"type":"string"},"description":"Names of the service/unit"},
	"allboots":{"type":"boolean","description":"Get the log entries from all boots"}},"additionalProperties":false}`

func tool(name, schema string) Tool { return Tool{Name: name, InputSchema: json.RawMessage(schema)} }

func TestNoteHints(t *testing.T) {
	tools := []Tool{
		tool("list_log", listLogSchema),
		tool("snapshot", `{"type":"object","properties":{
			"created":{"type":"string","format":"date-time","description":"When to take it"},
			"name":{"type":"string"}}}`),
		tool("quiet", `{"type":"object","properties":{
			"update":{"type":"string","description":"The package to update"},
			"candidate":{"type":"string","description":"A candidate version"},
			"timeout":{"type":"string","description":"Time to wait, in seconds"},
			"since":{"type":"string","description":"RFC 3339, e.g. 2026-10-07T11:00:00Z"},
			"mode":{"type":"string","enum":["a","b"]},
			"id":{"type":"string","pattern":"^[0-9]+$"},
			"count":{"type":"integer"}}}`),
		tool("camel", `{"type":"object","properties":{"createdAt":{"type":["string","null"],"description":"x"},"start_time":{"type":"string","description":"y"}}}`),
		tool("bare", ``),
	}
	got := NoteHints(tools, map[string]string{"camel": "noted"})
	want := []NoteHint{
		{Tool: "list_log", Times: []string{"from", "to"},
			Draft: "from, to: <the format the server takes, e.g. RFC 3339 2026-10-07T11:00:00+02:00; whether relative times such as -1h work>"},
		{Tool: "snapshot", Times: []string{"created"}, RFC3339: true, Undescribed: []string{"name"},
			Draft: "created: RFC 3339 times with a time zone, e.g. 2026-10-07T11:00:00+02:00"},
		{Tool: "camel", Times: []string{"createdAt", "start_time"}, Noted: true,
			Draft: "createdAt, start_time: <the format the server takes, e.g. RFC 3339 2026-10-07T11:00:00+02:00; whether relative times such as -1h work>"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hints\n got %+v\nwant %+v", got, want)
	}
	if got := UnknownNotes(tools, map[string]string{"list_log": "x", "list_logs": "y", "a": "z"}); !reflect.DeepEqual(got, []string{"a", "list_logs"}) {
		t.Errorf("unknown notes %v", got)
	}
	if got := UnknownNotes(tools, nil); got != nil {
		t.Errorf("unknown notes without notes %v", got)
	}
}

// The draft definition carries the drafts as comments; uncommented they
// are valid tool_notes.
func TestDefinitionNotes(t *testing.T) {
	res := &Result{Server: ServerInfo{Name: "fake"}}
	hints := NoteHints([]Tool{tool("list_log", listLogSchema)}, nil)
	y := Definition("srv", []string{"/usr/bin/srv"}, res, hints)
	if !strings.Contains(y, "# tool_notes:\n#   list_log: \"from, to: <the format") {
		t.Fatalf("no draft notes:\n%s", y)
	}
	for _, text := range []string{y, strings.NewReplacer("# tool_notes:", "tool_notes:", "#   list_log:", "  list_log:").Replace(y)} {
		var b config.Backend
		dec := yaml.NewDecoder(strings.NewReader(text))
		dec.KnownFields(true)
		if err := dec.Decode(&b); err != nil {
			t.Fatalf("%v\n%s", err, text)
		}
		b.ApplyDefaults()
		if err := b.Validate(); err != nil {
			t.Errorf("%v\n%s", err, text)
		}
		if text != y && !strings.HasPrefix(b.ToolNotes["list_log"], "from, to: ") {
			t.Errorf("notes %v", b.ToolNotes)
		}
	}
	if y := Definition("srv", []string{"/usr/bin/srv"}, res, nil); strings.Contains(y, "tool_notes") {
		t.Errorf("notes without hints:\n%s", y)
	}
}

func TestNotesReport(t *testing.T) {
	hints := NoteHints([]Tool{tool("list_log", listLogSchema), tool("get", `{"properties":{"name":{"type":"string"}}}`)}, nil)
	var w bytes.Buffer
	if err := NotesReport(&w, hints, []string{"gone"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  list_log: times without a format: from, to\n",
		"  get: no description: name\n",
		"  tool_notes:\n    list_log: \"from, to: <the format",
		"Tool notes for tools the server does not offer: gone",
	} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("missing %q in\n%s", want, w.String())
		}
	}
	w.Reset()
	if err := NotesReport(&w, nil, nil); err != nil || w.Len() != 0 {
		t.Errorf("without hints: %q %v", w.String(), err)
	}
}
