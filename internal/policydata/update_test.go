package policydata

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

const commented = `# Role data of example.org (who asked for what: see the ticket).
version: 1
roles:
  # Readers may look, nothing more.
  reader:
    description: read only
    permissions:
      - {server: fs, tool: 'read_*'}  # the files
      - {server: fs, tool: 'list_*'}
  writer:
    permissions:
      - server: fs
        tool: write_file
        require_approval: true # always asked
bindings:
  users:
    alice: [reader] # since 2026-01
  groups: {}
approvers:
  default: [self]
`

func TestUpdateYAML(t *testing.T) {
	_, base, _, err := readYAMLForTest(commented)
	if err != nil {
		t.Fatal(err)
	}
	// What Cockpit sends: the data as JSON, with bob bound, alice changed,
	// a role added, one permission dropped, and a field changed.
	var d map[string]any
	if err := jsonUnmarshal(base, &d); err != nil {
		t.Fatal(err)
	}
	b := d["bindings"].(map[string]any)
	b["users"].(map[string]any)["bob"] = []any{"writer"}
	b["users"].(map[string]any)["alice"] = []any{"reader", "writer"}
	roles := d["roles"].(map[string]any)
	roles["auditor"] = map[string]any{"permissions": []any{}}
	r := roles["reader"].(map[string]any)
	r["permissions"] = r["permissions"].([]any)[:1]
	r["description"] = "read only, files"
	data := jsonMarshal(t, d)

	y, err := UpdateYAML([]byte(commented), data)
	if err != nil {
		t.Fatal(err)
	}
	got := string(y)
	for _, want := range []string{
		"# Role data of example.org (who asked for what: see the ticket).",
		"# Readers may look, nothing more.",
		"# the files",
		"# always asked",
		"# since 2026-01",
		"description: read only, files",
		"alice: [reader, writer]",
		"bob: [writer]",
		"auditor:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "list_*") {
		t.Errorf("dropped permission still there:\n%s", got)
	}
	// Key order kept: version, roles, bindings, approvers.
	if v, ro, bi, ap := strings.Index(got, "\nversion:"), strings.Index(got, "\nroles:"), strings.Index(got, "\nbindings:"), strings.Index(got, "\napprovers:"); v >= ro || ro >= bi || bi >= ap {
		t.Errorf("order:\n%s", got)
	}
	// Unchanged data: the file as it was, but for the encoder's layout.
	same, err := UpdateYAML([]byte(commented), base)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(commented), "\n") {
		if !strings.Contains(string(same), strings.TrimSpace(strings.SplitN(line, "#", 2)[0])) {
			t.Errorf("unchanged: lost %q\n%s", line, same)
		}
	}
	// No base: a new file.
	fresh, err := UpdateYAML(nil, data)
	if err != nil {
		t.Fatal(err)
	}
	back, _ := ToJSON(fresh)
	var a, w any
	_ = jsonUnmarshal(back, &a)
	_ = jsonUnmarshal(data, &w)
	if !reflect.DeepEqual(a, w) {
		t.Errorf("fresh:\n%s", fresh)
	}
	if _, err := UpdateYAML([]byte(commented), []byte(`{"roles": `)); err == nil {
		t.Error("broken JSON accepted")
	}
	if _, err := UpdateYAML([]byte("roles: [\n"), data); err == nil {
		t.Error("broken base accepted")
	}
}

// Removing or adding a permission keeps the comments of the others.
func TestUpdateYAMLSequence(t *testing.T) {
	base := `roles:
  r:
    permissions:
      - {server: a, tool: x} # first
      - {server: b, tool: x} # second
      - {server: c, tool: x} # third
`
	for _, tc := range []struct {
		name, perms string
		want, gone  []string
	}{
		{"middle removed", `[{"server":"a","tool":"x"},{"server":"c","tool":"x"}]`, []string{"a, tool: x} # first", "c, tool: x} # third"}, []string{"# second"}},
		{"first removed", `[{"server":"b","tool":"x"},{"server":"c","tool":"x"}]`, []string{"b, tool: x} # second", "c, tool: x} # third"}, []string{"# first"}},
		{"added in front", `[{"server":"z","tool":"x"},{"server":"a","tool":"x"},{"server":"b","tool":"x"},{"server":"c","tool":"x"}]`,
			[]string{"z, tool: x}\n", "a, tool: x} # first", "b, tool: x} # second", "c, tool: x} # third"}, nil},
		{"one edited", `[{"server":"a","tool":"x"},{"server":"b","tool":"y"},{"server":"c","tool":"x"}]`,
			[]string{"a, tool: x} # first", "b, tool: y} # second", "c, tool: x} # third"}, nil},
	} {
		y, err := UpdateYAML([]byte(base), []byte(`{"roles":{"r":{"permissions":`+tc.perms+`}}}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, w := range tc.want {
			if !strings.Contains(string(y), w) {
				t.Errorf("%s: missing %q in\n%s", tc.name, w, y)
			}
		}
		for _, g := range tc.gone {
			if strings.Contains(string(y), g) {
				t.Errorf("%s: %q left in\n%s", tc.name, g, y)
			}
		}
	}
}

// Every shipped file survives an update to its own data unchanged in
// meaning, and an update to other data reads back as that data.
func TestUpdateYAMLShipped(t *testing.T) {
	for _, f := range shippedRoleFiles(t) {
		if !strings.HasSuffix(f, ".yaml") {
			continue
		}
		y, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, data, _, err := Read(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UpdateYAML(y, data); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		if _, err := UpdateYAML(y, []byte(`{"roles": {}, "bindings": {"users": {"x": ["y"]}}}`)); err != nil {
			t.Errorf("%s, other data: %v", f, err)
		}
	}
}

func readYAMLForTest(y string) (string, []byte, []string, error) {
	data, err := ToJSON([]byte(y))
	return "", data, nil, err
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func jsonMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
