package display

import (
	"encoding/json"
	"testing"
)

func TestEscape(t *testing.T) {
	for in, want := range map[string]string{
		"plain évé 日本\ttab\nline": "plain évé 日本\ttab\nline",
		"report\u202Efdp.sh":      `report\u202Efdp.sh`,
		"a\u2066b\u2069c\u200Bd":  `a\u2066b\u2069c\u200Bd`,
		"csi\u009b31m esc\x1b[2J": `csi\u009B31m esc\u001B[2J`,
		"tag\U000E0041":           `tag\U000E0041`,
	} {
		if got := Escape(in); got != want {
			t.Errorf("Escape(%q) = %q, want %q", in, got, want)
		}
	}
}

// The JSON stays JSON with the same strings, and no hidden character is
// left in it.
func TestJSON(t *testing.T) {
	args := map[string]any{"path": "/tmp/report\u202Efdp.sh", "note": "zw\u200Bj c1\u009b tag\U000E0041", "n": 3}
	s, err := JSON(args, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s {
		if Hidden(r) {
			t.Fatalf("hidden %U in %s", r, s)
		}
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(s), &back); err != nil || back["path"] != args["path"] || back["note"] != args["note"] {
		t.Fatalf("%s: %v %v", s, err, back)
	}
	want := `{
  "n": 3,
  "note": "zw\u200Bj c1\u009B tag\uDB40\uDC41",
  "path": "/tmp/report\u202Efdp.sh"
}`
	if s != want {
		t.Errorf("got\n%s\nwant\n%s", s, want)
	}
}
