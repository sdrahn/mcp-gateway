package principal

import (
	"strings"
	"testing"
)

func TestClientClean(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"claude-code", "claude-code"},
		{"évé 日本", "évé 日本"},
		{"evil\x1b[2J\x1b]52;c;aGk=\x07name", "evil[2J]52;c;aGk=name"},
		{"c1\u009b31mred", "c131mred"},
		{"report\u202efdp.sh", "reportfdp.sh"},
		{"zero\u200bwidth\u2066iso\u2069", "zerowidthiso"},
		{"bad\xffutf8", "badutf8"},
		{"tab\tnew\nline", "tabnewline"},
	} {
		got := Client{Name: tc.in, Version: tc.in}.Clean()
		if got.Name != tc.want || got.Version != tc.want {
			t.Errorf("%q: %+v, want %q", tc.in, got, tc.want)
		}
	}
	if got := (Client{Name: strings.Repeat("é", 500)}).Clean().Name; got != strings.Repeat("é", maxClientField) {
		t.Errorf("long name: %d characters", len([]rune(got)))
	}
}
