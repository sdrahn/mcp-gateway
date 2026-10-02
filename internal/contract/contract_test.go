package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type inner struct {
	B string `json:"b"`
}

type Embedded struct {
	E string `json:"e"`
}

type sample struct {
	Embedded
	A       inner             `json:"a"`
	List    []inner           `json:"list,omitempty"`
	Map     map[string]*inner `json:"map"`
	Lists   map[string][]string
	Strings []string        `json:"strings"`
	Raw     json.RawMessage `json:"raw"`
	Time    time.Time       `json:"time"`
	Skip    string          `json:"-"`
	hidden  string          //nolint:unused // unexported: no JSON field
	Self    *sample         `json:"self"`
}

func TestFields(t *testing.T) {
	got := Fields(sample{})
	want := []string{"Lists", "Lists{}", "a", "a.b", "e", "list", "list[].b", "map", "map{}.b", "raw", "self", "strings", "time"}
	if !slices.Equal(got, want) {
		t.Errorf("Fields = %q, want %q", got, want)
	}
}

func TestCheck(t *testing.T) {
	file := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(file, []byte("# header\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPDATE_CONTRACT", "1")
	Check(t, file, inner{})
	data, _ := os.ReadFile(file)
	if string(data) != "# header\nb\n" {
		t.Errorf("rewritten: %q", data)
	}
	t.Setenv("UPDATE_CONTRACT", "")
	ft := &fakeT{TB: t}
	Check(ft, file, struct {
		C string `json:"c"`
	}{})
	if len(ft.errors) != 2 { // b is gone, c is new
		t.Errorf("errors %q", ft.errors)
	}
}

type fakeT struct {
	testing.TB
	errors []string
}

func (f *fakeT) Helper() {}
func (f *fakeT) Errorf(format string, args ...any) {
	f.errors = append(f.errors, format)
}
