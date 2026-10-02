// Package contract fixes the JSON fields of the gateway's interfaces in
// files, so that a field is not renamed or dropped unnoticed: the policy
// input and decision documents, the control API's requests and responses
// (docs/architecture.md, decision D10). Tests compare a type's fields
// with its file; a field that is gone is an incompatible change, a new
// one must be added to the file (UPDATE_CONTRACT=1 rewrites the files).
package contract

import (
	"encoding"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Fields returns the JSON field paths of v's type, sorted: "a" for a
// field, "a.b" inside an object, "a[]" for the elements of a list, "a{}"
// for the values of a map. Types that marshal themselves (time.Time,
// json.RawMessage) are leaves.
func Fields(v any) []string {
	var out []string
	walk(reflect.TypeOf(v), "", map[reflect.Type]bool{}, &out)
	sort.Strings(out)
	return slices.Compact(out)
}

var (
	marshaler     = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

func walk(t reflect.Type, path string, seen map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Implements(marshaler) || reflect.PointerTo(t).Implements(marshaler) ||
		t.Implements(textMarshaler) || reflect.PointerTo(t).Implements(textMarshaler) {
		return
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return // []byte: a base64 string
		}
		elem(t.Elem(), path+"[]", seen, out)
	case reflect.Map:
		elem(t.Elem(), path+"{}", seen, out)
	case reflect.Struct:
		if seen[t] {
			return
		}
		seen[t] = true
		defer delete(seen, t)
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if tag == "-" {
				continue
			}
			if f.Anonymous && tag == "" {
				walk(f.Type, path, seen, out) // embedded: its fields are ours
				continue
			}
			if tag == "" {
				tag = f.Name
			}
			p := tag
			if path != "" {
				p = path + "." + tag
			}
			*out = append(*out, p)
			walk(f.Type, p, seen, out)
		}
	}
}

// elem walks the elements of a list or map, if they have fields.
func elem(t reflect.Type, path string, seen map[reflect.Type]bool, out *[]string) {
	n := len(*out)
	walk(t, path, seen, out)
	if len(*out) > n {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if k := t.Kind(); k == reflect.Slice || k == reflect.Array || k == reflect.Map {
		*out = append(*out, path) // a list of lists, without fields
	}
}

// Check compares the fields of v's type with the file (one path per line;
// "#" starts a comment). With UPDATE_CONTRACT=1 in the environment, it
// rewrites the file's field lines instead, keeping its comments.
func Check(t testing.TB, file string, v any) {
	t.Helper()
	got := Fields(v)
	data, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var header []string
	var want []string
	for _, l := range strings.Split(string(data), "\n") {
		switch l = strings.TrimSpace(l); {
		case strings.HasPrefix(l, "#"):
			if len(want) == 0 {
				header = append(header, l)
			}
		case l != "":
			want = append(want, l)
		}
	}
	if os.Getenv("UPDATE_CONTRACT") == "1" {
		body := strings.Join(append(header, got...), "\n") + "\n"
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, f := range want {
		if !slices.Contains(got, f) {
			t.Errorf("%s: field %q is gone: renaming or dropping a field breaks the interface (docs/architecture.md, D10)", file, f)
		}
	}
	for _, f := range got {
		if !slices.Contains(want, f) {
			t.Errorf("%s: new field %q: add it to the file (UPDATE_CONTRACT=1 go test) and document it", file, f)
		}
	}
}
