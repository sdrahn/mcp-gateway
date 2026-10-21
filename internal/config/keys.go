package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The keys of gateway.yaml, named as the file has them
// ("limits.tasks_per_principal"): a section is a struct of the
// configuration, a key is any other value of it (a list and a map of
// names too). mcp-gateway-admin config reads and sets them (roadmap step
// 36).

// ErrUnknownKey is the error of a key gateway.yaml does not have.
var ErrUnknownKey = errors.New("no such key in gateway.yaml")

// KeyType returns the Go type of key and whether it is a section.
func KeyType(key string) (reflect.Type, bool, error) {
	t := reflect.TypeFor[Gateway]()
	parts := strings.Split(key, ".")
	for i, name := range parts {
		f, ok := yamlField(t, name)
		if !ok {
			return nil, false, fmt.Errorf("%s: %w", key, ErrUnknownKey)
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if i == len(parts)-1 {
			return ft, ft.Kind() == reflect.Struct, nil
		}
		if ft.Kind() != reflect.Struct {
			return nil, false, fmt.Errorf("%s: %w (%s is a key, not a section)", key, ErrUnknownKey, strings.Join(parts[:i+1], "."))
		}
		t = ft
	}
	return nil, false, fmt.Errorf("%s: %w", key, ErrUnknownKey)
}

// yamlField returns the field of the struct type t named name in YAML.
func yamlField(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		n, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if f.IsExported() && n != "" && n != "-" && n == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// Keys returns every key of gateway.yaml, in the order of the
// configuration's types; sections are not keys, their keys are.
func Keys() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if !f.IsExported() || name == "" || name == "-" {
				continue
			}
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, prefix+name+".")
				continue
			}
			out = append(out, prefix+name)
		}
	}
	walk(reflect.TypeFor[Gateway](), "")
	return out
}

// Value returns the value of key in g (a key, not a section).
func Value(g *Gateway, key string) (reflect.Value, error) {
	v := reflect.ValueOf(g).Elem()
	for _, name := range strings.Split(key, ".") {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v = reflect.Zero(v.Type().Elem())
			} else {
				v = v.Elem()
			}
		}
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, fmt.Errorf("%s: %w", key, ErrUnknownKey)
		}
		f, ok := yamlField(v.Type(), name)
		if !ok {
			return reflect.Value{}, fmt.Errorf("%s: %w", key, ErrUnknownKey)
		}
		v = v.FieldByIndex(f.Index)
	}
	return v, nil
}

// Source is where the value of a key in force comes from: a file and the
// line of its key there.
type Source struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Sources returns, for each key that the files set, the file and line it
// comes from: the last of base ("" for none) and dropIns that sets it,
// as the drop-ins merge (a section merges key by key, a key replaces).
// A key that no file sets has its built-in default.
func Sources(base string, dropIns []string) (map[string]Source, error) {
	out := map[string]Source{}
	files := dropIns
	if base != "" {
		files = append([]string{base}, dropIns...)
	}
	for _, p := range files {
		n, err := readMapping(p)
		if err != nil {
			return nil, err
		}
		sources(n, reflect.TypeFor[Gateway](), "", p, out)
	}
	return out, nil
}

func sources(n *yaml.Node, t reflect.Type, prefix, file string, out map[string]Source) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		key := prefix + k.Value
		if section := sectionType(t, k.Value); section != nil && v.Kind == yaml.MappingNode {
			sources(v, section, key+".", file, out)
			continue
		}
		if section := sectionType(t, k.Value); section != nil {
			// A section set to something else (null): its keys come from
			// here, at their defaults.
			for _, sub := range Keys() {
				if strings.HasPrefix(sub, key+".") {
					out[sub] = Source{file, k.Line}
				}
			}
			continue
		}
		out[key] = Source{file, k.Line}
	}
}

// ResolveFiles is the configuration of base ("" for the built-in
// defaults) with dropIns over it, as Resolve reads them: what a drop-in
// that is not written yet would make.
func ResolveFiles(base string, dropIns []string) (*Gateway, error) {
	if len(dropIns) > 0 {
		return loadMerged(base, dropIns)
	}
	if base != "" {
		g, err := LoadGateway(base)
		if err != nil {
			return nil, &FileError{base, err}
		}
		return g, nil
	}
	g := &Gateway{}
	g.setDefaults()
	return g, g.Validate()
}
