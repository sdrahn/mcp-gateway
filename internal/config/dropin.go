package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultDropInDir holds the drop-ins of gateway.yaml: files read in the
// order of their names over the file in force, key by key (a section
// merges, a value or a list replaces), so that a setting can be changed
// without copying the whole default (roadmap step 36).
const DefaultDropInDir = "/etc/mcp-gateway/gateway.d"

// FileError is an error of one configuration file: gateway.yaml or a
// drop-in. Its message names the file already.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string { return e.Err.Error() }
func (e *FileError) Unwrap() error { return e.Err }

// ErrorFile names the file an error of Resolve is about as the audit
// and the status have it: "gateway.yaml", or "gateway.d/NAME" for a
// drop-in.
func ErrorFile(err error) string {
	var fe *FileError
	if errors.As(err, &fe) && filepath.Base(filepath.Dir(fe.Path)) == filepath.Base(DefaultDropInDir) {
		return filepath.Base(DefaultDropInDir) + "/" + filepath.Base(fe.Path)
	}
	return "gateway.yaml"
}

// DropIns returns the drop-ins in dir, sorted by name: its regular files
// (or links to them) named *.yaml, but not hidden ones (an editor's or a
// command's file being written). A missing dir has none.
func DropIns(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") || strings.HasPrefix(name, ".") {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil {
			return nil, &FileError{p, fmt.Errorf("%s: %w", p, err)}
		}
		if fi.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// loadMerged reads base ("" for the built-in defaults) and the drop-ins
// over it. Each drop-in is checked alone first (unknown keys, types, its
// format version), so that its errors name its lines; the configuration
// is then checked as a whole after each one, so that a drop-in that makes
// it invalid is named.
func loadMerged(base string, dropIns []string) (*Gateway, error) {
	doc := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	g := &Gateway{}
	g.setDefaults()
	if base != "" {
		var err error
		if g, err = LoadGateway(base); err != nil {
			return nil, &FileError{base, err}
		}
		if doc, err = readMapping(base); err != nil {
			return nil, &FileError{base, err}
		}
	}
	warnings := g.Warnings
	for _, p := range dropIns {
		n, err := readMapping(p)
		if err != nil {
			return nil, &FileError{p, err}
		}
		if len(n.Content) == 0 {
			continue // empty, or comments only
		}
		var alone Gateway
		w, err := decodeFile(p, &alone, gatewayDeprecations)
		if err != nil {
			return nil, &FileError{p, err}
		}
		if alone.Version != 0 {
			if err := checkVersion(alone.Version); err != nil {
				return nil, &FileError{p, fmt.Errorf("%s: %w", p, err)}
			}
		}
		for _, s := range w {
			warnings = append(warnings, p+": "+s)
		}
		merge(doc, n, reflect.TypeFor[Gateway]())
		if g, err = decodeMerged(doc); err != nil {
			return nil, &FileError{p, fmt.Errorf("%s: %w", p, err)}
		}
	}
	g.Warnings = warnings
	g.DropIns = dropIns
	return g, nil
}

// readMapping parses the YAML file at path into its top mapping; an
// empty file is an empty one.
func readMapping(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	n := doc.Content[0]
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: not a mapping of keys", path)
	}
	return n, nil
}

// merge puts the keys of src into dst, both mappings of a value of type
// t: a section (a struct of t's) merges key by key, any other value
// replaces dst's, a list and a map of names (agents.max_version) too.
func merge(dst, src *yaml.Node, t reflect.Type) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		k, v := src.Content[i], src.Content[i+1]
		j := -1
		for d := 0; d+1 < len(dst.Content); d += 2 { // keys at even places
			if dst.Content[d].Value == k.Value {
				j = d
				break
			}
		}
		section := sectionType(t, k.Value)
		switch {
		case j < 0:
			dst.Content = append(dst.Content, k, v)
		case section != nil && dst.Content[j+1].Kind == yaml.MappingNode && v.Kind == yaml.MappingNode:
			merge(dst.Content[j+1], v, section)
		default:
			dst.Content[j+1] = v
		}
	}
}

// sectionType returns the struct type of key in the struct type t, nil
// if it is not a section.
func sectionType(t reflect.Type, key string) reflect.Type {
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name != key {
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			return ft
		}
		return nil
	}
	return nil
}

// decodeMerged decodes and checks the merged configuration doc.
func decodeMerged(doc *yaml.Node) (*Gateway, error) {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	g := &Gateway{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(g); err != nil {
		return nil, err
	}
	g.setDefaults()
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return g, nil
}
