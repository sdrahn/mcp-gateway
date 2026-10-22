package policydata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Names are the names of a role data file, the one in force first: where
// a directory has both, the YAML is in force and the JSON ignored
// (docs/architecture.md, roadmap step 37).
var Names = []string{"data.yaml", "data.json"}

// InForce returns the role data file in force for path, and the files
// next to it that are not: for a path named as one of Names, the first of
// Names that exists in its directory (path itself if none does); any other
// path, and "-" (standard input), is in force as it is.
func InForce(path string) (string, []string) {
	if path == "-" || !slices.Contains(Names, filepath.Base(path)) {
		return path, nil
	}
	dir := filepath.Dir(path)
	inForce := ""
	var ignored []string
	for _, n := range Names {
		p := filepath.Join(dir, n)
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if inForce == "" {
			inForce = p
		} else {
			ignored = append(ignored, p)
		}
	}
	if inForce == "" {
		return path, nil
	}
	return inForce, ignored
}

// Read reads the role data in force for path (InForce) as JSON, which is
// what OPA, the checker and the readers of the role data work on: a YAML
// file is converted (ToJSON). It returns the file it read and those it
// ignored; "-" reads standard input, YAML or JSON.
func Read(path string) (file string, data []byte, ignored []string, err error) {
	file, ignored = InForce(path)
	if file == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		return file, nil, ignored, err
	}
	if isYAML(file, data) {
		if data, err = ToJSON(data); err != nil {
			name := file
			if file == "-" {
				name = "standard input"
			}
			return file, nil, ignored, fmt.Errorf("%s: %w", name, err)
		}
	}
	return file, data, ignored, nil
}

// isYAML reports whether the role data at file, with content data, is
// YAML: by its name, or for standard input when it is not JSON.
func isYAML(file string, data []byte) bool {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".yaml", ".yml":
		return true
	case ".json":
		return false
	}
	return !json.Valid(data)
}

// ToJSON converts YAML role data to JSON. YAML is a superset of JSON here:
// a mapping's keys must be strings (as JSON's are), and a value is a
// mapping, a sequence, a string, a number, a boolean or null. An error
// names the line.
func ToJSON(data []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 {
		return []byte("{}"), nil
	}
	v, err := jsonValue(&doc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jsonValue is the JSON value of a YAML node: mappings with string keys
// in their order, sequences, and scalars by their resolved tag.
func jsonValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return map[string]any{}, nil
		}
		return jsonValue(n.Content[0])
	case yaml.AliasNode:
		return jsonValue(n.Alias)
	case yaml.MappingNode:
		m := orderedMap{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.ShortTag() == "!!merge" {
				return nil, fmt.Errorf("line %d: merge keys (<<) are not supported", k.Line)
			}
			if k.Kind != yaml.ScalarNode || (k.ShortTag() != "!!str" && k.ShortTag() != "!!int" && k.ShortTag() != "!!bool") {
				return nil, fmt.Errorf("line %d: a key must be a string", k.Line)
			}
			val, err := jsonValue(v)
			if err != nil {
				return nil, err
			}
			if m.has(k.Value) {
				return nil, fmt.Errorf("line %d: key %q is already defined", k.Line, k.Value)
			}
			m.set(k.Value, val)
		}
		return m, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := jsonValue(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool", "!!int", "!!float":
			var v any
			if err := n.Decode(&v); err != nil {
				return nil, fmt.Errorf("line %d: %w", n.Line, err)
			}
			return v, nil
		case "!!str":
			return n.Value, nil
		default:
			// Timestamps, binary and the like: as written, a string.
			return n.Value, nil
		}
	}
	return nil, errors.New("unexpected YAML node")
}

// orderedMap is a JSON object that keeps the order of the YAML mapping.
type orderedMap struct {
	keys []string
	vals map[string]any
}

func (m *orderedMap) has(k string) bool { _, ok := m.vals[k]; return ok }

func (m *orderedMap) set(k string, v any) {
	if m.vals == nil {
		m.vals = map[string]any{}
	}
	m.keys = append(m.keys, k)
	m.vals[k] = v
}

func (m orderedMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := marshal(m.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshal is json.Marshal without HTML escaping (patterns hold < and >).
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// readShipped reads the role data in force in dir (a setup's directory
// of the shipped policy) as JSON. YAML that does not parse is a problem
// of the file, as JSON that does not is (Check).
func readShipped(dir string) (file string, data []byte, problem string, err error) {
	file, _ = InForce(filepath.Join(dir, Names[1]))
	if data, err = os.ReadFile(file); err != nil {
		return file, nil, "", err
	}
	if isYAML(file, data) {
		if data, err = ToJSON(data); err != nil {
			return file, nil, "not valid YAML: " + err.Error(), nil
		}
	}
	return file, data, "", nil
}
