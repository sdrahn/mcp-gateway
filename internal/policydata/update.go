package policydata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"go.yaml.in/yaml/v3"
)

// UpdateYAML returns base, YAML role data, changed to hold data (JSON):
// what is unchanged keeps its comments and style, keys keep their order
// in base, a changed value keeps the comments of its entry, and a new key
// comes after the key before it in data. In a sequence, an element still
// there keeps its comments, also when others before it were removed or
// added. The result reads back (ToJSON) as data; base empty starts from
// nothing.
func UpdateYAML(base, data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	want, err := yamlNode(dec)
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("not valid JSON: data after the top-level value")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(base, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode}
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{want}
	} else {
		doc.Content[0] = merge(doc.Content[0], want)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	// The YAML must say what data says; anything else is a bug here, and
	// writing it would change the role data unseen.
	back, err := ToJSON(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("updating the YAML: %w", err)
	}
	var a, b any
	if json.Unmarshal(back, &a) != nil || json.Unmarshal(data, &b) != nil || !reflect.DeepEqual(a, b) {
		return nil, errors.New("updating the YAML: the result does not read back as the data")
	}
	return buf.Bytes(), nil
}

// merge returns old changed to want (a node built from JSON): old's nodes
// where they still hold the same, with their comments.
func merge(old, want *yaml.Node) *yaml.Node {
	if old.Kind == yaml.AliasNode {
		old = old.Alias
	}
	switch {
	case old.Kind == yaml.MappingNode && want.Kind == yaml.MappingNode:
		// The keys still there in old's order; a new key after the
		// one before it in want (first if none is).
		wanted := map[string]*yaml.Node{}
		for i := 0; i+1 < len(want.Content); i += 2 {
			wanted[want.Content[i].Value] = want.Content[i+1]
		}
		var content []*yaml.Node
		have := map[string]bool{}
		for i := 0; i+1 < len(old.Content); i += 2 {
			k := old.Content[i]
			if v, ok := wanted[k.Value]; ok {
				content = append(content, k, merge(old.Content[i+1], v))
				have[k.Value] = true
			}
		}
		prev := ""
		for i := 0; i+1 < len(want.Content); i += 2 {
			k, v := want.Content[i], want.Content[i+1]
			if !have[k.Value] {
				at := 0
				for j := 0; j+1 < len(content); j += 2 {
					if content[j].Value == prev {
						at = j + 2
					}
				}
				content = append(content[:at], append([]*yaml.Node{k, v}, content[at:]...)...)
				have[k.Value] = true
			}
			prev = k.Value
		}
		old.Content = content
		return old
	case old.Kind == yaml.SequenceNode && want.Kind == yaml.SequenceNode:
		// Walk both: an old element equal to the wanted one is kept; old
		// elements up to an equal one are removed; an old element that a
		// later wanted one equals waits, and the wanted one is new; else
		// the old element is the one edited.
		var content []*yaml.Node
		j := 0
		for i, v := range want.Content {
			if k := indexEqual(old.Content[j:], v); k >= 0 {
				content = append(content, old.Content[j+k])
				j += k + 1
				continue
			}
			if j < len(old.Content) && indexEqual(want.Content[i+1:], old.Content[j]) < 0 {
				content = append(content, merge(old.Content[j], v))
				j++
				continue
			}
			content = append(content, v)
		}
		old.Content = content
		if old.Style == yaml.FlowStyle && !fitsFlow(old) {
			old.Style = 0
		}
		return old
	case old.Kind == yaml.ScalarNode && want.Kind == yaml.ScalarNode && sameScalar(old, want):
		return old
	}
	// Another value: want, with the comments of the entry it replaces.
	want.HeadComment, want.LineComment, want.FootComment = old.HeadComment, old.LineComment, old.FootComment
	return want
}

// indexEqual returns the index of the first of nodes with the same JSON
// value as n, or -1.
func indexEqual(nodes []*yaml.Node, n *yaml.Node) int {
	v, ok := value(n)
	if !ok {
		return -1
	}
	for i, c := range nodes {
		if cv, ok := value(c); ok && reflect.DeepEqual(cv, v) {
			return i
		}
	}
	return -1
}

// value is n as a decoded JSON value (maps unordered), for comparing.
func value(n *yaml.Node) (any, bool) {
	jv, err := jsonValue(n)
	if err != nil {
		return nil, false
	}
	b, err := marshal(jv)
	if err != nil {
		return nil, false
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	return v, true
}

// sameScalar reports whether two scalars are the same JSON value.
func sameScalar(a, b *yaml.Node) bool {
	va, err1 := jsonValue(a)
	vb, err2 := jsonValue(b)
	if err1 != nil || err2 != nil {
		return false
	}
	ja, _ := json.Marshal(va)
	jb, _ := json.Marshal(vb)
	return bytes.Equal(ja, jb)
}

// fitsFlow reports whether n would be put in flow style (flow).
func fitsFlow(n *yaml.Node) bool {
	c := *n
	c.Style = 0
	flow(&c)
	return c.Style == yaml.FlowStyle
}
