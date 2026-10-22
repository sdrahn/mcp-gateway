package policydata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// flowWidth is the longest a mapping or sequence of scalars may be to be
// written on one line ({server: fs, tool: read_*}).
const flowWidth = 72

// ToYAML converts JSON role data to YAML that ToJSON reads back as the
// same data, keys in their order: block style, with mappings and
// sequences of scalars that fit on a line in flow style. header, if not
// empty, becomes a comment at the top.
func ToYAML(data []byte, header string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	n, err := yamlNode(dec)
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("not valid JSON: data after the top-level value")
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{n}}
	if header != "" {
		doc.HeadComment = "# " + strings.ReplaceAll(strings.TrimRight(header, "\n"), "\n", "\n# ")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// yamlNode reads the next JSON value from dec as a YAML node.
func yamlNode(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("a key that is not a string: %v", k)
				}
				v, err := yamlNode(dec)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			flow(n)
			return n, nil
		case '[':
			n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for dec.More() {
				v, err := yamlNode(dec)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			flow(n)
			return n, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(t.String(), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: t.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(t)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected %v", tok)
}

// flow puts n, a mapping or sequence, in flow style if it holds scalars
// only (or nothing) and fits on a line.
func flow(n *yaml.Node) {
	width := 2
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode {
			return
		}
		width += len(c.Value) + 2
	}
	if width <= flowWidth {
		n.Style = yaml.FlowStyle
	}
}
