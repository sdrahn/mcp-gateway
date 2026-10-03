// Package profile records what an MCP server needs from the system while
// it runs in a permissive SELinux domain, and drafts a policy module and
// definition settings from it. It backs "mcp-gateway-admin profile".
//
// See docs/architecture.md, section 11, step 11.
package profile

import (
	"encoding/json"
	"regexp"
)

// SampleArgs builds arguments for a tool from its input schema: every
// required property gets its default, its first enum value, or a plain
// value of its type (a path-like string gets "/"). They exercise the
// tool's code path; they are not meant to make the call succeed.
func SampleArgs(schema json.RawMessage) map[string]any {
	var s prop
	if len(schema) == 0 || json.Unmarshal(schema, &s) != nil {
		return map[string]any{}
	}
	if v, ok := s.sample("", 0).(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

type prop struct {
	Type       any             `json:"type"`
	Default    json.RawMessage `json:"default"`
	Enum       []any           `json:"enum"`
	Const      any             `json:"const"`
	Minimum    *float64        `json:"minimum"`
	Properties map[string]prop `json:"properties"`
	Required   []string        `json:"required"`
	Items      *prop           `json:"items"`
	MinItems   int             `json:"minItems"`
	AnyOf      []prop          `json:"anyOf"`
	OneOf      []prop          `json:"oneOf"`
}

var pathName = regexp.MustCompile(`(?i)(^|_)(path|file|filename|dir|directory)$`)

// maxDepth bounds nested objects (and recursive schemas).
const maxDepth = 5

func (p prop) sample(name string, depth int) any {
	if len(p.Default) > 0 {
		var v any
		if json.Unmarshal(p.Default, &v) == nil {
			return v
		}
	}
	if p.Const != nil {
		return p.Const
	}
	if len(p.Enum) > 0 {
		return p.Enum[0]
	}
	if p.Type == nil {
		if len(p.AnyOf) > 0 {
			return p.AnyOf[0].sample(name, depth)
		}
		if len(p.OneOf) > 0 {
			return p.OneOf[0].sample(name, depth)
		}
	}
	switch p.typ() {
	case "object":
		out := map[string]any{}
		if depth >= maxDepth {
			return out
		}
		for _, r := range p.Required {
			out[r] = p.Properties[r].sample(r, depth+1)
		}
		return out
	case "array":
		out := []any{}
		if p.Items != nil && depth < maxDepth {
			for i := 0; i < p.MinItems; i++ {
				out = append(out, p.Items.sample(name, depth+1))
			}
		}
		return out
	case "integer", "number":
		if p.Minimum != nil {
			return *p.Minimum
		}
		return 0
	case "boolean":
		return false
	case "null":
		return nil
	}
	if pathName.MatchString(name) {
		return "/"
	}
	return ""
}

// typ returns the schema type; of a list of types the first that is not
// "null".
func (p prop) typ() string {
	switch t := p.Type.(type) {
	case string:
		return t
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "null" {
				return s
			}
		}
	}
	if p.Properties != nil {
		return "object"
	}
	return "string"
}
