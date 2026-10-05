// Package mcpheader is the part of the Streamable HTTP transport of MCP
// 2026-07-28 that mirrors request body fields into HTTP headers: the
// Base64 sentinel form of values, and tool parameters marked with
// x-mcp-header (Mcp-Param-{name}). The connector sets these headers
// toward servers; the gateway checks them on agents' requests.
package mcpheader

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
	// ParamPrefix starts the header of a tool parameter.
	ParamPrefix = "Mcp-Param-"
	// maxSafeInt bounds an integer in a header (JavaScript's safe range).
	maxSafeInt = 1<<53 - 1
)

// Encode returns s as a header value: as it is when that is safe, in the
// Base64 sentinel form otherwise (non-ASCII, control characters, leading
// or trailing whitespace, or a value that looks like the sentinel form).
func Encode(s string) string {
	safe := !strings.HasPrefix(s, sentinelPrefix) || !strings.HasSuffix(s, sentinelSuffix)
	for i := 0; safe && i < len(s); i++ {
		b := s[i]
		safe = b == '\t' || (b >= 0x20 && b <= 0x7e)
	}
	if safe && s != strings.Trim(s, " \t") {
		safe = false
	}
	if safe {
		return s
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(s)) + sentinelSuffix
}

// Decode returns the value a header carries, decoding the Base64 sentinel
// form.
func Decode(v string) (string, error) {
	inner, ok := strings.CutPrefix(v, sentinelPrefix)
	if !ok || !strings.HasSuffix(inner, sentinelSuffix) {
		return v, nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(inner, sentinelSuffix))
	if err != nil {
		return "", fmt.Errorf("invalid Base64 value %q", v)
	}
	return string(b), nil
}

// Param is a tool parameter mirrored into Mcp-Param-{Name}.
type Param struct {
	Name string
	Path []string // the properties keys leading to the parameter
	Type string   // string, integer or boolean
}

// ToolParams returns the parameters a tool's inputSchema marks with
// x-mcp-header, or why the annotations make the tool invalid.
func ToolParams(schema json.RawMessage) ([]Param, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	var root any
	if err := json.Unmarshal(schema, &root); err != nil {
		return nil, err
	}
	var params []Param
	var walk func(node any, path []string, reachable bool) error
	walk = func(node any, path []string, reachable bool) error {
		switch n := node.(type) {
		case []any:
			for _, v := range n {
				if err := walk(v, path, false); err != nil {
					return err
				}
			}
		case map[string]any:
			if v, ok := n["x-mcp-header"]; ok {
				p, err := checkParam(v, n, path, reachable)
				if err != nil {
					return err
				}
				for _, o := range params {
					if strings.EqualFold(o.Name, p.Name) {
						return fmt.Errorf("x-mcp-header %q is used twice", p.Name)
					}
				}
				params = append(params, p)
			}
			for k, v := range n {
				switch k {
				case "x-mcp-header", "enum", "const", "default", "examples":
					// values, not schemas
				case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
					m, _ := v.(map[string]any)
					for key, sub := range m {
						var err error
						if k == "properties" && reachable {
							err = walk(sub, append(slices.Clone(path), key), true)
						} else {
							err = walk(sub, path, false)
						}
						if err != nil {
							return err
						}
					}
				default:
					if err := walk(v, path, false); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := walk(root, nil, true); err != nil {
		return nil, err
	}
	return params, nil
}

func checkParam(v any, schema map[string]any, path []string, reachable bool) (Param, error) {
	name, _ := v.(string)
	if !reachable || len(path) == 0 {
		return Param{}, fmt.Errorf("x-mcp-header %q is not on a property reachable through properties alone", name)
	}
	if name == "" || strings.IndexFunc(name, func(r rune) bool { return !isTchar(r) }) >= 0 {
		return Param{}, fmt.Errorf("x-mcp-header %v is not a header name", v)
	}
	typ, _ := schema["type"].(string)
	switch typ {
	case "string", "integer", "boolean":
	default:
		return Param{}, fmt.Errorf("x-mcp-header %q is on a parameter of type %v, not string, integer or boolean", name, schema["type"])
	}
	return Param{Name: name, Path: path, Type: typ}, nil
}

// isTchar reports whether r may be in an HTTP field name (RFC 9110).
func isTchar(r rune) bool {
	return r < 0x7f && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
}

// Value returns the header value of p in a call's arguments; ok is false
// when the parameter has no value there (absent, null, or of another
// type), and then there is no header.
func (p Param) Value(arguments json.RawMessage) (string, bool) {
	raw := arguments
	for _, key := range p.Path {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return "", false
		}
		raw = obj[key]
	}
	switch p.Type {
	case "string":
		var s string
		if json.Unmarshal(raw, &s) == nil && len(raw) > 0 && raw[0] == '"' {
			return Encode(s), true
		}
	case "boolean":
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return strconv.FormatBool(b), true
		}
	case "integer":
		var f float64
		if json.Unmarshal(raw, &f) == nil && f == float64(int64(f)) && f >= -maxSafeInt && f <= maxSafeInt {
			return strconv.FormatInt(int64(f), 10), true
		}
	}
	return "", false
}

// Set sets the Mcp-Param headers of a tools/call from its arguments.
func Set(h http.Header, params []Param, arguments json.RawMessage) {
	for _, p := range params {
		if v, ok := p.Value(arguments); ok {
			h.Set(ParamPrefix+p.Name, v)
		}
	}
}

// ErrMismatch is wrapped by Check's errors.
var ErrMismatch = errors.New("header mismatch")

// Check verifies the Mcp-Param headers of a tools/call against its
// arguments: each parameter with a value has its header with that value
// (after decoding; integers compared as numbers), and one without a value
// has none.
func Check(h http.Header, params []Param, arguments json.RawMessage) error {
	for _, p := range params {
		key := ParamPrefix + p.Name
		got := h.Values(key)
		want, ok := p.Value(arguments)
		switch {
		case !ok && len(got) == 0:
			continue
		case !ok:
			return fmt.Errorf("%w: %s given, but the argument has no value", ErrMismatch, key)
		case len(got) != 1:
			return fmt.Errorf("%w: %s missing or repeated", ErrMismatch, key)
		}
		g, err := Decode(got[0])
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrMismatch, key, err)
		}
		w, _ := Decode(want)
		if g != w && (p.Type != "integer" || !sameNumber(g, w)) {
			return fmt.Errorf("%w: %s does not match the argument", ErrMismatch, key)
		}
	}
	return nil
}

func sameNumber(a, b string) bool {
	x, err1 := strconv.ParseFloat(a, 64)
	y, err2 := strconv.ParseFloat(b, 64)
	return err1 == nil && err2 == nil && x == y
}
