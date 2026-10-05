package mcpheader

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestEncode(t *testing.T) {
	for in, want := range map[string]string{
		"us-west1":            "us-west1",
		"a b":                 "a b",
		"":                    "",
		"Hello, 世界":           "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":            "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":        "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=":  "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"=?base64?unfinished": "=?base64?unfinished",
	} {
		if got := Encode(in); got != want {
			t.Errorf("Encode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToolParams(t *testing.T) {
	for _, tc := range []struct {
		schema string
		want   string // the headers, or the error
	}{
		{`{"type":"object","properties":{"r":{"type":"string","x-mcp-header":"Region"}}}`, "Region=r"},
		{`{"type":"object","properties":{"o":{"type":"object","properties":{"n":{"type":"integer","x-mcp-header":"N"}}}}}`, "N=o.n"},
		{`{"type":"object","properties":{"x-mcp-header":{"type":"string"}}}`, ""},
		{`{"type":"object","properties":{"e":{"type":"string","enum":[{"x-mcp-header":"E"}]}}}`, ""},
		{`{"type":"object","x-mcp-header":"Root"}`, "not on a property"},
		{`{"type":"object","properties":{"l":{"type":"array","items":{"type":"string","x-mcp-header":"I"}}}}`, "not on a property"},
		{`{"type":"object","properties":{"o":{"anyOf":[{"type":"object","properties":{"s":{"type":"string","x-mcp-header":"S"}}}]}}}`, "not on a property"},
		{`{"type":"object","$defs":{"d":{"type":"string","x-mcp-header":"D"}}}`, "not on a property"},
		{`{"type":"object","properties":{"f":{"type":"number","x-mcp-header":"F"}}}`, "type number"},
		{`{"type":"object","properties":{"s":{"type":"string","x-mcp-header":"A B"}}}`, "not a header name"},
		{`{"type":"object","properties":{"s":{"type":"string","x-mcp-header":""}}}`, "not a header name"},
		{`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"boolean","x-mcp-header":"x"}}}`, "used twice"},
	} {
		params, err := ToolParams(json.RawMessage(tc.schema))
		var got []string
		for _, h := range params {
			got = append(got, h.Name+"="+strings.Join(h.Path, "."))
		}
		if err != nil {
			got = []string{err.Error()}
		}
		if s := strings.Join(got, ","); (tc.want == "" && s != "") || !strings.Contains(s, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.schema, s, tc.want)
		}
	}
}

func TestDecode(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                               "plain",
		"=?base64?SGVsbG8sIOS4lueVjA==?=":     "Hello, 世界",
		"=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=": "=?base64?literal?=",
		"=?base64?unfinished":                 "=?base64?unfinished",
	} {
		if got, err := Decode(in); err != nil || got != want {
			t.Errorf("Decode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := Decode("=?base64?not base64!?="); err == nil {
		t.Error("invalid Base64 accepted")
	}
}

func TestCheck(t *testing.T) {
	params, err := ToolParams(json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},` +
		`"o":{"type":"object","properties":{"n":{"type":"integer","x-mcp-header":"N"}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	args := json.RawMessage(`{"region":"zürich","o":{"n":42}}`)
	h := http.Header{}
	Set(h, params, args)
	if h.Get("Mcp-Param-Region") != "=?base64?esO8cmljaA==?=" || h.Get("Mcp-Param-N") != "42" {
		t.Fatalf("Set: %v", h)
	}
	if err := Check(h, params, args); err != nil {
		t.Fatalf("Check of what Set set: %v", err)
	}
	for name, edit := range map[string]func(http.Header){
		"missing":    func(h http.Header) { h.Del("Mcp-Param-Region") },
		"different":  func(h http.Header) { h.Set("Mcp-Param-Region", "bern") },
		"repeated":   func(h http.Header) { h.Add("Mcp-Param-N", "42") },
		"bad base64": func(h http.Header) { h.Set("Mcp-Param-Region", "=?base64?!!?=") },
	} {
		h2 := h.Clone()
		edit(h2)
		if err := Check(h2, params, args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Integers compare as numbers; a header without an argument value is refused.
	h2 := h.Clone()
	h2.Set("Mcp-Param-N", "42.0")
	if err := Check(h2, params, args); err != nil {
		t.Errorf("42.0: %v", err)
	}
	if err := Check(h, params, json.RawMessage(`{"region":"zürich"}`)); err == nil {
		t.Error("Mcp-Param-N without an argument accepted")
	}
}
