package router

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

func canonicalJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	if len(raw) == 0 {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("not JSON: %q", raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// structField decodes raw as encoding/json decodes into a struct with
// one field tagged key: case-insensitively, the last match winning.
func structField(t *testing.T, raw json.RawMessage, key string) (json.RawMessage, bool) {
	t.Helper()
	for _, r := range key {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", r) {
			return nil, false
		}
	}
	if key == "" || key == "-" { // "-" leaves the field out
		return nil, false
	}
	typ := reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[json.RawMessage](), Tag: reflect.StructTag(`json:"` + key + `"`)}})
	ptr := reflect.New(typ)
	if err := json.Unmarshal(raw, ptr.Interface()); err != nil {
		t.Fatalf("struct decode of %s: %v", raw, err)
	}
	return ptr.Elem().Field(0).Interface().(json.RawMessage), true
}

var fuzzMethods = []string{"tools/call", "prompts/get", "resources/read", "completion/complete"}

// FuzzCallTarget: for parameters the router accepts (Session.call checks
// the keys, then target builds the policy input), a server decoding the
// forwarded parameters into Go structs, case-insensitively, sees the
// tool, prompt or resource and the arguments policy decided on.
func FuzzCallTarget(f *testing.F) {
	for _, s := range []struct {
		method     uint8
		aggregated bool
		params     string
	}{
		{0, true, `{"name":"fs__read_file","arguments":{"path":"/home/a/x"}}`},
		{0, true, `{"name":"fs__read_file","arguments":{"path":"/home/a/x","Path":"/etc/shadow"}}`},
		{0, true, `{"name":"fs__read_file","Name":"git__push"}`},
		{0, false, `{"name":"read_file","arguments":{"a":{"b":1}}}`},
		{1, true, `{"name":"git__summary","arguments":{"ref":"main"}}`},
		{2, true, `{"uri":"mcp+fs:file:///home/a/x"}`},
		{2, false, `{"uri":"file:///home/a/x","URI":"file:///etc/shadow"}`},
		{3, true, `{"ref":{"type":"ref/prompt","name":"git__summary"},"argument":{"name":"ref","value":"m"}}`},
	} {
		f.Add(s.method, s.aggregated, []byte(s.params))
	}
	backends := map[string]*config.Backend{"fs": {Name: "fs"}, "git": {Name: "git"}}
	f.Fuzz(func(t *testing.T, method uint8, aggregated bool, raw []byte) {
		m := fuzzMethods[int(method)%len(fuzzMethods)]
		if jsonrpc.CheckKeys(raw) != nil {
			return // Session.call refuses these
		}
		var params map[string]json.RawMessage
		if json.Unmarshal(raw, &params) != nil {
			return
		}
		s := &Session{annotations: map[string]map[string]any{}}
		if aggregated {
			ep := aggregatedEndpoint(backends)
			s.ep.Store(&ep)
		} else {
			ep := singleEndpoint(backends["fs"])
			s.ep.Store(&ep)
		}
		if checkParamKeys(params) != nil {
			return // Session.call refuses these
		}
		tg, rpcErr := s.target(m, params)
		if rpcErr != nil {
			return
		}
		// What the tool or prompt declares (from tools/list, prompts/list).
		declared := []string{"mode", "path", "ref"}
		if caseVariant(tg.args, declared, "arguments") != nil {
			return // Session.call refuses these
		}
		if s.endpoint().backends[tg.server] == nil {
			t.Fatalf("target server %q is not an endpoint backend", tg.server)
		}
		tg.rewrite(params)
		fwd, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		switch m {
		case "tools/call", "prompts/get":
			name, _ := structField(t, fwd, "name")
			var got string
			if json.Unmarshal(name, &got) != nil || got != tg.resource.Name {
				t.Fatalf("server reads name %s, policy decided on %q (forwarded %s)", name, tg.resource.Name, fwd)
			}
			args, _ := structField(t, fwd, "arguments")
			var exact map[string]json.RawMessage
			if len(args) > 0 && string(args) != "null" {
				if err := json.Unmarshal(args, &exact); err != nil {
					t.Fatalf("forwarded arguments %s: %v", args, err)
				}
			}
			if len(exact) != len(tg.args) {
				t.Fatalf("policy saw %d arguments, the server gets %d (%s)", len(tg.args), len(exact), args)
			}
			for k := range exact {
				if _, ok := tg.args[k]; !ok {
					t.Fatalf("argument %q forwarded but not in the policy input", k)
				}
			}
			// A Go server decodes its declared arguments into struct
			// fields: each must read what policy saw under that name.
			for _, k := range declared {
				var sv json.RawMessage
				if len(args) > 0 && string(args) != "null" {
					sv, _ = structField(t, args, k)
				}
				if canonicalJSON(t, sv) != canonicalJSON(t, exact[k]) {
					t.Fatalf("argument %q: policy saw %s, a Go server reads %s (arguments %s)", k, exact[k], sv, args)
				}
			}
		case "resources/read":
			uri, _ := structField(t, fwd, "uri")
			var got string
			if json.Unmarshal(uri, &got) != nil || got != tg.resource.Name {
				t.Fatalf("server reads uri %s, policy decided on %q", uri, tg.resource.Name)
			}
		}
	})
}
