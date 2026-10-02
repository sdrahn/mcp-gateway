package pep

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

// FuzzVersioned: the policy input OPA receives is one JSON object with
// "version": 1 and otherwise exactly the gateway's input, whatever the
// input holds (client-supplied arguments end up in it).
func FuzzVersioned(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`{"action":"tools.call","args":{"path":"/home/a"}}`,
		`{"args":{"version":2,"x":"}\",\"version\":3"}}`,
		`{"a":" </script>"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var in map[string]json.RawMessage
		if json.Unmarshal(data, &in) != nil || jsonrpc.CheckKeys(data) != nil {
			return
		}
		if _, ok := in["version"]; ok {
			return // no input of the gateway has one
		}
		out, err := versioned(in)
		if err != nil {
			t.Fatalf("versioned: %v", err)
		}
		if err := jsonrpc.CheckKeys(out); err != nil {
			t.Fatalf("output %s: %v", out, err)
		}
		var got map[string]json.RawMessage
		dec := json.NewDecoder(bytes.NewReader(out))
		if err := dec.Decode(&got); err != nil || dec.More() {
			t.Fatalf("output is not one object: %s (%v)", out, err)
		}
		if string(got["version"]) != "1" {
			t.Fatalf("version %s", got["version"])
		}
		delete(got, "version")
		if len(got) != len(in) {
			t.Fatalf("keys changed: %d, want %d", len(got), len(in))
		}
		for k, v := range in {
			var a, b any
			_ = json.Unmarshal(v, &a)
			_ = json.Unmarshal(got[k], &b)
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			if !bytes.Equal(ja, jb) {
				t.Fatalf("key %q: %s became %s", k, v, got[k])
			}
		}
	})
}
