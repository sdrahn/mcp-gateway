package pep

import (
	"bytes"
	"encoding/json"
	"strings"
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
		`{"Version":1}`,
		`{"verſion":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var in map[string]json.RawMessage
		// JSON null decodes into a nil map: not an object, which every
		// input of the gateway is.
		if json.Unmarshal(data, &in) != nil || in == nil || jsonrpc.CheckKeys(data) != nil {
			return
		}
		for k := range in {
			if strings.EqualFold(k, "version") {
				return // no input of the gateway has one, in any case
			}
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
