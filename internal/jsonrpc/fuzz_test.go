package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// canonical returns raw JSON decoded and encoded again, so that two
// encodings of the same value (escapes, spacing) compare equal.
func canonical(t *testing.T, raw json.RawMessage) string {
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

// FuzzRead reads messages from any input. Every message Read returns is
// JSON-RPC 2.0 with a method or an id, and survives Write and Read with
// the same method, id and params; malformed lines are LineErrors and do
// not end the connection.
func FuzzRead(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":1}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"a","result":{}}`,
		`{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"no"}}`,
		"\n\n{\"jsonrpc\":\"2.0\",\"id\":[1, 2],\"method\":\"m\"}\r\n",
		`{"jsonrpc":"1.0","id":1,"method":"m"}`,
		`not json`,
		`{"jsonrpc":"2.0","id":null,"method":"m"}`,
		`{"jsonrpc":"2.0","id":1,"method":"m","params":null}` + "\n" + `{"jsonrpc":"2.0","method":"\u0000"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c := NewConn(rwc{Reader: bytes.NewReader(data), Writer: io.Discard})
		for range 1000 {
			m, err := c.Read()
			var le *LineError
			switch {
			case errors.As(err, &le):
				var je *Error
				if !errors.As(err, &je) || (je.Code != CodeParseError && je.Code != CodeInvalidRequest) {
					t.Fatalf("line error %v", err)
				}
				continue
			case err != nil:
				return // end of input, or too large
			}
			if m.JSONRPC != Version || (m.Method == "" && len(m.ID) == 0) {
				t.Fatalf("invalid message returned: %+v", m)
			}
			var out bytes.Buffer
			if err := NewConn(rwc{Reader: &bytes.Buffer{}, Writer: &out}).Write(m); err != nil {
				t.Fatalf("write %+v: %v", m, err)
			}
			if bytes.Count(out.Bytes(), []byte("\n")) != 1 {
				t.Fatalf("written message is not one line: %q", out.Bytes())
			}
			m2, err := NewConn(rwc{Reader: &out, Writer: io.Discard}).Read()
			if err != nil {
				t.Fatalf("re-read %q: %v", out.Bytes(), err)
			}
			if m2.Method != m.Method || canonical(t, m2.ID) != canonical(t, m.ID) || canonical(t, m2.Params) != canonical(t, m.Params) {
				t.Fatalf("round trip changed the message:\n%+v\n%+v", m, m2)
			}
		}
	})
}

// tagSafe reports keys usable as a struct tag name by encoding/json.
func tagSafe(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", r):
		case unicode.IsLetter(r) || unicode.IsDigit(r):
		default:
			return false
		}
	}
	return true
}

// FuzzCheckKeys: when CheckKeys accepts an object, a decoder that matches
// keys case-insensitively (encoding/json into a struct, as Go MCP servers
// decode their arguments) sees for every key the value an exact decoder
// (a map, as the gateway decides on) sees.
func FuzzCheckKeys(f *testing.F) {
	for _, s := range []string{
		`{"path":"/home/a","mode":1}`,
		`{"path":"/home/a","Path":"/etc"}`,
		`{"a":{"b":1,"B":2}}`,
		"{\"k\":1,\"K\":2}",
		`{"x":1,"x":2}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var exact map[string]json.RawMessage
		if json.Unmarshal(data, &exact) != nil || CheckKeys(data) != nil {
			return
		}
		for k, v := range exact {
			if !tagSafe(k) {
				continue
			}
			typ := reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[json.RawMessage](), Tag: reflect.StructTag(`json:"` + k + `"`)}})
			ptr := reflect.New(typ)
			if err := json.Unmarshal(data, ptr.Interface()); err != nil {
				t.Fatalf("struct decode: %v", err)
			}
			got := ptr.Elem().Field(0).Interface().(json.RawMessage)
			if canonical(t, got) != canonical(t, v) {
				t.Fatalf("key %q: exact decoder sees %s, case-insensitive decoder %s (input %s)", k, v, got, data)
			}
		}
	})
}
