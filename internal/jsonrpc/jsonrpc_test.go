package jsonrpc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

type rwc struct {
	io.Reader
	io.Writer
}

func (rwc) Close() error { return nil }

func TestReadClassifies(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		``,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"a","result":{}}`,
		`not json`,
		`{"jsonrpc":"1.0","id":1,"method":"x"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`, // no trailing newline
	}, "\n")
	c := NewConn(rwc{strings.NewReader(in), io.Discard})

	m, err := c.Read()
	if err != nil || !m.IsRequest() || m.Method != "tools/list" || m.Key() != "1" {
		t.Fatalf("request: %+v %v", m, err)
	}
	if m, err = c.Read(); err != nil || !m.IsNotification() {
		t.Fatalf("notification: %+v %v", m, err)
	}
	if m, err = c.Read(); err != nil || !m.IsResponse() || m.Key() != `"a"` {
		t.Fatalf("response: %+v %v", m, err)
	}
	var rpcErr *Error
	var lineErr *LineError
	if _, err = c.Read(); !errors.As(err, &rpcErr) || rpcErr.Code != CodeParseError ||
		!errors.As(err, &lineErr) || string(lineErr.Line) != "not json" {
		t.Fatalf("parse error: %v", err)
	}
	if _, err = c.Read(); !errors.As(err, &rpcErr) || rpcErr.Code != CodeInvalidRequest ||
		!errors.As(err, &lineErr) || !strings.Contains(string(lineErr.Line), `"1.0"`) {
		t.Fatalf("invalid request: %v", err)
	}
	if m, err = c.Read(); err != nil || m.Method != "ping" {
		t.Fatalf("last line: %+v %v", m, err)
	}
	if _, err = c.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReadTooLarge(t *testing.T) {
	big := `{"jsonrpc":"2.0","method":"x","params":"` + strings.Repeat("a", MaxMessageSize) + `"}` + "\n"
	c := NewConn(rwc{strings.NewReader(big), io.Discard})
	if _, err := c.Read(); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := NewConn(a), NewConn(b)
	defer func() { _ = ca.Close() }()
	defer func() { _ = cb.Close() }()

	req, err := NewRequest([]byte(`7`), "tools/call", map[string]any{"name": "x"})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ca.Write(req) }()
	got, err := cb.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != "tools/call" || string(got.Params) != `{"name":"x"}` || got.Key() != "7" {
		t.Fatalf("got %+v", got)
	}

	go func() { _ = cb.Write(NewError(nil, CodeForbidden, "no")) }()
	got, err = ca.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Error == nil || got.Error.Code != CodeForbidden || string(got.ID) != "null" {
		t.Fatalf("got %+v", got)
	}
}

func TestCheckKeys(t *testing.T) {
	for _, tc := range []struct {
		raw, want string // want: substring of the error, "" for none
	}{
		{``, ""},
		{`{"name":"x","arguments":{"path":"/a","mode":1}}`, ""},
		{`[{"a":1},{"a":2}]`, ""},
		{`"plain"`, ""},
		{`{"a":1,"a":2}`, `key "a" appears twice`},
		{`{"arguments":{"path":"/a","Path":"/b"}}`, `keys "path" and "Path" differ only in case`},
		{`{"x":[{"deep":{"k":1,"K":2}}]}`, `differ only in case`},
		{"{\"k\":1,\"K\":2}", `differ only in case`}, // Kelvin sign
		{"{\"s\":1,\"ſ\":2}", `differ only in case`}, // long s
		{`{"a":1} {"b":2}`, `trailing data`},
		{`{"a":`, `EOF`},
	} {
		err := CheckKeys(json.RawMessage(tc.raw))
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.raw, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want %q", tc.raw, err, tc.want)
		}
	}
}
