package jsonrpc

import (
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
	if _, err = c.Read(); !errors.As(err, &rpcErr) || rpcErr.Code != CodeParseError {
		t.Fatalf("parse error: %v", err)
	}
	if _, err = c.Read(); !errors.As(err, &rpcErr) || rpcErr.Code != CodeInvalidRequest {
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
