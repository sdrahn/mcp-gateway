package transport

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A body sent too slowly is cut off; once read, the response may take as
// long as it takes (an SSE stream after a POST).
func TestBodyDeadline(t *testing.T) {
	got := make(chan string, 4)
	srv := httptest.NewServer(BodyDeadline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			got <- "read error"
			return
		}
		time.Sleep(300 * time.Millisecond) // past the deadline
		if r.Context().Err() != nil {
			got <- "cancelled"
			return
		}
		_, _ = fmt.Fprintf(w, "got %s", body)
		got <- "ok"
	}), 100*time.Millisecond))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "got hello" || <-got != "ok" {
		t.Fatalf("whole body: %q", b)
	}

	// Headers announce 10 bytes, one comes.
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nh")
	select {
	case r := <-got:
		if r != "read error" {
			t.Fatalf("slow body: %s", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a slow body holds the handler")
	}

	// A GET without a body gets no deadline.
	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "got " || <-got != "ok" {
		t.Fatalf("GET: %q", b)
	}
}

func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitListener(inner, 1)
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2 := dial(), dial()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	first := <-accepted
	select {
	case <-accepted:
		t.Fatal("a second connection accepted while the first is open")
	case <-time.After(200 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("the second connection not accepted after the first closed")
	}
	_ = l.Close()
	if _, ok := <-accepted; ok {
		t.Error("accepted after Close")
	}
	if LimitListener(inner, 0) != inner {
		t.Error("no limit wraps the listener")
	}
}
