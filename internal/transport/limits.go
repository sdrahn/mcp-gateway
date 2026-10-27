package transport

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// BodyDeadline gives a request d to send its body: the read deadline is
// set when the request has one and cleared once it is read, so that a
// client cannot hold a connection by sending its body slowly, while a
// response stream (SSE) after it runs as long as it lasts. Requests
// without a body (an SSE GET) get no deadline.
func BodyDeadline(h http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
			rc := http.NewResponseController(w)
			if rc.SetReadDeadline(time.Now().Add(d)) == nil {
				r.Body = &clearOnEOF{ReadCloser: r.Body, clear: func() { _ = rc.SetReadDeadline(time.Time{}) }}
			}
		}
		h.ServeHTTP(w, r)
	})
}

// clearOnEOF clears the read deadline when the body has been read.
type clearOnEOF struct {
	io.ReadCloser
	clear func()
	once  sync.Once
}

func (c *clearOnEOF) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if err == io.EOF {
		c.once.Do(c.clear)
	}
	return n, err
}

// LimitListener accepts at most n connections at a time from l; the
// next waits until one of them is closed (n <= 0: no limit).
func LimitListener(l net.Listener, n int) net.Listener {
	if n <= 0 {
		return l
	}
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
