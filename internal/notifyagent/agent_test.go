package notifyagent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeNotifier struct {
	mu      sync.Mutex
	next    uint32
	shown   map[uint32]Notification
	closed  []uint32
	actions chan uint32
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{shown: map[uint32]Notification{}, actions: make(chan uint32, 4)}
}

func (f *fakeNotifier) Show(n Notification) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := n.Replaces
	if id == 0 {
		f.next++
		id = f.next
	}
	f.shown[id] = n
	return id, nil
}

func (f *fakeNotifier) Close(id uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.shown, id)
	f.closed = append(f.closed, id)
	return nil
}

func (f *fakeNotifier) Actions() <-chan uint32 { return f.actions }

func (f *fakeNotifier) snapshot() map[uint32]Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[uint32]Notification{}
	for k, v := range f.shown {
		out[k] = v
	}
	return out
}

// fakeGateway serves GET /v1/events on a unix socket from a channel of
// SSE data lines.
type fakeGateway struct {
	sock   string
	events chan string
	srv    *http.Server
	status int
}

func startGateway(t *testing.T, sock string, status int) *fakeGateway {
	t.Helper()
	g := &fakeGateway{sock: sock, events: make(chan string, 16), status: status}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	g.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.status != http.StatusOK {
			w.WriteHeader(g.status)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case data := <-g.events:
				if _, err := fmt.Fprintf(w, "event: approval\ndata: %s\n\n", data); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	})}
	go func() { _ = g.srv.Serve(l) }()
	return g
}

func (g *fakeGateway) stop() { _ = g.srv.Close() }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 400 {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

const pendingEvent = `{"type":"pending","id":"a-1","url":"https://gw.example.com/approvals/a-1","pending":{"principal":{"sub":"alice","transport":"unix","client":{"name":"kit"}},"action":"tools.call","server":"fs","name":"write_file","waiting":true}}`

func TestAgent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	g := startGateway(t, sock, http.StatusOK)
	n := newFakeNotifier()
	opened := make(chan string, 4)
	a := &Agent{Socket: sock, URLTemplate: "https://localhost:9090/mcp-gateway#/approvals/{id}", Notifier: n,
		Open: func(u string) error { opened <- u; return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	g.events <- pendingEvent
	waitFor(t, "notification", func() bool { return len(n.snapshot()) == 1 })
	shown := n.snapshot()[1]
	if shown.Summary != "Approval needed: fs / write_file" {
		t.Fatalf("summary %q", shown.Summary)
	}

	// The same approval without a waiting call updates the notification.
	g.events <- `{"type":"pending","id":"a-1","pending":{"principal":{"sub":"alice"},"server":"fs","name":"write_file","waiting":false}}`
	waitFor(t, "update", func() bool {
		s := n.snapshot()
		return len(s) == 1 && s[1].Body != shown.Body
	})

	// The action opens the approval page (the template, since the update
	// carried no URL).
	n.actions <- 1
	if u := <-opened; u != "https://localhost:9090/mcp-gateway#/approvals/a-1" {
		t.Fatalf("opened %q", u)
	}

	// Resolved: the notification goes.
	g.events <- `{"type":"resolved","id":"a-1"}`
	waitFor(t, "close", func() bool { return len(n.snapshot()) == 0 })

	// The gateway restarts: notifications are cleared and the agent
	// reconnects.
	g.events <- `{"type":"pending","id":"a-2","url":"https://gw.example.com/approvals/a-2","pending":{"principal":{"sub":"alice"},"server":"fs","name":"x","waiting":true}}`
	waitFor(t, "second notification", func() bool { return len(n.snapshot()) == 1 })
	g.stop()
	waitFor(t, "cleared", func() bool { return len(n.snapshot()) == 0 })
	_ = os.Remove(sock)
	g2 := startGateway(t, sock, http.StatusOK)
	defer g2.stop()
	g2.events <- pendingEvent
	waitFor(t, "notification after reconnect", func() bool { return len(n.snapshot()) == 1 })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAgentRejectsOddURLs(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	g := startGateway(t, sock, http.StatusOK)
	defer g.stop()
	n := newFakeNotifier()
	opened := make(chan string, 4)
	a := &Agent{Socket: sock, Notifier: n, Open: func(u string) error { opened <- u; return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	g.events <- `{"type":"pending","id":"a-1","url":"file:///etc/passwd","pending":{"principal":{"sub":"alice"},"server":"fs","name":"x","waiting":true}}`
	waitFor(t, "notification", func() bool { return len(n.snapshot()) == 1 })
	n.actions <- 1
	select {
	case u := <-opened:
		t.Fatalf("opened %q", u)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAgentWithoutAccess(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	g := startGateway(t, sock, http.StatusForbidden)
	defer g.stop()
	a := &Agent{Socket: sock, Notifier: newFakeNotifier(), Open: func(string) error { return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != ErrNoAccess {
		t.Fatalf("got %v, want ErrNoAccess", err)
	}
}

func TestEscapeMarkup(t *testing.T) {
	if got := EscapeMarkup(`<b>x</b> & "y"`); got != "&lt;b&gt;x&lt;/b&gt; &amp; &#34;y&#34;" {
		t.Fatalf("got %q", got)
	}
}
