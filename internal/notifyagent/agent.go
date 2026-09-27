// Package notifyagent is the desktop side of the out-of-band approval push
// channel: it follows the gateway's event stream (GET /v1/events on the
// control socket, as the logged-in user) and shows a desktop notification
// for every approval the user may decide on. The notification's action
// opens the approval page; approving itself happens there, not from the
// notification, which any program in the user's session could click.
package notifyagent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Notification is what the agent shows.
type Notification struct {
	Summary string
	Body    string // plain text; notifiers escape it for markup
	// Replaces is the id of a notification this one updates (0: new).
	Replaces uint32
}

// Notifier shows desktop notifications.
type Notifier interface {
	Show(n Notification) (uint32, error)
	Close(id uint32) error
	// Actions delivers the ids of notifications whose action was invoked.
	Actions() <-chan uint32
}

// ErrNoAccess means the user may not use the control socket (not in the
// gateway's socket group): the agent has nothing to do for this user.
var ErrNoAccess = errors.New("notifyagent: no access to the gateway's control socket")

// Agent follows the gateway's approvals and notifies.
type Agent struct {
	Socket string
	// URLTemplate is the approval page for events without one ({id}).
	URLTemplate string
	Notifier    Notifier
	// Open opens a URL (xdg-open).
	Open func(string) error
	Log  *slog.Logger

	mu    sync.Mutex
	shown map[string]uint32 // approval id → notification id
	urls  map[uint32]string // notification id → approval page
}

type event struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	URL     string `json:"url"`
	Pending *struct {
		Principal struct {
			Sub       string `json:"sub"`
			Issuer    string `json:"iss"`
			Transport string `json:"transport"`
			Client    struct {
				Name string `json:"name"`
			} `json:"client"`
		} `json:"principal"`
		Action  string    `json:"action"`
		Server  string    `json:"server"`
		Name    string    `json:"name"`
		Prompt  string    `json:"prompt"`
		Expires time.Time `json:"expires"`
		Waiting bool      `json:"waiting"`
	} `json:"pending"`
}

// Run follows the event stream until ctx ends, reconnecting while the
// gateway is unavailable. It returns ErrNoAccess if the user may not use
// the socket.
func (a *Agent) Run(ctx context.Context) error {
	if a.Log == nil {
		a.Log = slog.New(slog.DiscardHandler)
	}
	a.mu.Lock()
	a.shown, a.urls = map[string]uint32{}, map[uint32]string{}
	a.mu.Unlock()
	go a.actions(ctx)
	backoff := time.Second
	for {
		err := a.follow(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, ErrNoAccess):
			return err
		case err != nil:
			a.Log.Debug("event stream ended", "err", err)
		}
		// The gateway restarted or is down: its approvals are listed
		// again on reconnect.
		a.clear()
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (a *Agent) follow(ctx context.Context) error {
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", a.Socket)
	}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://gateway/v1/events", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
			return ErrNoAccess
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden {
		return ErrNoAccess
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notifyagent: GET /v1/events: %s", resp.Status)
	}
	a.Log.Info("following approvals", "socket", a.Socket)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue
		}
		a.handle(ev)
	}
	return sc.Err()
}

func (a *Agent) handle(ev event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case ev.Type == "pending" && ev.Pending != nil:
		p := ev.Pending
		who := p.Principal.Sub
		if p.Principal.Issuer != "" {
			who += " (" + p.Principal.Issuer + ")"
		}
		body := fmt.Sprintf("%s wants to run %s on %s.", who, p.Name, p.Server)
		if p.Principal.Client.Name != "" {
			body += "\nClient: " + p.Principal.Client.Name
		}
		if !p.Waiting {
			body += "\nThe agent is no longer waiting; approving lets its next attempt through."
		} else if !p.Expires.IsZero() {
			body += "\nTimes out at " + p.Expires.Local().Format("15:04:05") + "."
		}
		body += "\nOpen the approval page to decide."
		id, err := a.Notifier.Show(Notification{Summary: "Approval needed: " + p.Server + " / " + p.Name,
			Body: body, Replaces: a.shown[ev.ID]})
		if err != nil {
			a.Log.Warn("showing notification failed", "err", err)
			return
		}
		a.shown[ev.ID] = id
		a.urls[id] = a.pageURL(ev)
	case ev.Type == "resolved":
		if id, ok := a.shown[ev.ID]; ok {
			delete(a.shown, ev.ID)
			delete(a.urls, id)
			_ = a.Notifier.Close(id)
		}
	}
}

// pageURL is the approval page of ev: the gateway's, else the template.
func (a *Agent) pageURL(ev event) string {
	if ev.URL != "" {
		return ev.URL
	}
	return strings.ReplaceAll(a.URLTemplate, "{id}", url.PathEscape(ev.ID))
}

// clear closes all notifications (the gateway is gone).
func (a *Agent) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for approval, id := range a.shown {
		_ = a.Notifier.Close(id)
		delete(a.shown, approval)
		delete(a.urls, id)
	}
}

func (a *Agent) actions(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-a.Notifier.Actions():
			a.mu.Lock()
			u := a.urls[id]
			a.mu.Unlock()
			if u == "" {
				continue
			}
			if parsed, err := url.Parse(u); err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
				a.Log.Warn("not opening approval page with unexpected URL", "url", u)
				continue
			}
			if err := a.Open(u); err != nil {
				a.Log.Warn("opening approval page failed", "url", u, "err", err)
			}
		}
	}
}

// EscapeMarkup escapes text for notification servers that interpret the
// body markup subset.
func EscapeMarkup(s string) string { return html.EscapeString(s) }
