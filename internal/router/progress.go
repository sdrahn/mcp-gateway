package router

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

const defaultProgressInterval = 15 * time.Second

// clientProgress is the progress a client asked for with a request's
// params._meta.progressToken. While the request waits for approval, the
// gateway reports progress itself, so that the client knows the request
// is alive (clients may give up on requests that report nothing for a
// while); afterwards the backend's progress is passed on, shifted by what
// the gateway reported, since MCP requires progress to increase.
type clientProgress struct {
	s     *Session
	token json.RawMessage
	req   json.RawMessage // the client request it reports on

	mu   sync.Mutex
	sent float64
}

// progressOf returns the progress the client asked for in params, or nil.
func (s *Session) progressOf(ctx context.Context, params map[string]json.RawMessage) *clientProgress {
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) != nil {
		return nil
	}
	token, ok := meta["progressToken"]
	if !ok {
		return nil
	}
	return &clientProgress{s: s, token: token, req: requestOf(ctx)}
}

// report sends one progress notification with message.
func (cp *clientProgress) report(message string) {
	cp.mu.Lock()
	cp.sent++
	n := cp.sent
	cp.mu.Unlock()
	params, err := json.Marshal(map[string]any{"progressToken": cp.token, "progress": n, "message": message})
	if err != nil {
		return
	}
	_ = jsonrpc.WriteRelated(cp.s.client, &jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: "notifications/progress", Params: params}, cp.req)
}

// offset is the progress the gateway reported itself (0 for nil).
func (cp *clientProgress) offset() float64 {
	if cp == nil {
		return 0
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.sent
}

// reportWaiting reports progress for t while it waits for approval: at
// once and then every ProgressInterval, until the returned function is
// called. It does nothing if the client did not ask for progress.
func (s *Session) reportWaiting(t *callTarget) (stop func()) {
	cp := t.progress
	if cp == nil {
		return func() {}
	}
	interval := s.r.settings().ProgressInterval
	if interval <= 0 {
		interval = defaultProgressInterval
	}
	message := "Waiting for approval of " + t.server + "/" + t.resource.Name
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		cp.report(message)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				cp.report(message)
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// shiftProgress adds offset to the number params[key], if it is one.
func shiftProgress(params map[string]json.RawMessage, key string, offset float64) {
	var v float64
	if json.Unmarshal(params[key], &v) != nil {
		return
	}
	params[key] = json.RawMessage(strconv.FormatFloat(v+offset, 'f', -1, 64))
}
