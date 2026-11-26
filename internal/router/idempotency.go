package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Idempotency keys (Custos R8): a client may name a tools/call with a key
// in its _meta. The gateway keeps, per principal and key, the call's
// outcome for a while (idempotency.window): a call sent again with the
// same key, server, tool and arguments is not run again but answered from
// the first, waiting for it while it runs; one with the same key and
// another call is refused. A call with a key runs to its end whatever
// happens to the client's connection, so that a client cut off while it
// runs can ask again. Outcomes are kept in memory: not across a restart.

// IdempotencyMeta is the _meta key of a tools/call's idempotency key.
const IdempotencyMeta = "io.github.sdrahn.mcp-gateway/idempotencyKey"

const (
	// maxIdempotencyKey bounds a key's length.
	maxIdempotencyKey = 128
	// maxIdempotencyKeys bounds the keys one principal has kept or
	// running; more are refused until some expire.
	maxIdempotencyKeys = 1000
	// defaultIdempotencyWindow keeps an outcome this long when
	// idempotency.window is not set.
	defaultIdempotencyWindow = 10 * time.Minute
)

// deliverFunc hands a call's result to a principal, deciding delivery
// again (Session.deliver).
type deliverFunc func(ctx context.Context, to principal.Principal) (any, *jsonrpc.Error)

// idemEntry is one key's call: running until done is closed, then its
// outcome, an error or a result to deliver.
type idemEntry struct {
	key, owner  string
	fingerprint string
	server      string
	name        string
	done        chan struct{}

	mu         sync.Mutex
	decisionID string
	deliver    deliverFunc
	err        *jsonrpc.Error
	finished   bool
}

func (e *idemEntry) setDecision(id string) {
	e.mu.Lock()
	e.decisionID = id
	e.mu.Unlock()
}

func (e *idemEntry) decision() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.decisionID
}

// setDeliver keeps the call's result to deliver, or, larger than max
// bytes (size), an error saying it ran.
func (e *idemEntry) setDeliver(d deliverFunc, size, max int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if size > max {
		e.err = rpcError(jsonrpc.CodeInternalError, fmt.Sprintf(
			"mcp-gateway: the call with this idempotency key ran; its result (%d bytes) was larger than the gateway keeps (%d) and is not sent again", size, max))
		return
	}
	e.deliver = d
}

// idemStore holds the kept calls, by principal and key.
type idemStore struct {
	mu      sync.Mutex
	entries map[string]*idemEntry
	count   map[string]int // by owner
}

func (st *idemStore) init() {
	if st.entries == nil {
		st.entries = map[string]*idemEntry{}
		st.count = map[string]int{}
	}
}

// begin returns the entry for p's key: a new one (first true) for a key
// not kept, else the kept one. It refuses a new key beyond the
// principal's bound.
func (st *idemStore) begin(p principal.Principal, key, fingerprint, server, name string) (e *idemEntry, first bool, err *jsonrpc.Error) {
	owner := principalKey(p)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init()
	if e := st.entries[owner+"\x00"+key]; e != nil {
		return e, false, nil
	}
	if st.count[owner] >= maxIdempotencyKeys {
		return nil, false, rpcError(jsonrpc.CodeInvalidRequest, fmt.Sprintf(
			"mcp-gateway: %d calls with idempotency keys are kept for you already; retry when some have expired", maxIdempotencyKeys))
	}
	e = &idemEntry{key: key, owner: owner, fingerprint: fingerprint, server: server, name: name, done: make(chan struct{})}
	st.entries[owner+"\x00"+key] = e
	st.count[owner]++
	return e, true, nil
}

// finish ends e's call: kept for window, or, with keep false (no outcome
// to keep: an answer asking the agent for input, a tool of the gateway's
// own), forgotten at once, so the key may be used again.
func (st *idemStore) finish(e *idemEntry, rerr *jsonrpc.Error, keep bool, window time.Duration) {
	e.mu.Lock()
	if e.deliver == nil && e.err == nil {
		e.err = rerr
	}
	if !keep {
		e.deliver, e.err = nil, nil
	}
	e.finished = true
	e.mu.Unlock()
	if !keep {
		st.forget(e)
	} else {
		time.AfterFunc(window, func() { st.forget(e) })
	}
	close(e.done)
}

func (st *idemStore) forget(e *idemEntry) {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := e.owner + "\x00" + e.key
	if st.entries[k] == e {
		delete(st.entries, k)
		if st.count[e.owner]--; st.count[e.owner] <= 0 {
			delete(st.count, e.owner)
		}
	}
}

// idemKey is a context key for the entry of the call a context runs.
type idemKey struct{}

func withIdem(ctx context.Context, e *idemEntry) context.Context {
	return context.WithValue(ctx, idemKey{}, e)
}

func idemOf(ctx context.Context) *idemEntry {
	e, _ := ctx.Value(idemKey{}).(*idemEntry)
	return e
}

// takeIdempotencyKey removes the key from params' _meta (the server never
// sees it) and returns it; "" without one. A key that is not a string of
// 1 to maxIdempotencyKey printable ASCII characters is an error.
func takeIdempotencyKey(params map[string]json.RawMessage) (string, error) {
	raw, ok := params["_meta"]
	if !ok {
		return "", nil
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(raw, &meta) != nil || meta == nil {
		return "", nil
	}
	v, ok := meta[IdempotencyMeta]
	if !ok {
		return "", nil
	}
	var key string
	if json.Unmarshal(v, &key) != nil {
		return "", fmt.Errorf("_meta %s must be a string", IdempotencyMeta)
	}
	if key == "" || len(key) > maxIdempotencyKey {
		return "", fmt.Errorf("_meta %s must have 1 to %d characters", IdempotencyMeta, maxIdempotencyKey)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return "", fmt.Errorf("_meta %s must be printable ASCII without spaces", IdempotencyMeta)
		}
	}
	delete(meta, IdempotencyMeta)
	if len(meta) == 0 {
		delete(params, "_meta")
	} else {
		params["_meta"], _ = json.Marshal(meta)
	}
	return key, nil
}

// callFingerprint identifies a call by server, tool and arguments (map
// keys in order, as encoding/json writes them).
func callFingerprint(server, name string, args map[string]any) string {
	b, _ := json.Marshal(struct {
		Server string         `json:"s"`
		Name   string         `json:"n"`
		Args   map[string]any `json:"a"`
	}{server, name, args})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// idempotent runs the tools/call t (key key) through run once per
// principal and key: the first call runs, detached from the client (its
// connection ending or a cancellation does not end the call), and later
// ones with the same call wait for it and get its outcome, delivered to
// them as policy decides now; a later one with another call is refused.
func (s *Session) idempotent(ctx context.Context, key string, t *callTarget,
	run func(ctx context.Context) (any, *jsonrpc.Error)) (any, *jsonrpc.Error) {
	p := s.snapshotPrincipal()
	fp := callFingerprint(t.server, t.resource.Name, t.args)
	e, first, rerr := s.r.idem.begin(p, key, fp, t.server, t.resource.Name)
	if rerr != nil {
		return nil, rerr
	}
	if !first {
		return s.repeat(ctx, p, e, fp, t)
	}
	// The call runs to its end even when the client goes away or cancels:
	// this request waits for it, keeping the instance and its place among
	// the principal's requests, and a repeat gets its outcome.
	v, rerr := run(withIdem(context.WithoutCancel(ctx), e))
	e.mu.Lock()
	kept := e.deliver != nil || e.err != nil
	e.mu.Unlock()
	// Kept: a result to deliver, or an error of the call (not an answer
	// that asks the agent for input, nor a tool of the gateway's own,
	// which a repeat runs again).
	s.r.idem.finish(e, rerr, kept || rerr != nil, s.r.idempotencyWindow())
	return v, rerr
}

// repeat answers a call sent again with e's key.
func (s *Session) repeat(ctx context.Context, p principal.Principal, e *idemEntry, fp string, t *callTarget) (any, *jsonrpc.Error) {
	note := func(outcome string) {
		s.r.Audit.Note("mcp-repeat", map[string]string{
			"session": p.SessionID, "sub": p.Sub, "server": t.server, "name": t.resource.Name,
			"idempotency_key": e.key, "decision_id": e.decision(), "outcome": outcome,
		})
	}
	if fp != e.fingerprint {
		note("refused")
		return nil, rpcError(jsonrpc.CodeInvalidParams, fmt.Sprintf(
			"invalid params: idempotency key %q was used for another call (%s/%s with other arguments, or another tool); a key names one call", e.key, e.server, e.name))
	}
	select {
	case <-e.done:
	default:
		note("waiting")
		select {
		case <-e.done:
		case <-ctx.Done():
			return nil, rpcError(jsonrpc.CodeInternalError, "request cancelled; the call with this idempotency key runs on")
		}
	}
	e.mu.Lock()
	deliver, rerr := e.deliver, e.err
	e.mu.Unlock()
	if deliver == nil && rerr == nil {
		// Not kept (an answer that asked for input): this call runs as a
		// new one.
		return nil, rpcError(jsonrpc.CodeInternalError, "the call with this idempotency key ended without an outcome to repeat; send it again")
	}
	note("answered")
	if rerr != nil {
		return nil, rerr
	}
	return deliver(ctx, s.snapshotPrincipal())
}

// idempotencyWindow is how long an outcome is kept (idempotency.window).
func (r *Router) idempotencyWindow() time.Duration { return r.settings().IdempotencyWindow }
