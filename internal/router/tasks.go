package router

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Tasks (docs/architecture.md, decision D20, roadmap step 31): an agent
// that asks for one gets a task id at once, and the gateway makes the
// tools/call to the server as for any call, in a session of its own (the
// task session) that does not end with the agent's connection or token.
// The result is kept for the principal until fetched and for
// tasks.retention after the call ended. Servers stay synchronous: no
// server needs to support tasks. Agents of MCP 2025-11-25 ask with the
// task parameter of tools/call and use tasks/get, tasks/result,
// tasks/list and tasks/cancel; agents of 2026-07-28 declare the tasks
// extension and use tasks/get, tasks/update and tasks/cancel. What the
// call asks of the client (an approval, a server's elicitation, sampling
// or roots) makes the task input_required until the agent answers.

const (
	// tasksExtension is the tasks extension of MCP 2026-07-28.
	tasksExtension = "io.modelcontextprotocol/tasks"
	// metaRelatedTask marks messages and results of a task (2025-11-25).
	metaRelatedTask = "io.modelcontextprotocol/related-task"
	// tasksVersion is the first legacy version with tasks.
	tasksVersion = "2025-11-25"
	// taskPollInterval is the polling interval suggested to agents.
	taskPollInterval = 2 * time.Second
)

const (
	defaultTasksPerPrincipal = 32
	defaultTaskRetention     = time.Hour
	defaultTaskResultBytes   = 4 << 20
)

type taskStatus string

const (
	taskWorking       taskStatus = "working"
	taskInputRequired taskStatus = "input_required"
	taskCompleted     taskStatus = "completed"
	taskFailed        taskStatus = "failed"
	taskCancelled     taskStatus = "cancelled"
)

func (st taskStatus) terminal() bool {
	return st == taskCompleted || st == taskFailed || st == taskCancelled
}

// task is one tools/call run as a task.
type task struct {
	id        string
	owner     string // taskOwner of the principal
	principal principal.Principal
	server    string
	tool      string
	created   time.Time
	cancel    context.CancelFunc
	s         *Session // the task session

	mu        sync.Mutex
	status    taskStatus
	message   string
	updated   time.Time
	ended     time.Time
	result    json.RawMessage // completed
	err       *jsonrpc.Error  // failed
	inputs    []*taskInput    // the call's requests to the client, pending
	changed   chan struct{}   // closed and replaced on every change
	delivered bool
	expiry    *time.Timer
	// deliver hands the call's result to a principal, through the
	// delivery check (session.go); nil for results the gateway answered
	// itself (a denial, gateway_capabilities), which go as they are.
	deliver func(ctx context.Context, to principal.Principal) (any, *jsonrpc.Error)
	// notify passes the call's notifications (progress, log messages)
	// to the agent's session while it lasts (nil: dropped).
	notify func(*jsonrpc.Message)
}

// taskInput is a request of the call to the client, waiting for the
// agent's answer.
type taskInput struct {
	id      json.RawMessage // in the task session
	method  string
	params  json.RawMessage
	claimed bool // being asked over an agent's tasks/result
}

// key is the input's key in inputRequests and inputResponses.
func (in *taskInput) key() string {
	var k string
	if json.Unmarshal(in.id, &k) != nil {
		return string(in.id)
	}
	return k
}

// taskStore holds the tasks by id.
type taskStore struct {
	mu    sync.Mutex
	tasks map[string]*task
}

// taskOwner identifies the principal a task belongs to: issuer and
// subject (the local user), and the client certificate if any.
func taskOwner(p principal.Principal) string {
	k := principalKey(p)
	if p.Cert != nil {
		k += "\x00" + p.Cert.Thumbprint
	}
	return k
}

// touch records a change; t.mu must be held.
func (t *task) touch() {
	t.updated = time.Now()
	close(t.changed)
	t.changed = make(chan struct{})
}

// wire is the task as MCP 2025-11-25 describes it.
func (t *task) wire(retention time.Duration) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]any{
		"taskId":        t.id,
		"status":        t.status,
		"ttl":           retention.Milliseconds(),
		"createdAt":     t.created.UTC().Format(time.RFC3339Nano),
		"lastUpdatedAt": t.updated.UTC().Format(time.RFC3339Nano),
		"pollInterval":  taskPollInterval.Milliseconds(),
	}
	if t.message != "" {
		out["statusMessage"] = t.message
	}
	return out
}

// wireModern is the task as the tasks extension of MCP 2026-07-28
// describes it; detailed adds what its status carries (the input
// requests, the result, the error).
func (t *task) wireModern(retention time.Duration, detailed bool) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]any{
		"taskId":         t.id,
		"status":         t.status,
		"ttlMs":          retention.Milliseconds(),
		"createdAt":      t.created.UTC().Format(time.RFC3339Nano),
		"lastUpdatedAt":  t.updated.UTC().Format(time.RFC3339Nano),
		"pollIntervalMs": taskPollInterval.Milliseconds(),
	}
	if t.message != "" {
		out["statusMessage"] = t.message
	}
	if !detailed {
		return out
	}
	switch t.status {
	case taskInputRequired:
		reqs := map[string]any{}
		for _, in := range t.inputs {
			r := map[string]any{"method": in.method}
			if len(in.params) > 0 {
				r["params"] = withoutMeta(in.params)
			}
			reqs[in.key()] = r
		}
		out["inputRequests"] = reqs
	case taskCompleted:
		out["result"] = taskResultOf(t.result)
	case taskFailed:
		out["error"] = t.err
	}
	return out
}

// taskResultOf is a call's result as a modern task carries it.
func taskResultOf(raw json.RawMessage) map[string]json.RawMessage {
	var res map[string]json.RawMessage
	_ = json.Unmarshal(raw, &res)
	if res == nil {
		res = map[string]json.RawMessage{}
	}
	res["resultType"] = json.RawMessage(`"complete"`)
	return res
}

// withoutMeta drops the gateway's request _meta (related request, task)
// from params passed on as an input request.
func withoutMeta(params json.RawMessage) json.RawMessage {
	var p map[string]json.RawMessage
	if json.Unmarshal(params, &p) != nil {
		return params
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(p["_meta"], &meta) == nil {
		delete(meta, metaRelatedTask)
		if len(meta) == 0 {
			delete(p, "_meta")
		} else {
			p["_meta"], _ = json.Marshal(meta)
		}
	}
	out, err := json.Marshal(p)
	if err != nil {
		return params
	}
	return out
}

// taskConn is the task session's client: it records the call's requests
// to the client as the task's inputs and passes notifications on.
type taskConn struct{ t *task }

func (c taskConn) Read() (*jsonrpc.Message, error) { return nil, io.EOF }
func (c taskConn) Close() error                    { return nil }

func (c taskConn) Write(m *jsonrpc.Message) error {
	t := c.t
	switch {
	case m.IsRequest():
		t.mu.Lock()
		t.inputs = append(t.inputs, &taskInput{id: m.ID, method: m.Method, params: m.Params})
		if !t.status.terminal() {
			t.status = taskInputRequired
		}
		t.touch()
		t.mu.Unlock()
	case m.Method == "notifications/cancelled":
		// The call no longer waits for an input (it timed out).
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		_ = json.Unmarshal(m.Params, &p)
		t.mu.Lock()
		t.inputs = slices.DeleteFunc(t.inputs, func(in *taskInput) bool { return string(in.id) == string(p.RequestID) })
		if len(t.inputs) == 0 && t.status == taskInputRequired {
			t.status = taskWorking
		}
		t.touch()
		t.mu.Unlock()
	case m.IsNotification():
		t.mu.Lock()
		notify := t.notify
		t.mu.Unlock()
		if notify != nil {
			notify(m)
		}
	}
	return nil
}

// answer gives the call the agent's answer to an input (resp carries the
// input's id).
func (t *task) answer(in *taskInput, resp *jsonrpc.Message) {
	t.mu.Lock()
	n := len(t.inputs)
	t.inputs = slices.DeleteFunc(t.inputs, func(x *taskInput) bool { return x == in })
	found := len(t.inputs) < n
	if found {
		if len(t.inputs) == 0 && t.status == taskInputRequired {
			t.status = taskWorking
		}
		t.touch()
	}
	t.mu.Unlock()
	if found {
		t.s.dispatch(resp)
	}
}

func (t *task) setDelivery(deliver func(context.Context, principal.Principal) (any, *jsonrpc.Error)) {
	t.mu.Lock()
	t.deliver = deliver
	t.mu.Unlock()
}

// outcome is the completed task's result for principal to, as it is
// delivered to it now (decision D20): asked of policy again, with the
// obligations of that decision applied.
func (t *task) outcome(ctx context.Context, to principal.Principal) (json.RawMessage, *jsonrpc.Error) {
	t.mu.Lock()
	raw, deliver := t.result, t.deliver
	t.mu.Unlock()
	if deliver == nil {
		return raw, nil
	}
	res, rpcErr := deliver(ctx, to)
	if rpcErr != nil {
		return nil, rpcErr
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, rpcError(jsonrpc.CodeInternalError, "internal error")
	}
	return out, nil
}

// claim returns an input no agent's tasks/result is asking for yet, and
// marks it asked (nil: none).
func (t *task) claim() *taskInput {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, in := range t.inputs {
		if !in.claimed {
			in.claimed = true
			return in
		}
	}
	return nil
}

func (t *task) unclaim(in *taskInput) {
	t.mu.Lock()
	in.claimed = false
	t.touch()
	t.mu.Unlock()
}

// wantsTask reports whether the tools/call params of a legacy session
// ask for a task, and whether the task parameter is well formed.
func (s *Session) wantsTask(params map[string]json.RawMessage) (bool, *jsonrpc.Error) {
	raw, ok := params["task"]
	if !ok || !s.offersTasks() {
		return false, nil
	}
	var p struct {
		TTL *float64 `json:"ttl"`
	}
	if json.Unmarshal(raw, &p) != nil || (p.TTL != nil && *p.TTL < 0) {
		return false, rpcError(jsonrpc.CodeInvalidParams, "invalid params: task")
	}
	return true, nil
}

// offersTasks reports whether the legacy session negotiated a version
// with tasks.
func (s *Session) offersTasks() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.modern && s.task == nil && s.version >= tasksVersion
}

// agentWantsTask reports whether a modern agent's request declares the
// tasks extension: its tools/call then runs as a task.
func (s *Session) agentWantsTask() bool {
	var ext map[string]json.RawMessage
	if json.Unmarshal(s.clientCaps["extensions"], &ext) != nil {
		return false
	}
	_, ok := ext[tasksExtension]
	return ok
}

// toolsCall serves a legacy session's tools/call: as a task if it asks
// for one, else as a call.
func (s *Session) toolsCall(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	var params map[string]json.RawMessage
	if json.Unmarshal(m.Params, &params) == nil {
		want, rpcErr := s.wantsTask(params)
		if rpcErr != nil {
			return nil, rpcErr
		}
		if want {
			t, rpcErr := s.startTask(m, params)
			if rpcErr != nil {
				return nil, rpcErr
			}
			return map[string]any{"task": t.wire(s.r.taskRetention())}, nil
		}
	}
	return s.call(ctx, m)
}

// agentTask starts a modern agent's tools/call as a task and returns the
// task result.
func (s *Session) agentTask(m *jsonrpc.Message) (any, *jsonrpc.Error) {
	var params map[string]json.RawMessage
	if json.Unmarshal(m.Params, &params) != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params")
	}
	t, rpcErr := s.startTask(m, params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	out := t.wireModern(s.r.taskRetention(), false)
	out["resultType"] = "task"
	return out, nil
}

// startTask runs the tools/call m (params decoded) in a task session.
func (s *Session) startTask(m *jsonrpc.Message, params map[string]json.RawMessage) (*task, *jsonrpc.Error) {
	r := s.r
	p := s.snapshotPrincipal()
	if err := jsonrpc.CheckKeys(m.Params); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: "+err.Error())
	}
	var name string
	_ = json.Unmarshal(params["name"], &name)
	server, tool, _ := s.endpoint().resolveName(name)

	inner := maps.Clone(params)
	delete(inner, "task")
	if s.modern {
		// The agent's protocol fields belong to its request, not to the
		// call the task session makes.
		var meta map[string]json.RawMessage
		if json.Unmarshal(inner["_meta"], &meta) == nil {
			maps.DeleteFunc(meta, func(k string, _ json.RawMessage) bool {
				return strings.HasPrefix(k, "io.modelcontextprotocol/")
			})
			if len(meta) == 0 {
				delete(inner, "_meta")
			} else {
				inner["_meta"], _ = json.Marshal(meta)
			}
		}
	}
	raw, err := json.Marshal(inner)
	if err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params")
	}
	call := &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Method: m.Method, Params: raw}

	now := time.Now()
	ctx, cancel := context.WithCancel(r.taskContext())
	t := &task{id: rand.Text(), owner: taskOwner(p), principal: p, server: server, tool: tool,
		created: now, updated: now, cancel: cancel, status: taskWorking, changed: make(chan struct{})}
	if err := r.addTask(t); err != nil {
		cancel()
		return nil, limitError(err)
	}

	ts := newSession(r, s.endpoint(), taskConn{t}, p)
	ts.task = t
	ts.ctx = ctx
	s.mu.Lock()
	ts.clientCaps = s.clientCaps
	ts.version = s.version
	ts.logLevel = s.logLevel
	maps.Copy(ts.annotations, s.annotations)
	ts.declared = maps.Clone(s.declared)
	s.mu.Unlock()
	ts.vault = s.vault
	t.s = ts
	if !s.modern {
		// Progress and log messages of the call go to the session that
		// started it, while it lasts.
		client, alive := s.client, s.ctx
		t.notify = func(n *jsonrpc.Message) {
			if alive.Err() == nil {
				_ = client.Write(n)
			}
		}
	}
	r.Audit.Note("mcp-task", map[string]string{"event": "created", "task": t.id,
		"principal": p.Sub, "transport": string(p.Transport), "session": p.SessionID, "server": server, "tool": tool})

	go func() {
		defer ts.release()
		defer cancel()
		result, rpcErr := ts.call(withRequest(ctx, m.ID), call)
		r.finishTask(t, result, rpcErr)
	}()
	return t, nil
}

// finishTask records the call's outcome.
func (r *Router) finishTask(t *task, result any, rpcErr *jsonrpc.Error) {
	var raw json.RawMessage
	if rpcErr == nil {
		var err error
		if raw, err = json.Marshal(result); err != nil {
			rpcErr = rpcError(jsonrpc.CodeInternalError, "internal error")
		} else if max := r.settings().TaskMaxResultBytes; len(raw) > max {
			rpcErr = rpcError(jsonrpc.CodeInternalError, "mcp-gateway: the result exceeds tasks.max_result_bytes ("+strconv.Itoa(max)+")")
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status.terminal() {
		return // cancelled meanwhile
	}
	if rpcErr != nil {
		t.status, t.err = taskFailed, rpcErr
	} else {
		t.status, t.result = taskCompleted, raw
	}
	t.inputs = nil
	r.ended(t)
}

// ended starts the task's retention; t.mu must be held.
func (r *Router) ended(t *task) {
	t.ended = time.Now()
	t.touch()
	t.expiry = time.AfterFunc(r.taskRetention(), func() { r.expireTask(t) })
}

// expireTask drops a task whose retention is over.
func (r *Router) expireTask(t *task) {
	r.tasks.mu.Lock()
	if r.tasks.tasks[t.id] == t {
		delete(r.tasks.tasks, t.id)
	}
	r.tasks.mu.Unlock()
	t.mu.Lock()
	unfetched := !t.delivered && t.status != taskCancelled
	t.mu.Unlock()
	if unfetched {
		r.Audit.Note("mcp-task", map[string]string{"event": "expired", "task": t.id,
			"principal": t.principal.Sub, "transport": string(t.principal.Transport), "server": t.server, "tool": t.tool,
			"reason": "result not fetched"})
	}
}

// addTask stores t, unless its principal is at limits.tasks_per_principal.
func (r *Router) addTask(t *task) *LimitError {
	max := r.settings().MaxTasksPerPrincipal
	r.tasks.mu.Lock()
	if r.tasks.tasks == nil {
		r.tasks.tasks = map[string]*task{}
	}
	n := 0
	for _, o := range r.tasks.tasks {
		if o.owner == t.owner {
			n++
		}
	}
	if n >= max {
		r.tasks.mu.Unlock()
		e := &LimitError{Limit: "tasks_per_principal", Max: max}
		r.refused(t.principal, e)
		return e
	}
	r.tasks.tasks[t.id] = t
	r.tasks.mu.Unlock()
	return nil
}

// taskOf returns the session principal's task named by params.taskId; a
// task of another principal is not found either.
func (s *Session) taskOf(params json.RawMessage) (*task, *jsonrpc.Error) {
	var p struct {
		TaskID string `json:"taskId"`
	}
	if json.Unmarshal(params, &p) != nil || p.TaskID == "" {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: taskId")
	}
	owner := taskOwner(s.snapshotPrincipal())
	s.r.tasks.mu.Lock()
	t := s.r.tasks.tasks[p.TaskID]
	s.r.tasks.mu.Unlock()
	if t == nil || t.owner != owner {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "task not found")
	}
	return t, nil
}

// deliver records that the task's outcome reached the agent.
func (r *Router) deliver(t *task) {
	t.mu.Lock()
	first := !t.delivered && (t.status == taskCompleted || t.status == taskFailed)
	if first {
		t.delivered = true
	}
	t.mu.Unlock()
	if first {
		p := t.principal
		r.Audit.Note("mcp-task", map[string]string{"event": "delivered", "task": t.id,
			"principal": p.Sub, "transport": string(p.Transport), "server": t.server, "tool": t.tool})
	}
}

// cancelTask cancels the task's call: the server is told as when the
// agent cancels a call.
func (r *Router) cancelTask(t *task, by string) *jsonrpc.Error {
	t.mu.Lock()
	if t.status.terminal() {
		st := t.status
		t.mu.Unlock()
		return rpcError(jsonrpc.CodeInvalidParams, "cannot cancel a task in status "+string(st))
	}
	t.status, t.message, t.inputs = taskCancelled, "cancelled by "+by, nil
	r.ended(t)
	t.mu.Unlock()
	t.cancel()
	p := t.principal
	r.Audit.Note("mcp-task", map[string]string{"event": "cancelled", "task": t.id,
		"principal": p.Sub, "transport": string(p.Transport), "server": t.server, "tool": t.tool, "reason": "cancelled by " + by})
	return nil
}

// --- MCP 2025-11-25 --------------------------------------------------------

func (s *Session) taskGet(_ context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	t, rpcErr := s.taskOf(m.Params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return t.wire(s.r.taskRetention()), nil
}

func (s *Session) taskList(context.Context, *jsonrpc.Message) (any, *jsonrpc.Error) {
	owner := taskOwner(s.snapshotPrincipal())
	s.r.tasks.mu.Lock()
	var ts []*task
	for _, t := range s.r.tasks.tasks {
		if t.owner == owner {
			ts = append(ts, t)
		}
	}
	s.r.tasks.mu.Unlock()
	slices.SortFunc(ts, func(a, b *task) int { return a.created.Compare(b.created) })
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.wire(s.r.taskRetention()))
	}
	return map[string]any{"tasks": out}, nil
}

func (s *Session) taskCancel(_ context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	t, rpcErr := s.taskOf(m.Params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if rpcErr := s.r.cancelTask(t, "the agent"); rpcErr != nil {
		return nil, rpcErr
	}
	return t.wire(s.r.taskRetention()), nil
}

// taskResult serves tasks/result: it asks the agent what the call asks
// of the client, on this request's stream, and answers the call's result
// once the task ended.
func (s *Session) taskResult(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	t, rpcErr := s.taskOf(m.Params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	for {
		if in := t.claim(); in != nil {
			params := withRelatedTask(in.params, t.id)
			resp, err := s.requestClient(ctx, in.method, params, requestOf(ctx))
			if ctx.Err() != nil {
				t.unclaim(in)
				return nil, rpcError(jsonrpc.CodeInternalError, "cancelled")
			}
			answer := &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: in.id}
			switch e := err.(type) {
			case nil:
				answer.Result = resp.Result
			case *jsonrpc.Error:
				answer.Error = e
			default:
				answer.Error = rpcError(jsonrpc.CodeInternalError, "client unavailable")
			}
			t.answer(in, answer)
			continue
		}
		t.mu.Lock()
		st, terr, changed := t.status, t.err, t.changed
		t.mu.Unlock()
		switch st {
		case taskCompleted:
			res, rpcErr := t.outcome(ctx, s.snapshotPrincipal())
			if rpcErr != nil {
				return nil, rpcErr
			}
			s.r.deliver(t)
			return withRelatedTask(res, t.id), nil
		case taskFailed:
			s.r.deliver(t)
			return nil, terr
		case taskCancelled:
			return nil, rpcError(jsonrpc.CodeInternalError, "task cancelled")
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, rpcError(jsonrpc.CodeInternalError, "cancelled")
		}
	}
}

// withRelatedTask adds the related-task _meta to a JSON object.
func withRelatedTask(raw json.RawMessage, id string) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		obj = map[string]json.RawMessage{}
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(obj["_meta"], &meta) != nil || meta == nil {
		meta = map[string]json.RawMessage{}
	}
	meta[metaRelatedTask], _ = json.Marshal(map[string]string{"taskId": id})
	obj["_meta"], _ = json.Marshal(meta)
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// --- MCP 2026-07-28, tasks extension ------------------------------------

func (s *Session) agentTaskGet(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	t, rpcErr := s.taskOf(m.Params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	out := t.wireModern(s.r.taskRetention(), true)
	if out["status"] == taskCompleted {
		res, derr := t.outcome(ctx, s.snapshotPrincipal())
		if derr != nil {
			delete(out, "result")
			out["status"], out["error"] = taskFailed, derr
		} else {
			out["result"] = taskResultOf(res)
		}
	}
	s.r.deliver(t)
	return out, nil
}

func (s *Session) agentTaskUpdate(_ context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	t, rpcErr := s.taskOf(m.Params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	var p struct {
		InputResponses map[string]json.RawMessage `json:"inputResponses"`
	}
	if json.Unmarshal(m.Params, &p) != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: inputResponses")
	}
	t.mu.Lock()
	byKey := map[string]*taskInput{}
	for _, in := range t.inputs {
		byKey[in.key()] = in
	}
	t.mu.Unlock()
	for k, v := range p.InputResponses {
		// Answers to inputs the call no longer waits for are dropped.
		if in := byKey[k]; in != nil {
			t.answer(in, &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: in.id, Result: v})
		}
	}
	return map[string]any{}, nil
}

func (s *Session) agentTaskCancel(_ context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	t, rpcErr := s.taskOf(m.Params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if rpcErr := s.r.cancelTask(t, "the agent"); rpcErr != nil {
		return nil, rpcErr
	}
	return map[string]any{}, nil
}

// --- advertising --------------------------------------------------------

// taskCapability is the server capability of MCP 2025-11-25 tasks.
func taskCapability() json.RawMessage {
	return json.RawMessage(`{"list":{},"cancel":{},"requests":{"tools":{"call":{}}}}`)
}

// withTaskCapability adds the tasks capability to an initialize result's
// capabilities if the session offers tasks.
func (s *Session) withTaskCapability(res map[string]any) map[string]any {
	if !s.offersTasks() {
		return res
	}
	raw, err := json.Marshal(res["capabilities"])
	var caps map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &caps) != nil || caps == nil {
		caps = map[string]json.RawMessage{}
	}
	caps["tasks"] = taskCapability()
	res["capabilities"] = caps
	return res
}

// withTaskSupport marks each tool of a tools/list as one that can run as
// a task (2025-11-25: execution.taskSupport "optional"); toward a modern
// agent it drops the field, which MCP 2026-07-28 removed.
func (s *Session) withTaskSupport(tools []map[string]json.RawMessage) {
	offer := s.offersTasks()
	for _, tool := range tools {
		var exec map[string]json.RawMessage
		_ = json.Unmarshal(tool["execution"], &exec)
		if offer {
			if exec == nil {
				exec = map[string]json.RawMessage{}
			}
			exec["taskSupport"] = json.RawMessage(`"optional"`)
		} else {
			if exec == nil {
				continue
			}
			delete(exec, "taskSupport")
		}
		if len(exec) == 0 {
			delete(tool, "execution")
			continue
		}
		tool["execution"], _ = json.Marshal(exec)
	}
}

// --- router -------------------------------------------------------------

// taskContext is the context task sessions run in: it ends with the
// gateway, not with an agent's connection.
func (r *Router) taskContext() context.Context {
	r.init()
	return r.tasksCtx
}

// endTasks cancels the calls of all tasks (the gateway stops).
func (r *Router) endTasks() {
	r.init()
	r.stopTasks()
}

func (r *Router) taskRetention() time.Duration { return r.settings().TaskRetention }

// modernCapabilities are an endpoint's capabilities toward a modern
// agent: with the tasks extension, without the legacy tasks capability.
func modernCapabilities(caps any) map[string]json.RawMessage {
	raw, err := json.Marshal(caps)
	var out map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &out) != nil || out == nil {
		out = map[string]json.RawMessage{}
	}
	delete(out, "tasks")
	var ext map[string]json.RawMessage
	if json.Unmarshal(out["extensions"], &ext) != nil || ext == nil {
		ext = map[string]json.RawMessage{}
	}
	ext[tasksExtension] = json.RawMessage(`{}`)
	out["extensions"], _ = json.Marshal(ext)
	return out
}

// --- control API --------------------------------------------------------

// TaskInfo describes a task for the control API (GET /v1/tasks).
type TaskInfo struct {
	ID        string              `json:"id"`
	Server    string              `json:"server"`
	Tool      string              `json:"tool"`
	Sub       string              `json:"sub"`
	Issuer    string              `json:"iss,omitempty"`
	UID       *uint32             `json:"uid,omitempty"`
	Transport principal.Transport `json:"transport"`
	// Status is working, input_required, completed, failed or cancelled.
	Status  string     `json:"status"`
	Message string     `json:"status_message,omitempty"`
	Created time.Time  `json:"created"`
	Updated time.Time  `json:"updated"`
	Ended   *time.Time `json:"ended,omitempty"`
	// Delivered tells that the agent fetched the result.
	Delivered bool `json:"delivered"`
}

// ErrNoTask and ErrTaskEnded are CancelTask's errors.
var (
	ErrNoTask    = errors.New("no such task")
	ErrTaskEnded = errors.New("the task has ended")
)

// Tasks lists the agents' tasks, running and kept, oldest first.
func (r *Router) Tasks() []TaskInfo {
	r.init()
	r.tasks.mu.Lock()
	ts := make([]*task, 0, len(r.tasks.tasks))
	for _, t := range r.tasks.tasks {
		ts = append(ts, t)
	}
	r.tasks.mu.Unlock()
	slices.SortFunc(ts, func(a, b *task) int { return a.created.Compare(b.created) })
	out := make([]TaskInfo, 0, len(ts))
	for _, t := range ts {
		t.mu.Lock()
		info := TaskInfo{ID: t.id, Server: t.server, Tool: t.tool, Sub: t.principal.Sub, Issuer: t.principal.Issuer,
			UID: t.principal.UID, Transport: t.principal.Transport, Status: string(t.status), Message: t.message,
			Created: t.created, Updated: t.updated, Delivered: t.delivered}
		if !t.ended.IsZero() {
			ended := t.ended
			info.Ended = &ended
		}
		t.mu.Unlock()
		out = append(out, info)
	}
	return out
}

// CancelTask cancels the task id on behalf of by (an administrator, in
// the control API): its call is cancelled as by the agent.
func (r *Router) CancelTask(id, by string) error {
	r.init()
	r.tasks.mu.Lock()
	t := r.tasks.tasks[id]
	r.tasks.mu.Unlock()
	if t == nil {
		return ErrNoTask
	}
	if r.cancelTask(t, by) != nil {
		return ErrTaskEnded
	}
	return nil
}
