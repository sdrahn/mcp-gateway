package router

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// taskWire is a task as tasks/get answers it, in either era.
type taskWire struct {
	TaskID        string                     `json:"taskId"`
	Status        string                     `json:"status"`
	StatusMessage string                     `json:"statusMessage"`
	TTL           *int64                     `json:"ttl"`
	TTLMs         *int64                     `json:"ttlMs"`
	ResultType    string                     `json:"resultType"`
	InputRequests map[string]json.RawMessage `json:"inputRequests"`
	Result        json.RawMessage            `json:"result"`
	Error         *jsonrpc.Error             `json:"error"`
}

func taskOfResult(t *testing.T, m *jsonrpc.Message) taskWire {
	t.Helper()
	var r struct {
		Task taskWire `json:"task"`
	}
	if m.Error != nil || json.Unmarshal(m.Result, &r) != nil || r.Task.TaskID == "" {
		t.Fatalf("want a CreateTaskResult, got %+v (%s)", m.Error, m.Result)
	}
	return r.Task
}

func decodeTask(t *testing.T, m *jsonrpc.Message) taskWire {
	t.Helper()
	var w taskWire
	if m.Error != nil || json.Unmarshal(m.Result, &w) != nil || w.TaskID == "" {
		t.Fatalf("want a task, got %+v (%s)", m.Error, m.Result)
	}
	return w
}

// awaitStatus polls tasks/get until the task has status want.
func awaitStatus(t *testing.T, c *client, id *int, taskID, want string, params func(map[string]any) map[string]any) taskWire {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		*id++
		p := map[string]any{"taskId": taskID}
		if params != nil {
			p = params(p)
		}
		w := decodeTask(t, c.roundTrip(*id, "tasks/get", p))
		if w.Status == want {
			return w
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s: status %q, want %q", taskID, w.Status, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sameUser is p in a new session.
func sameUser(p principal.Principal, session string) principal.Principal {
	p.SessionID = session
	return p
}

// A legacy client of 2025-11-25 is offered tasks: the capability, and
// every tool may run as one.
func TestTasksAdvertised(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connectVersion(t, r, alice(), "", nil, nil, "2025-11-25")
	var init struct {
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	_ = json.Unmarshal(c.init.Result, &init)
	if string(init.Capabilities["tasks"]) != `{"list":{},"cancel":{},"requests":{"tools":{"call":{}}}}` {
		t.Fatalf("tasks capability: %s", init.Capabilities["tasks"])
	}
	var list struct {
		Tools []struct {
			Name      string `json:"name"`
			Execution struct {
				TaskSupport string `json:"taskSupport"`
			} `json:"execution"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(c.roundTrip(1, "tools/list", map[string]any{}).Result, &list)
	if len(list.Tools) == 0 {
		t.Fatal("no tools")
	}
	for _, tool := range list.Tools {
		if tool.Execution.TaskSupport != "optional" {
			t.Errorf("%s: taskSupport %q", tool.Name, tool.Execution.TaskSupport)
		}
	}

	// Older clients are not.
	old := connect(t, r, alice(), "", nil)
	init.Capabilities = nil
	_ = json.Unmarshal(old.init.Result, &init)
	if _, ok := init.Capabilities["tasks"]; ok {
		t.Fatalf("tasks offered to 2025-06-18: %s", old.init.Result)
	}
	if strings.Contains(string(old.roundTrip(1, "tools/list", map[string]any{}).Result), "taskSupport") {
		t.Fatal("taskSupport listed for 2025-06-18")
	}
}

// A task outlives its agent's session: the call completes at the server
// and the result is fetched in a new session of the same user, once.
func TestTaskOutlivesSession(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	p := alice()
	c := connectVersion(t, r, p, "fs", nil, nil, "2025-11-25")
	created := taskOfResult(t, c.roundTrip(1, "tools/call", map[string]any{"name": "commit", "task": map[string]any{"ttl": 1000}}))
	if created.Status != "working" || created.TTL == nil || *created.TTL != defaultTaskRetention.Milliseconds() {
		t.Fatalf("created: %+v", created)
	}
	id := 1
	awaitStatus(t, c, &id, created.TaskID, "working", nil)
	c.close()

	close(l.started("fs")[0].commit)
	c2 := connectVersion(t, r, sameUser(p, p.SessionID+"-2"), "fs", nil, nil, "2025-11-25")
	id = 10
	awaitStatus(t, c2, &id, created.TaskID, "completed", nil)
	m := c2.roundTrip(20, "tasks/result", map[string]any{"taskId": created.TaskID})
	if text, isErr := toolText(t, m); isErr || text != "committed" {
		t.Fatalf("result: %q %v", text, isErr)
	}
	if !strings.Contains(string(m.Result), `"io.modelcontextprotocol/related-task":{"taskId":"`+created.TaskID+`"}`) {
		t.Fatalf("result lacks related-task: %s", m.Result)
	}
	var list struct {
		Tasks []taskWire `json:"tasks"`
	}
	_ = json.Unmarshal(c2.roundTrip(21, "tasks/list", map[string]any{}).Result, &list)
	if len(list.Tasks) != 1 || list.Tasks[0].TaskID != created.TaskID {
		t.Fatalf("tasks/list: %+v", list)
	}

	// Another user does not see it.
	bob := principal.Principal{Sub: "bob", Transport: principal.TransportUnix, SessionID: "bob-1"}
	b := connectVersion(t, r, bob, "fs", nil, nil, "2025-11-25")
	for _, method := range []string{"tasks/get", "tasks/result", "tasks/cancel"} {
		if m := b.roundTrip(1, method, map[string]any{"taskId": created.TaskID}); m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
			t.Fatalf("bob %s: %+v", method, m)
		}
	}
	_ = json.Unmarshal(b.roundTrip(2, "tasks/list", map[string]any{}).Result, &list)
	if len(list.Tasks) != 0 {
		t.Fatalf("bob lists %+v", list)
	}
}

// An approval makes the task input_required; tasks/result asks the
// agent and the call goes on.
func TestTaskApproval(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connectVersion(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}}, nil, "2025-11-25")
	created := taskOfResult(t, c.roundTrip(1, "tools/call", map[string]any{"name": "write_file", "task": map[string]any{}}))
	id := 1
	awaitStatus(t, c, &id, created.TaskID, "input_required", nil)

	c.send(10, "tasks/result", map[string]any{"taskId": created.TaskID})
	el := c.read()
	if el.Method != "elicitation/create" || !strings.Contains(string(el.Params), `"io.modelcontextprotocol/related-task":{"taskId":"`+created.TaskID+`"}`) {
		t.Fatalf("want the approval form of the task, got %+v (%s)", el, el.Params)
	}
	if strings.Contains(string(el.Params), `"session"`) {
		t.Fatalf("a task's approval offers the session scope: %s", el.Params)
	}
	c.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}))
	m := c.read()
	if m.Key() != "10" {
		t.Fatalf("want the tasks/result response, got %+v", m)
	}
	if text, isErr := toolText(t, m); isErr || text != "fs did write_file" {
		t.Fatalf("result: %q %v", text, isErr)
	}
}

// Cancelling a task cancels its call at the server.
func TestTaskCancel(t *testing.T) {
	r, l := testRouter(t, 0)
	c := connectVersion(t, r, alice(), "fs", nil, nil, "2025-11-25")
	created := taskOfResult(t, c.roundTrip(1, "tools/call", map[string]any{"name": "slow", "task": map[string]any{}}))
	time.Sleep(50 * time.Millisecond) // let the call reach the backend
	w := decodeTask(t, c.roundTrip(2, "tasks/cancel", map[string]any{"taskId": created.TaskID}))
	if w.Status != "cancelled" {
		t.Fatalf("cancel: %+v", w)
	}
	select {
	case <-l.started("fs")[0].cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("backend not told about cancellation")
	}
	if m := c.roundTrip(3, "tasks/cancel", map[string]any{"taskId": created.TaskID}); m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("second cancel: %+v", m)
	}
	if m := c.roundTrip(4, "tasks/result", map[string]any{"taskId": created.TaskID}); m.Error == nil {
		t.Fatalf("result of a cancelled task: %+v", m)
	}
}

// limits.tasks_per_principal, tasks.retention and tasks.max_result_bytes.
func TestTaskLimits(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.MaxTasksPerPrincipal, r.TaskRetention, r.TaskMaxResultBytes = 1, 100*time.Millisecond, 100
	c := connectVersion(t, r, alice(), "fs", nil, nil, "2025-11-25")

	big := taskOfResult(t, c.roundTrip(1, "tools/call", map[string]any{"name": "read_big", "task": map[string]any{}}))
	if m := c.roundTrip(2, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}); m.Error == nil ||
		!strings.Contains(m.Error.Message, "task limit reached (1)") {
		t.Fatalf("second task: %+v", m)
	}
	id := 2
	awaitStatus(t, c, &id, big.TaskID, "failed", nil)
	m := c.roundTrip(10, "tasks/result", map[string]any{"taskId": big.TaskID})
	if m.Error == nil || !strings.Contains(m.Error.Message, "tasks.max_result_bytes") {
		t.Fatalf("result of a too large task: %+v", m)
	}

	// After its retention the task is gone, and makes room.
	deadline := time.Now().Add(3 * time.Second)
	for c.roundTrip(11, "tasks/get", map[string]any{"taskId": big.TaskID}).Error == nil {
		if time.Now().After(deadline) {
			t.Fatal("task kept past its retention")
		}
		time.Sleep(20 * time.Millisecond)
	}
	created := taskOfResult(t, c.roundTrip(12, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}))
	id = 12
	awaitStatus(t, c, &id, created.TaskID, "completed", nil)
}

// A modern agent that declares the tasks extension gets a task for its
// tools/call, polls it with tasks/get and answers its inputs with
// tasks/update.
func TestAgentTask(t *testing.T) {
	r, _ := testRouter(t, 0)
	caps := map[string]any{metaClientCapabilities: map[string]any{
		"elicitation": map[string]any{"form": map[string]any{}},
		"extensions":  map[string]any{tasksExtension: map[string]any{}},
	}}
	c := agent(t, r, alice(), "fs")

	m := c.roundTrip(1, "server/discover", withAgentMeta(nil, caps))
	if !strings.Contains(string(m.Result), `"extensions":{"`+tasksExtension+`":{}}`) || strings.Contains(string(m.Result), `"tasks":{`) {
		t.Fatalf("discover: %s", m.Result)
	}

	m = c.roundTrip(2, "tools/call", withAgentMeta(map[string]any{"name": "write_file"}, caps))
	created := decodeTask(t, m)
	// The approval may already be asked for when the task is answered.
	if created.ResultType != "task" || (created.Status != "working" && created.Status != "input_required") || created.TTLMs == nil {
		t.Fatalf("created: %s", m.Result)
	}
	id := 2
	meta := func(p map[string]any) map[string]any { return withAgentMeta(p, caps) }
	w := awaitStatus(t, c, &id, created.TaskID, "input_required", meta)
	if w.ResultType != "complete" || len(w.InputRequests) != 1 {
		t.Fatalf("input_required: %+v", w)
	}
	var key string
	for k, req := range w.InputRequests {
		key = k
		if !strings.Contains(string(req), `"method":"elicitation/create"`) {
			t.Fatalf("input request: %s", req)
		}
	}
	m = c.roundTrip(20, "tasks/update", withAgentMeta(map[string]any{"taskId": created.TaskID,
		"inputResponses": map[string]any{key: map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}}}, caps))
	if m.Error != nil || !strings.Contains(string(m.Result), `"resultType":"complete"`) {
		t.Fatalf("tasks/update: %+v (%s)", m.Error, m.Result)
	}
	id = 20
	w = awaitStatus(t, c, &id, created.TaskID, "completed", meta)
	if !strings.Contains(string(w.Result), `fs did write_file`) || !strings.Contains(string(w.Result), `"resultType":"complete"`) {
		t.Fatalf("result: %s", w.Result)
	}

	// Without the extension, a call is answered as before.
	plain := map[string]any{metaClientCapabilities: map[string]any{}}
	if text, _ := toolText(t, c.roundTrip(30, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, plain))); text != "fs did read_file" {
		t.Fatalf("plain call: %q", text)
	}
	if m := c.roundTrip(31, "tasks/cancel", withAgentMeta(map[string]any{"taskId": created.TaskID}, caps)); m.Error == nil {
		t.Fatalf("cancelled a completed task: %s", m.Result)
	}
}
