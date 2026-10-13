package router

import (
	"encoding/json"
	"errors"
	"slices"
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
		w := decodeTask(t, taskRT(c, *id, "tasks/get", p))
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
	_ = json.Unmarshal(taskRT(c, 1, "tools/list", map[string]any{}).Result, &list)
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
	if strings.Contains(string(taskRT(old, 1, "tools/list", map[string]any{}).Result), "taskSupport") {
		t.Fatal("taskSupport listed for 2025-06-18")
	}
}

// A task outlives its agent's session: the call completes at the server
// and the result is fetched in a new session of the same user, once.
func TestTaskOutlivesSession(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	p := alice()
	c := connectVersion(t, r, p, "fs", nil, nil, "2025-11-25")
	created := taskOfResult(t, taskRT(c, 1, "tools/call", map[string]any{"name": "commit", "task": map[string]any{"ttl": 1000}}))
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
	m := taskRT(c2, 20, "tasks/result", map[string]any{"taskId": created.TaskID})
	if text, isErr := toolText(t, m); isErr || text != "committed" {
		t.Fatalf("result: %q %v", text, isErr)
	}
	if !strings.Contains(string(m.Result), `"io.modelcontextprotocol/related-task":{"taskId":"`+created.TaskID+`"}`) {
		t.Fatalf("result lacks related-task: %s", m.Result)
	}
	var list struct {
		Tasks []taskWire `json:"tasks"`
	}
	_ = json.Unmarshal(taskRT(c2, 21, "tasks/list", map[string]any{}).Result, &list)
	if len(list.Tasks) != 1 || list.Tasks[0].TaskID != created.TaskID {
		t.Fatalf("tasks/list: %+v", list)
	}

	// Another user does not see it.
	bob := principal.Principal{Sub: "bob", Transport: principal.TransportUnix, SessionID: "bob-1"}
	b := connectVersion(t, r, bob, "fs", nil, nil, "2025-11-25")
	for _, method := range []string{"tasks/get", "tasks/result", "tasks/cancel"} {
		if m := taskRT(b, 1, method, map[string]any{"taskId": created.TaskID}); m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
			t.Fatalf("bob %s: %+v", method, m)
		}
	}
	_ = json.Unmarshal(taskRT(b, 2, "tasks/list", map[string]any{}).Result, &list)
	if len(list.Tasks) != 0 {
		t.Fatalf("bob lists %+v", list)
	}
}

// An approval makes the task input_required; tasks/result asks the
// agent and the call goes on.
func TestTaskApproval(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connectVersion(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}}, nil, "2025-11-25")
	created := taskOfResult(t, taskRT(c, 1, "tools/call", map[string]any{"name": "write_file", "task": map[string]any{}}))
	id := 1
	awaitStatus(t, c, &id, created.TaskID, "input_required", nil)

	c.send(10, "tasks/result", map[string]any{"taskId": created.TaskID})
	el := readSkipping(c)
	if el.Method != "elicitation/create" || !strings.Contains(string(el.Params), `"io.modelcontextprotocol/related-task":{"taskId":"`+created.TaskID+`"}`) {
		t.Fatalf("want the approval form of the task, got %+v (%s)", el, el.Params)
	}
	if strings.Contains(string(el.Params), `"session"`) {
		t.Fatalf("a task's approval offers the session scope: %s", el.Params)
	}
	c.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}))
	m := readSkipping(c)
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
	created := taskOfResult(t, taskRT(c, 1, "tools/call", map[string]any{"name": "slow", "task": map[string]any{}}))
	time.Sleep(50 * time.Millisecond) // let the call reach the backend
	w := decodeTask(t, taskRT(c, 2, "tasks/cancel", map[string]any{"taskId": created.TaskID}))
	if w.Status != "cancelled" {
		t.Fatalf("cancel: %+v", w)
	}
	select {
	case <-l.started("fs")[0].cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("backend not told about cancellation")
	}
	if m := taskRT(c, 3, "tasks/cancel", map[string]any{"taskId": created.TaskID}); m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("second cancel: %+v", m)
	}
	if m := taskRT(c, 4, "tasks/result", map[string]any{"taskId": created.TaskID}); m.Error == nil {
		t.Fatalf("result of a cancelled task: %+v", m)
	}
}

// limits.tasks_per_principal, tasks.retention and tasks.max_result_bytes.
func TestTaskLimits(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.MaxTasksPerPrincipal, r.TaskRetention, r.TaskMaxResultBytes = 1, 100*time.Millisecond, 100
	c := connectVersion(t, r, alice(), "fs", nil, nil, "2025-11-25")

	big := taskOfResult(t, taskRT(c, 1, "tools/call", map[string]any{"name": "read_big", "task": map[string]any{}}))
	if m := taskRT(c, 2, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}); m.Error == nil ||
		!strings.Contains(m.Error.Message, "task limit reached (1)") {
		t.Fatalf("second task: %+v", m)
	}
	id := 2
	awaitStatus(t, c, &id, big.TaskID, "failed", nil)
	m := taskRT(c, 10, "tasks/result", map[string]any{"taskId": big.TaskID})
	if m.Error == nil || !strings.Contains(m.Error.Message, "tasks.max_result_bytes") {
		t.Fatalf("result of a too large task: %+v", m)
	}

	// After its retention the task is gone, and makes room.
	deadline := time.Now().Add(3 * time.Second)
	for taskRT(c, 11, "tasks/get", map[string]any{"taskId": big.TaskID}).Error == nil {
		if time.Now().After(deadline) {
			t.Fatal("task kept past its retention")
		}
		time.Sleep(20 * time.Millisecond)
	}
	created := taskOfResult(t, taskRT(c, 12, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}))
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

	m := taskRT(c, 1, "server/discover", withAgentMeta(nil, caps))
	if !strings.Contains(string(m.Result), `"extensions":{"`+tasksExtension+`":{}}`) || strings.Contains(string(m.Result), `"tasks":{`) {
		t.Fatalf("discover: %s", m.Result)
	}

	m = taskRT(c, 2, "tools/call", withAgentMeta(map[string]any{"name": "write_file"}, caps))
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
	m = taskRT(c, 20, "tasks/update", withAgentMeta(map[string]any{"taskId": created.TaskID,
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
	if text, _ := toolText(t, taskRT(c, 30, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, plain))); text != "fs did read_file" {
		t.Fatalf("plain call: %q", text)
	}
	if m := taskRT(c, 31, "tasks/cancel", withAgentMeta(map[string]any{"taskId": created.TaskID}, caps)); m.Error == nil {
		t.Fatalf("cancelled a completed task: %s", m.Result)
	}
}

// Policy decides again before a result goes (D20): a denial withholds
// it, and the obligations of the delivery decision apply.
func TestDeliveryCheck(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	text, isErr := toolText(t, taskRT(c, 1, "tools/call", map[string]any{"name": "read_withheld"}))
	if !isErr || text != "mcp-gateway: result withheld: not to be delivered" {
		t.Fatalf("withheld: %q %v", text, isErr)
	}
	if text, _ := toolText(t, taskRT(c, 2, "tools/call", map[string]any{"name": "read_redacted_later"})); text != "fs [redacted] read_redacted_later" {
		t.Fatalf("delivery obligations: %q", text)
	}
	if text, _ := toolText(t, taskRT(c, 3, "tools/call", map[string]any{"name": "read_file"})); text != "fs did read_file" {
		t.Fatalf("plain call: %q", text)
	}
}

// A task's result is decided again whenever it is fetched: withheld from
// the user whose role was removed meanwhile, delivered while it holds.
func TestTaskResultDeliveryCheck(t *testing.T) {
	r, _ := testRouter(t, 0)
	p := alice()
	c := connectVersion(t, r, p, "fs", nil, nil, "2025-11-25")
	created := taskOfResult(t, taskRT(c, 1, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}))
	id := 1
	awaitStatus(t, c, &id, created.TaskID, "completed", nil)

	revoked := sameUser(p, p.SessionID+"-revoked")
	revoked.Groups = []string{"revoked"}
	rc := connectVersion(t, r, revoked, "fs", nil, nil, "2025-11-25")
	text, isErr := toolText(t, taskRT(rc, 1, "tasks/result", map[string]any{"taskId": created.TaskID}))
	if !isErr || text != "mcp-gateway: result withheld: role removed" {
		t.Fatalf("after the role was removed: %q %v", text, isErr)
	}
	if text, isErr := toolText(t, taskRT(c, 10, "tasks/result", map[string]any{"taskId": created.TaskID})); isErr || text != "fs did read_file" {
		t.Fatalf("while the role holds: %q %v", text, isErr)
	}

	// The same for a modern agent's tasks/get.
	caps := map[string]any{metaClientCapabilities: map[string]any{"extensions": map[string]any{tasksExtension: map[string]any{}}}}
	a := agent(t, r, p, "fs")
	modern := decodeTask(t, taskRT(a, 1, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, caps)))
	ra := agent(t, r, revoked, "fs")
	meta := func(m map[string]any) map[string]any { return withAgentMeta(m, caps) }
	id = 1
	w := awaitStatus(t, ra, &id, modern.TaskID, "completed", meta)
	if !strings.Contains(string(w.Result), "result withheld: role removed") || !strings.Contains(string(w.Result), `"isError":true`) {
		t.Fatalf("modern, after the role was removed: %s", w.Result)
	}
	id = 1
	w = awaitStatus(t, a, &id, modern.TaskID, "completed", meta)
	if !strings.Contains(string(w.Result), "fs did read_file") {
		t.Fatalf("modern, while the role holds: %s", w.Result)
	}
}

// The control API lists tasks and cancels a running one for an
// administrator.
func TestTasksForControlAPI(t *testing.T) {
	r, l := testRouter(t, 0)
	p := alice()
	c := connectVersion(t, r, p, "fs", nil, nil, "2025-11-25")
	slow := taskOfResult(t, taskRT(c, 1, "tools/call", map[string]any{"name": "slow", "task": map[string]any{}}))
	done := taskOfResult(t, taskRT(c, 2, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}))
	id := 2
	awaitStatus(t, c, &id, done.TaskID, "completed", nil)

	list := r.Tasks()
	if len(list) != 2 || list[0].ID != slow.TaskID || list[0].Server != "fs" || list[0].Tool != "slow" ||
		list[0].Sub != "alice" || list[0].UID == nil || list[0].Status != "working" || list[0].Ended != nil ||
		list[1].Status != "completed" || list[1].Ended == nil {
		t.Fatalf("tasks %+v", list)
	}
	if err := r.CancelTask(done.TaskID, "carol"); !errors.Is(err, ErrTaskEnded) {
		t.Fatalf("cancel a completed task: %v", err)
	}
	if err := r.CancelTask("nope", "carol"); !errors.Is(err, ErrNoTask) {
		t.Fatalf("cancel an unknown task: %v", err)
	}
	if err := r.CancelTask(slow.TaskID, "carol (control API)"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.started("fs")[0].cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("backend not told about cancellation")
	}
	w := decodeTask(t, taskRT(c, 10, "tasks/get", map[string]any{"taskId": slow.TaskID}))
	if w.Status != "cancelled" || w.StatusMessage != "cancelled by carol (control API)" {
		t.Fatalf("after cancel: %+v", w)
	}
}

// statusesUntil reads c until want(m) is true, collecting the statuses
// of notifications/tasks/status for taskID on the way.
func statusesUntil(t *testing.T, c *client, taskID string, want func(*jsonrpc.Message) bool) ([]string, *jsonrpc.Message) {
	t.Helper()
	var seen []string
	for {
		m := c.read()
		if m.Method == "notifications/tasks/status" {
			var w taskWire
			if json.Unmarshal(m.Params, &w) != nil || w.TaskID != taskID {
				t.Fatalf("status notification: %s", m.Params)
			}
			seen = append(seen, w.Status)
		}
		if want(m) {
			return seen, m
		}
	}
}

// A session of 2025-11-25 hears of its task's changes (step 32): the
// approval it waits for, and its end, without polling.
func TestTaskStatusNotifications(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connectVersion(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}}, nil, "2025-11-25")
	c.send(1, "tools/call", map[string]any{"name": "write_file", "task": map[string]any{}})
	// The task, and the notice that it waits for the approval, in either
	// order.
	var created taskWire
	notified := false
	for created.TaskID == "" || !notified {
		m := c.read()
		switch {
		case m.Key() == "1":
			created = taskOfResult(t, m)
		case m.Method == "notifications/tasks/status":
			var w taskWire
			notified = json.Unmarshal(m.Params, &w) == nil && w.Status == "input_required"
		default:
			t.Fatalf("unexpected %+v", m)
		}
	}
	c.send(2, "tasks/result", map[string]any{"taskId": created.TaskID})
	statuses, el := statusesUntil(t, c, created.TaskID, func(m *jsonrpc.Message) bool { return m.Method == "elicitation/create" })
	c.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}))
	more, res := statusesUntil(t, c, created.TaskID, func(m *jsonrpc.Message) bool { return m.Key() == "2" })
	if text, isErr := toolText(t, res); isErr || text != "fs did write_file" {
		t.Fatalf("result: %q %v", text, isErr)
	}
	statuses = append(statuses, more...)
	// The completion may come just after the result.
	deadline := time.After(2 * time.Second)
	for !slices.Contains(statuses, "completed") {
		select {
		case m := <-c.msgs:
			if m.Method == "notifications/tasks/status" {
				var w taskWire
				_ = json.Unmarshal(m.Params, &w)
				statuses = append(statuses, w.Status)
			}
		case <-deadline:
			t.Fatalf("no completion notified: %v", statuses)
		}
	}
	if !slices.Contains(statuses, "working") {
		t.Fatalf("statuses %v", statuses)
	}
}

// A listen stream of 2026-07-28 carries the changes of the tasks it asks
// for, of its principal only; a completed task's result through the
// delivery check of the stream's principal.
func TestAgentTaskNotifications(t *testing.T) {
	r, _ := testRouter(t, 0)
	p := alice()
	caps := map[string]any{metaClientCapabilities: map[string]any{
		"elicitation": map[string]any{"form": map[string]any{}},
		"extensions":  map[string]any{tasksExtension: map[string]any{}},
	}}
	c := agent(t, r, p, "fs")
	created := decodeTask(t, taskRT(c, 1, "tools/call", withAgentMeta(map[string]any{"name": "write_file"}, caps)))
	id := 1
	w := awaitStatus(t, c, &id, created.TaskID, "input_required", func(m map[string]any) map[string]any { return withAgentMeta(m, caps) })
	var key string
	for k := range w.InputRequests {
		key = k
	}

	// Bob's stream asking for alice's task gets nothing accepted.
	bob := principal.Principal{Sub: "bob", Transport: principal.TransportUnix}
	b := agent(t, r, bob, "fs")
	if ack := listenAck(t, b, 7, map[string]any{"taskIds": []string{created.TaskID}}); ack["taskIds"] != nil {
		t.Fatalf("bob's ack %v", ack)
	}
	l := agent(t, r, p, "fs")
	ack := listenAck(t, l, 5, map[string]any{"taskIds": []string{created.TaskID, "nope"}})
	if ids, _ := json.Marshal(ack["taskIds"]); string(ids) != `["`+created.TaskID+`"]` {
		t.Fatalf("ack %v", ack)
	}
	revoked := sameUser(p, "")
	revoked.Groups = []string{"revoked"}
	rl := agent(t, r, revoked, "fs")
	listenAck(t, rl, 6, map[string]any{"taskIds": []string{created.TaskID}})

	taskRT(c, 20, "tasks/update", withAgentMeta(map[string]any{"taskId": created.TaskID,
		"inputResponses": map[string]any{key: map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}}}, caps))
	final := func(c *client) taskWire {
		t.Helper()
		for {
			m := c.read()
			var n taskWire
			if m.Method != "notifications/tasks" || json.Unmarshal(m.Params, &n) != nil || n.TaskID != created.TaskID {
				t.Fatalf("want a task notification, got %+v", m)
			}
			if n.Status == "completed" {
				return n
			}
		}
	}
	if n := final(l); !strings.Contains(string(n.Result), "fs did write_file") {
		t.Fatalf("listener: %s", n.Result)
	}
	if n := final(rl); !strings.Contains(string(n.Result), "result withheld: role removed") {
		t.Fatalf("revoked listener: %s", n.Result)
	}
	select {
	case m := <-b.msgs:
		t.Fatalf("bob heard %+v", m)
	case <-time.After(100 * time.Millisecond):
	}
}

// readSkipping reads c's next message other than a task status
// notification (step 32), which the tests above do not look at.
func readSkipping(c *client) *jsonrpc.Message {
	c.t.Helper()
	for {
		if m := c.read(); m.Method != "notifications/tasks/status" {
			return m
		}
	}
}

// taskRT is roundTrip skipping task status notifications.
func taskRT(c *client, id int, method string, params any) *jsonrpc.Message {
	c.t.Helper()
	c.send(id, method, params)
	m := readSkipping(c)
	if m.Key() != itoa(id) {
		c.t.Fatalf("want response %d, got %+v", id, m)
	}
	return m
}
