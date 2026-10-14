package router

import (
	"context"
	"sync"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// replayConn is a client connection that keeps responses for replay, as
// an HTTP session does: it records how each is made again.
type replayConn struct {
	jsonrpc.MessageConn
	mu    sync.Mutex
	again map[string]transport.Redelivery
}

func (c *replayConn) WriteReplayable(m *jsonrpc.Message, again transport.Redelivery) error {
	c.mu.Lock()
	c.again[m.Key()] = again
	c.mu.Unlock()
	return c.Write(m)
}

func (c *replayConn) replay(t *testing.T, key string, p principal.Principal) *jsonrpc.Message {
	t.Helper()
	c.mu.Lock()
	again := c.again[key]
	c.mu.Unlock()
	if again == nil {
		t.Fatalf("response %s cannot be made again", key)
	}
	return again(context.Background(), p)
}

// A replayed answer to a call, and a replayed task result, are decided
// again for the principal resuming the stream (roadmap step 33): withheld
// once the role was removed, delivered while it holds. Answers without a
// result to decide go as they are.
func TestReplayDecidedAgain(t *testing.T) {
	r, _ := testRouter(t, 0)
	p := alice()
	rc := &replayConn{again: map[string]transport.Redelivery{}}
	wrap := func(c jsonrpc.MessageConn) jsonrpc.MessageConn { rc.MessageConn = c; return rc }
	c := connectVersion(t, r, p, "fs", nil, wrap, "2025-11-25")
	revoked := p
	revoked.Groups = []string{"revoked"}

	if text, _ := toolText(t, taskRT(c, 1, "tools/call", map[string]any{"name": "read_file"})); text != "fs did read_file" {
		t.Fatalf("call: %q", text)
	}
	if text, isErr := toolText(t, rc.replay(t, "1", revoked)); !isErr || text != "mcp-gateway: result withheld: role removed" {
		t.Fatalf("replayed after the role was removed: %q %v", text, isErr)
	}
	if text, isErr := toolText(t, rc.replay(t, "1", p)); isErr || text != "fs did read_file" {
		t.Fatalf("replayed while the role holds: %q %v", text, isErr)
	}

	created := taskOfResult(t, taskRT(c, 2, "tools/call", map[string]any{"name": "read_file", "task": map[string]any{}}))
	id := 2
	awaitStatus(t, c, &id, created.TaskID, "completed", nil)
	id++
	if text, _ := toolText(t, taskRT(c, id, "tasks/result", map[string]any{"taskId": created.TaskID})); text != "fs did read_file" {
		t.Fatalf("tasks/result: %q", text)
	}
	if text, isErr := toolText(t, rc.replay(t, itoa(id), revoked)); !isErr || text != "mcp-gateway: result withheld: role removed" {
		t.Fatalf("replayed task result after the role was removed: %q %v", text, isErr)
	}

	rc.mu.Lock()
	_, listed := rc.again["2"] // the task's creation: no result to decide
	rc.mu.Unlock()
	if listed {
		t.Error("the answer creating a task is made again")
	}
}
