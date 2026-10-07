package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// askPDP is fakePDP, but the tools in ask need an approval through
// channel (fallback oob), and are allowed with a grant.
type askPDP struct {
	fakePDP
	channel pep.Channel
	ask     map[string]bool
}

func (p askPDP) Decide(ctx context.Context, in pep.Input) (pep.Decision, error) {
	if in.Action == "tools.call" && p.ask[in.Resource.Name] {
		if len(in.Grants) > 0 {
			return pep.Decision{Effect: pep.Allow}, nil
		}
		return pep.Decision{Effect: pep.Ask, Ask: &pep.AskSpec{Channel: p.channel, Fallback: "oob", Scopes: []string{"once", "session", "1h"}}}, nil
	}
	return p.fakePDP.Decide(ctx, in)
}

// interim is an InputRequiredResult.
type interim struct {
	ResultType    string `json:"resultType"`
	InputRequests map[string]struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	} `json:"inputRequests"`
	RequestState string `json:"requestState"`
}

func inputRequiredOf(t *testing.T, m *jsonrpc.Message) interim {
	t.Helper()
	var r interim
	if m.Error != nil || json.Unmarshal(m.Result, &r) != nil || r.ResultType != "input_required" || r.RequestState == "" {
		t.Fatalf("want an InputRequiredResult, got %+v (%s)", m.Error, m.Result)
	}
	return r
}

// retry is the params of a retry: the call's params, the answers and the
// state.
func retry(params map[string]any, state string, responses map[string]any, extra map[string]any) map[string]any {
	out := withAgentMeta(params, extra)
	out["requestState"] = state
	if responses != nil {
		out["inputResponses"] = responses
	}
	return out
}

var formCaps = map[string]any{metaClientCapabilities: map[string]any{"elicitation": map[string]any{"form": map[string]any{}}}}

// An approval by form is a round of the call: the gateway answers with
// the form and its state at once, and the retry with the answer goes
// on. No session, so no "session" scope.
func TestAgentApprovalForm(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")
	call := map[string]any{"name": "write_file", "arguments": map[string]any{"path": "/a"}}

	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, formCaps)))
	form := ir.InputRequests["approval"]
	if form.Method != "elicitation/create" || !strings.Contains(string(form.Params), `"enum":["once"]`) ||
		!strings.Contains(string(form.Params), "write_file") {
		t.Fatalf("approval form: %+v", ir.InputRequests)
	}
	m := c.roundTrip(2, "tools/call", retry(call, ir.RequestState, map[string]any{
		"approval": map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}}, formCaps))
	if text, isErr := toolText(t, m); isErr || text != "fs did write_file" {
		t.Fatalf("approved call: %q %v", text, isErr)
	}
	if !strings.Contains(string(m.Result), `"resultType":"complete"`) {
		t.Fatalf("result %s", m.Result)
	}

	// Declined.
	ir = inputRequiredOf(t, c.roundTrip(3, "tools/call", withAgentMeta(call, formCaps)))
	text, isErr := toolText(t, c.roundTrip(4, "tools/call", retry(call, ir.RequestState, map[string]any{
		"approval": map[string]any{"action": "decline"}}, formCaps)))
	if !isErr || !strings.Contains(text, "declined by user") {
		t.Fatalf("declined: %q %v", text, isErr)
	}

	// An agent that cannot show forms: the fallback (oob) is not
	// available either.
	text, isErr = toolText(t, c.roundTrip(5, "tools/call", withAgentMeta(call, nil)))
	if !isErr || !strings.Contains(text, "approval via form required but not available") {
		t.Fatalf("no form: %q %v", text, isErr)
	}
}

// tampered returns state with one bit of its sealed bytes changed. (Not
// its text: the decoder ignores the unused bits of the last character,
// so changed text may decode to the same bytes.)
func tampered(t *testing.T, state string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

// The gateway's state is bound to the principal, the endpoint, the call
// and its parameters; anything else is invalid params.
func TestAgentRequestState(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")
	call := map[string]any{"name": "write_file", "arguments": map[string]any{"path": "/a"}}
	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, formCaps)))
	accept := map[string]any{"approval": map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}}

	bob := alice()
	bob.Sub = "bob"
	other := agent(t, r, bob, "fs")
	git := agent(t, r, alice(), "git")
	for name, tc := range map[string]struct {
		c      *client
		params map[string]any
	}{
		"tampered":        {c, retry(call, tampered(t, ir.RequestState), accept, formCaps)},
		"garbage":         {c, retry(call, "s1", accept, formCaps)},
		"other arguments": {c, retry(map[string]any{"name": "write_file", "arguments": map[string]any{"path": "/b"}}, ir.RequestState, accept, formCaps)},
		"other principal": {other, retry(call, ir.RequestState, accept, formCaps)},
		"other endpoint":  {git, retry(call, ir.RequestState, accept, formCaps)},
	} {
		m := tc.c.roundTrip(2, "tools/call", tc.params)
		if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams || !strings.Contains(m.Error.Message, "requestState is not valid") {
			t.Errorf("%s: %+v", name, m)
		}
	}
	m := c.roundTrip(3, "tools/call", retry(call, ir.RequestState, accept, map[string]any{
		metaClientCapabilities: map[string]any{"elicitation": map[string]any{}}, "progressToken": 1}))
	if text, isErr := toolText(t, m); isErr || text != "fs did write_file" {
		t.Fatalf("same call, other _meta: %q %v", text, isErr)
	}
}

// approvalRouter is testRouter with tools that need approval through
// channel, the approval page at gw.example.com, oob approvals, and short
// waits.
func approvalRouter(t *testing.T, channel pep.Channel) *Router {
	t.Helper()
	r, _ := testRouter(t, time.Hour)
	r.PDP = askPDP{channel: channel, ask: map[string]bool{"run_job": true, "ask_input": true}}
	r.Broker = mustBroker(t, broker.Options{Timeout: time.Minute, OOB: true, URLTemplate: "https://gw.example.com/approve/{id}"})
	r.RetryWait = 100 * time.Millisecond
	return r
}

// self decides alice's approvals (without a policy, only she may).
var self = broker.Approver{Name: "alice", UID: 1001}

// An approval on the page is a URL-mode input request; retries wait up
// to approvals.retry_wait for the decision and are otherwise answered to
// retry, carrying the same approval.
func TestAgentApprovalURL(t *testing.T) {
	r := approvalRouter(t, pep.ChannelURL)
	c := agent(t, r, alice(), "fs")
	urlCaps := map[string]any{metaClientCapabilities: map[string]any{"elicitation": map[string]any{"url": map[string]any{}}}}
	call := map[string]any{"name": "run_job", "arguments": map[string]any{}}

	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, urlCaps)))
	var page broker.URLElicitParams
	_ = json.Unmarshal(ir.InputRequests["approval"].Params, &page)
	if page.Mode != "url" || !strings.HasPrefix(page.URL, "https://gw.example.com/approve/a-") || page.ElicitationID == "" {
		t.Fatalf("approval page: %+v", ir.InputRequests)
	}
	pending := r.Broker.ListPending(t.Context(), self)
	if len(pending) != 1 || pending[0].ID != page.ElicitationID || pending[0].Waiting {
		t.Fatalf("pending: %+v", pending)
	}

	// Nobody decided yet: retry.
	accept := map[string]any{"approval": map[string]any{"action": "accept"}}
	next := inputRequiredOf(t, c.roundTrip(2, "tools/call", retry(call, ir.RequestState, accept, urlCaps)))
	if len(next.InputRequests) != 0 {
		t.Fatalf("retry asks again: %+v", next.InputRequests)
	}

	// Decided while a retry waits.
	r.RetryWait = 5 * time.Second
	r.SetSettings(Settings{RetryWait: 5 * time.Second})
	go func() {
		for {
			if p := r.Broker.ListPending(context.Background(), self); len(p) == 1 && p[0].Waiting {
				_, _ = r.Broker.Resolve(context.Background(), self, p[0].ID, true, "once")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	m := c.roundTrip(3, "tools/call", retry(call, next.RequestState, nil, urlCaps))
	if text, isErr := toolText(t, m); isErr || text != "fs did run_job" {
		t.Fatalf("approved: %q %v", text, isErr)
	}

	// Declined to open the page: the approval goes.
	ir = inputRequiredOf(t, c.roundTrip(4, "tools/call", withAgentMeta(call, urlCaps)))
	text, isErr := toolText(t, c.roundTrip(5, "tools/call", retry(call, ir.RequestState,
		map[string]any{"approval": map[string]any{"action": "decline"}}, urlCaps)))
	if !isErr || !strings.Contains(text, "declined by user") || len(r.Broker.ListPending(t.Context(), self)) != 0 {
		t.Fatalf("declined: %q %v", text, isErr)
	}
}

// An approval out of band (the fallback when the agent cannot open the
// page): no input request, only the state; decided while no retry waits,
// the retry finds the grant, or the denial.
func TestAgentApprovalOOB(t *testing.T) {
	r := approvalRouter(t, pep.ChannelURL)
	c := agent(t, r, alice(), "fs")
	call := map[string]any{"name": "run_job", "arguments": map[string]any{"n": 1}}

	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, nil)))
	if len(ir.InputRequests) != 0 {
		t.Fatalf("oob asks: %+v", ir.InputRequests)
	}
	pending := r.Broker.ListPending(t.Context(), self)
	if len(pending) != 1 || pending[0].Channel != pep.ChannelOOB {
		t.Fatalf("pending: %+v", pending)
	}
	if _, err := r.Broker.Resolve(t.Context(), self, pending[0].ID, true, "once"); err != nil {
		t.Fatal(err)
	}
	if text, isErr := toolText(t, c.roundTrip(2, "tools/call", retry(call, ir.RequestState, nil, nil))); isErr || text != "fs did run_job" {
		t.Fatalf("approved: %q %v", text, isErr)
	}

	// Denied.
	ir = inputRequiredOf(t, c.roundTrip(3, "tools/call", withAgentMeta(call, nil)))
	pending = r.Broker.ListPending(t.Context(), self)
	if _, err := r.Broker.Resolve(t.Context(), self, pending[0].ID, false, ""); err != nil {
		t.Fatal(err)
	}
	if text, isErr := toolText(t, c.roundTrip(4, "tools/call", retry(call, ir.RequestState, nil, nil))); !isErr || !strings.Contains(text, "approval denied or expired") {
		t.Fatalf("denied: %q %v", text, isErr)
	}

}

// For a client without a request timeout of its own
// (agents.no_request_timeout), a round waits until the approval is
// decided, however long past approvals.retry_wait: the call is one round.
func TestAgentApprovalUntilDecided(t *testing.T) {
	r := approvalRouter(t, pep.ChannelURL)
	r.NoRequestTimeout = []string{"Kit"}
	c := agent(t, r, alice(), "fs")
	call := map[string]any{"name": "run_job", "arguments": map[string]any{"n": 1}}
	kit := map[string]any{metaClientInfo: map[string]any{"name": "kit", "version": "0.121.1"}}

	go func() {
		time.Sleep(500 * time.Millisecond) // five times approvals.retry_wait
		pending := r.Broker.ListPending(context.Background(), self)
		if len(pending) == 1 {
			_, _ = r.Broker.Resolve(context.Background(), self, pending[0].ID, true, "once")
		}
	}()
	if text, isErr := toolText(t, c.roundTrip(1, "tools/call", withAgentMeta(call, kit))); isErr || text != "fs did run_job" {
		t.Fatalf("approved in one round: %q %v", text, isErr)
	}

	// Other clients still get a round per approvals.retry_wait.
	if ir := inputRequiredOf(t, c.roundTrip(2, "tools/call", withAgentMeta(call, nil))); len(ir.InputRequests) != 0 {
		t.Fatalf("other client: %+v", ir)
	}
}

// A modern server's input requests reach a modern agent with the
// gateway's state, after policy: the retry's answers and the server's
// state go back to the server. What policy refuses the gateway answers.
func TestAgentServerInput(t *testing.T) {
	r, l := modernRouter(t)
	caps := map[string]any{metaClientCapabilities: map[string]any{"elicitation": map[string]any{"form": map[string]any{}}, "roots": map[string]any{}}}
	c := agent(t, r, alice(), "modern")
	call := map[string]any{"name": "ask_input", "arguments": map[string]any{}}

	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, caps)))
	if ir.InputRequests["name"].Method != "elicitation/create" || !strings.Contains(string(ir.InputRequests["name"].Params), `"message":"[modern] Your name?"`) ||
		ir.InputRequests["roots"].Method != "roots/list" {
		t.Fatalf("input requests: %+v", ir)
	}
	m := c.roundTrip(2, "tools/call", retry(call, ir.RequestState, map[string]any{
		"name":  map[string]any{"action": "accept", "content": map[string]any{"name": "Alice"}},
		"roots": map[string]any{"roots": []any{}},
		"extra": map[string]any{"action": "accept"},
	}, caps))
	if text, isErr := toolText(t, m); isErr || text != `answers {"name":{"action":"accept","content":{"name":"Alice"}},"roots":{"roots":[]}}` {
		t.Fatalf("answered: %q %v", text, isErr)
	}
	_, metas, _ := l.started("modern")[0].seen()
	if got := string(metas[len(metas)-1][metaClientCapabilities]); got != `{"elicitation":{"form":{}},"roots":{}}` {
		t.Errorf("clientCapabilities %s", got)
	}

	// Refused by policy: declined by the gateway, without a round.
	m = c.roundTrip(3, "tools/call", withAgentMeta(map[string]any{"name": "ask_secret", "arguments": map[string]any{}}, caps))
	if text, isErr := toolText(t, m); isErr || text != `answers {"pw":{"action":"decline"}}` {
		t.Fatalf("refused: %q %v", text, isErr)
	}

	// The rounds are bounded.
	m = c.roundTrip(4, "tools/call", withAgentMeta(map[string]any{"name": "ask_forever", "arguments": map[string]any{}}, caps))
	if m.Error == nil || !strings.Contains(m.Error.Message, "more than 8 times") {
		t.Fatalf("rounds: %+v", m)
	}
}

// An approval and a server's input in one call: the approval is asked
// once, and its grant carries the later rounds.
func TestAgentApprovalThenServerInput(t *testing.T) {
	r, _ := modernRouter(t)
	r.PDP = askPDP{channel: pep.ChannelForm, ask: map[string]bool{"ask_input": true}}
	caps := map[string]any{metaClientCapabilities: map[string]any{"elicitation": map[string]any{"form": map[string]any{}}, "roots": map[string]any{}}}
	c := agent(t, r, alice(), "modern")
	call := map[string]any{"name": "ask_input", "arguments": map[string]any{}}

	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, caps)))
	if _, ok := ir.InputRequests["approval"]; !ok {
		t.Fatalf("want the approval first: %+v", ir.InputRequests)
	}
	ir = inputRequiredOf(t, c.roundTrip(2, "tools/call", retry(call, ir.RequestState, map[string]any{
		"approval": map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}}, caps)))
	if _, ok := ir.InputRequests["name"]; !ok {
		t.Fatalf("want the server's requests: %+v", ir.InputRequests)
	}
	m := c.roundTrip(3, "tools/call", retry(call, ir.RequestState, map[string]any{
		"name":  map[string]any{"action": "decline"},
		"roots": map[string]any{"roots": []any{}},
	}, caps))
	if text, isErr := toolText(t, m); isErr || !strings.HasPrefix(text, "answers ") {
		t.Fatalf("call: %q %v", text, isErr)
	}
}

// Signing in is a round of the call too: the link as a URL-mode input
// request, retries waiting for the callback, then the call goes on.
func TestAgentSignIn(t *testing.T) {
	r, _ := testRouter(t, time.Minute)
	si := &fakeSignIns{signed: map[string]bool{}}
	r.SignIns = si
	r.Backends["tickets"] = &config.Backend{Name: "tickets", Isolation: config.IsolationPrincipal,
		Discovery: config.DiscoveryInstance, SignIn: &config.SignIn{}}
	urlCaps := map[string]any{metaClientCapabilities: map[string]any{"elicitation": map[string]any{"url": map[string]any{}}}}
	c := agent(t, r, alice(), "tickets")
	call := map[string]any{"name": "read_file", "arguments": map[string]any{}}

	ir := inputRequiredOf(t, c.roundTrip(1, "tools/call", withAgentMeta(call, urlCaps)))
	var link broker.URLElicitParams
	_ = json.Unmarshal(ir.InputRequests["sign_in"].Params, &link)
	if link.Mode != "url" || !strings.Contains(link.URL, "state=s1") || si.links != 1 {
		t.Fatalf("sign-in link: %+v", ir.InputRequests)
	}
	accept := map[string]any{"sign_in": map[string]any{"action": "accept"}}
	ir = inputRequiredOf(t, c.roundTrip(2, "tools/call", retry(call, ir.RequestState, accept, urlCaps)))
	if len(ir.InputRequests) != 0 {
		t.Fatalf("waiting retry asks: %+v", ir.InputRequests)
	}
	si.mu.Lock()
	si.signed["alice/tickets"] = true
	si.mu.Unlock()
	if text, isErr := toolText(t, c.roundTrip(3, "tools/call", retry(call, ir.RequestState, nil, urlCaps))); isErr || text != "tickets did read_file" {
		t.Fatalf("after sign-in: %q %v", text, isErr)
	}

	// Declined; and an agent that cannot open links gets the link to
	// show.
	si.mu.Lock()
	si.signed = map[string]bool{}
	si.mu.Unlock()
	ir = inputRequiredOf(t, c.roundTrip(4, "tools/call", withAgentMeta(call, urlCaps)))
	text, isErr := toolText(t, c.roundTrip(5, "tools/call", retry(call, ir.RequestState,
		map[string]any{"sign_in": map[string]any{"action": "decline"}}, urlCaps)))
	if !isErr || si.abandoned != 1 || !strings.Contains(text, "signing in to tickets failed") {
		t.Fatalf("declined: %q %v", text, isErr)
	}
	text, isErr = toolText(t, c.roundTrip(6, "tools/call", withAgentMeta(call, nil)))
	if !isErr || !strings.Contains(text, "open https://gw.example.com/oauth/start/s1") {
		t.Fatalf("link: %q %v", text, isErr)
	}
}

// The sealed state opens only with the key that sealed it.
func TestSealer(t *testing.T) {
	a, b := newSealer(), newSealer()
	sealed, err := a.seal(agentState{Approval: "a-1"})
	if err != nil {
		t.Fatal(err)
	}
	var st agentState
	if err := a.open(sealed, &st); err != nil || st.Approval != "a-1" {
		t.Fatalf("open: %v %+v", err, st)
	}
	if b.open(sealed, &st) == nil {
		t.Fatal("opened with another key")
	}
	if raw, _ := base64.RawURLEncoding.DecodeString(sealed); strings.Contains(string(raw), `"a-1"`) {
		t.Fatal("state readable")
	}
}
