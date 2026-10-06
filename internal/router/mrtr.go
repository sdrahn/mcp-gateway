package router

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/signin"
)

// A modern agent's call that needs something from its user (an
// approval, a sign-in, what a modern server asks for) is a multi
// round-trip request (docs/architecture.md, section 5.11.2): the gateway
// answers with an InputRequiredResult at once, and the agent calls again
// with the answers and the gateway's requestState, sealed so that the
// agent can neither read nor change it, bound to the principal, the
// endpoint and the call, and expiring.

// stateTTL bounds the round trips of one call.
const stateTTL = 30 * time.Minute

// stateAAD binds sealed states to their use.
const stateAAD = "mcp-gateway requestState v1"

// sealer seals the gateway's requestState with a key it makes at start:
// a restart turns outstanding retries into errors, which agents answer
// by calling again.
type sealer struct{ aead cipher.AEAD }

func newSealer() *sealer {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &sealer{aead}
}

func (k *sealer) seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, k.aead.NonceSize(), k.aead.NonceSize()+len(plain)+k.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, plain, []byte(stateAAD))), nil
}

func (k *sealer) open(sealed string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < k.aead.NonceSize() {
		return errors.New("malformed")
	}
	n := k.aead.NonceSize()
	plain, err := k.aead.Open(nil, raw[:n], raw[n:], []byte(stateAAD))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// agentState is the gateway's requestState.
type agentState struct {
	Principal string `json:"p"`
	Endpoint  string `json:"e"`
	Method    string `json:"m"`
	Digest    string `json:"d"`
	Expires   int64  `json:"x"`
	// Form: the agent was asked to approve the call with a form.
	Form bool `json:"f,omitempty"`
	// Approval is the parked approval the call waits for (url, oob).
	Approval string `json:"a,omitempty"`
	// Grant is the "once" grant that allowed the call in an earlier
	// round, for its later rounds.
	Grant *pep.Grant `json:"g,omitempty"`
	// SignIn is the sign-in the call waits for.
	SignIn string `json:"s,omitempty"`
	// Server holds a modern server's input round.
	Server *serverInput `json:"v,omitempty"`
}

// serverInput is the round of a modern server's InputRequiredResult that
// the gateway passed on to the agent.
type serverInput struct {
	Name string `json:"n"`
	// State is the server's own requestState.
	State *string `json:"s,omitempty"`
	Round int     `json:"r"`
	// Forwarded are the input requests the agent was asked.
	Forwarded []string `json:"f,omitempty"`
	// Answers are the gateway's own answers (to what it refused).
	Answers map[string]json.RawMessage `json:"a,omitempty"`
}

// agentRound is one round of a modern agent's call.
type agentRound struct {
	method    string
	digest    string
	state     *agentState // nil: the first round
	responses map[string]json.RawMessage
	// grant is the "once" grant the call is allowed with: later rounds
	// carry it.
	grant *pep.Grant
}

// errBadState refuses a requestState that does not open, belongs to
// another principal or call, or expired.
var errBadState = rpcError(jsonrpc.CodeInvalidParams, "invalid params: requestState is not valid for this request (expired, from another call, or from before a restart of the gateway); call again without it")

// agentRoundOf returns the round of a modern agent's request: the
// gateway's state it carries, opened and checked, and its answers.
func (s *Session) agentRoundOf(method string, params map[string]json.RawMessage) (*agentRound, *jsonrpc.Error) {
	rest := maps.Clone(params)
	delete(rest, "_meta")
	delete(rest, "inputResponses")
	delete(rest, "requestState")
	r := &agentRound{method: method, digest: digestOf(rest)}
	raw, ok := params["requestState"]
	if !ok || string(raw) == "null" {
		return r, nil // answers without a state answer nothing
	}
	var sealed string
	if json.Unmarshal(raw, &sealed) != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: requestState must be a string")
	}
	if raw, ok := params["inputResponses"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &r.responses) != nil {
			return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: inputResponses must be an object")
		}
	}
	var st agentState
	if s.r.sealer.open(sealed, &st) != nil || st.Principal != s.binding() || st.Endpoint != s.endpointName() ||
		st.Method != method || st.Digest != r.digest || time.Now().Unix() > st.Expires {
		return nil, errBadState
	}
	r.state = &st
	return r, nil
}

// digestOf is the digest of a call's parameters, independent of how the
// agent encoded them.
func digestOf(params map[string]json.RawMessage) string {
	var v any
	raw, _ := json.Marshal(params)
	_ = json.Unmarshal(raw, &v)
	canonical, _ := json.Marshal(v)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// binding identifies the session's principal in a state.
func (s *Session) binding() string {
	p := s.snapshotPrincipal()
	uid := ""
	if p.UID != nil {
		uid = strconv.FormatUint(uint64(*p.UID), 10)
	}
	return principalKey(p) + "\x00" + uid
}

// endpointName names the session's endpoint in a state.
func (s *Session) endpointName() string {
	if s.endpoint().aggregated {
		return "\x00all"
	}
	return s.endpoint().order[0]
}

// response returns the agent's answer to input request key as an
// elicitation result.
func (r *agentRound) response(key string) (broker.ElicitResult, bool) {
	raw, ok := r.responses[key]
	if !ok {
		return broker.ElicitResult{}, false
	}
	var res broker.ElicitResult
	if json.Unmarshal(raw, &res) != nil || res.Action == "" {
		return broker.ElicitResult{}, false
	}
	return res, true
}

// inputRequest is an input request of an InputRequiredResult.
type inputRequest struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

// inputRequired answers a round with an InputRequiredResult: requests
// (none: the agent just calls again) and the state st for the next
// round.
func (s *Session) inputRequired(r *agentRound, st agentState, requests map[string]inputRequest) any {
	st.Principal, st.Endpoint, st.Method, st.Digest = s.binding(), s.endpointName(), r.method, r.digest
	exp := time.Now().Add(stateTTL)
	st.Expires = exp.Unix()
	if r.grant != nil {
		// The grant holds for the call's rounds, as long as the state.
		g := *r.grant
		g.Expires = exp.UTC().Format(time.RFC3339)
		st.Grant = &g
	}
	sealed, err := s.r.sealer.seal(st)
	if err != nil {
		return nil
	}
	// inputRequests always, empty if there is nothing to ask: with the
	// method's own result field (below) and no inputRequests, some
	// clients (the Python SDK 2.3) take the result for the method's.
	if requests == nil {
		requests = map[string]inputRequest{}
	}
	res := map[string]any{"resultType": "input_required", "requestState": sealed, "inputRequests": requests}
	// The method's own result field, empty: some clients (mcp-go 1.1)
	// parse the result as the method's before they look at resultType,
	// and refuse it without that field.
	if field, ok := emptyResultFields[r.method]; ok {
		res[field] = []any{}
	}
	return res
}

// emptyResultFields are the required fields of the results of the
// methods that may ask for input.
var emptyResultFields = map[string]string{"tools/call": "content", "resources/read": "contents", "prompts/get": "messages"}

// decideModern evaluates policy for t on a modern agent's call (r nil:
// a request that cannot ask for input), with the approval policy asks
// for as rounds of the call. A non-nil last result is the
// InputRequiredResult to answer with.
func (s *Session) decideModern(ctx context.Context, t *callTarget, decisionID string, r *agentRound) (pep.Decision, string, pep.Input, any) {
	p := s.snapshotPrincipal()
	in := pep.Input{
		Principal: p,
		Action:    t.action,
		Resource:  t.resource,
		Args:      t.args,
		Grants:    s.r.Broker.Grants(p, t.resource.Server, t.resource.Name),
		Context:   s.policyContext(decisionID),
	}
	in.Resource.Privileged = s.r.privileged(t.resource.Server)
	var st agentState
	if r != nil && r.state != nil {
		st = *r.state
	}
	if st.Grant != nil {
		in.Grants = append(in.Grants, *st.Grant)
		if dec := pep.Evaluate(ctx, s.r.PDP, in); dec.Effect != pep.Ask {
			if dec.Effect == pep.Allow {
				r.grant = st.Grant
			}
			return dec, st.Grant.ID, in, nil
		}
		in.Grants = in.Grants[:len(in.Grants)-1]
	}
	dec, grantID := s.withOnce(ctx, &in, r)
	if dec.Effect != pep.Ask {
		return dec, grantID, in, nil
	}
	if r == nil {
		return pep.Decision{Effect: pep.Deny, Reason: "approval required, which a " + t.action + " request of MCP 2026-07-28 cannot ask for"}, "", in, nil
	}
	ask := *dec.Ask
	// No session: no grant for the session.
	ask.Scopes = slices.DeleteFunc(slices.Clone(ask.Scopes), func(sc string) bool { return sc == "session" })
	switch {
	case st.Form:
		if res, ok := r.response("approval"); ok {
			g, err := s.r.Broker.FormAnswer(in, ask, res)
			return s.granted(ctx, in, g, err, r)
		}
		// No answer: asked again below.
	case st.Approval != "":
		if res, ok := r.response("approval"); ok && res.Action != "accept" {
			s.r.Broker.Withdraw(st.Approval, p)
			return pep.Decision{Effect: pep.Deny, Reason: "declined by user"}, "", in, nil
		}
		return s.awaitApproval(ctx, t, in, dec, st.Approval, r)
	}
	c, err := s.r.Broker.Channel(s, ask)
	if err != nil {
		return pep.Decision{Effect: pep.Deny, Reason: fmt.Sprintf("approval via %s required but not available", ask.Channel)}, "", in, nil
	}
	switch c {
	case pep.ChannelForm:
		return dec, "", in, s.inputRequired(r, agentState{Form: true}, map[string]inputRequest{
			"approval": {Method: "elicitation/create", Params: broker.FormParams(in, ask)}})
	case pep.ChannelURL:
		id := s.r.Broker.Park(in, ask, c)
		return dec, "", in, s.inputRequired(r, agentState{Approval: id}, map[string]inputRequest{
			"approval": {Method: "elicitation/create", Params: s.r.Broker.URLParams(in, ask, id)}})
	default:
		// Nothing to show the agent first: this round waits already.
		id := s.r.Broker.Park(in, ask, c)
		s.r.Broker.NotifyOOB(requestElicitor{s, requestOf(ctx)}, in, id)
		return s.awaitApproval(ctx, t, in, dec, id, r)
	}
}

// awaitApproval waits up to approvals.retry_wait for the decision on
// parked approval id, and answers the round with it, or to retry.
func (s *Session) awaitApproval(ctx context.Context, t *callTarget, in pep.Input, dec pep.Decision, id string, r *agentRound) (pep.Decision, string, pep.Input, any) {
	stop := s.reportWaiting(t)
	g, outcome := s.r.Broker.Await(ctx, id, in.Principal, s.r.settings().RetryWait)
	stop()
	switch outcome {
	case broker.Waiting:
		return dec, "", in, s.inputRequired(r, agentState{Approval: id}, nil)
	case broker.Decided:
		return s.granted(ctx, in, g, nil, r)
	}
	// Decided while no retry waited (its grant is stored), or denied or
	// expired.
	in.Grants = s.r.Broker.Grants(in.Principal, t.resource.Server, t.resource.Name)
	dec, grantID := s.withOnce(ctx, &in, r)
	if dec.Effect == pep.Ask {
		dec = pep.Decision{Effect: pep.Deny, Reason: "approval denied or expired"}
	}
	return dec, grantID, in, nil
}

// withOnce evaluates in, with a "once" grant from an approval decided
// while no call waited if there is one (used up if it allows the call).
func (s *Session) withOnce(ctx context.Context, in *pep.Input, r *agentRound) (pep.Decision, string) {
	once, haveOnce := s.r.Broker.TakeOnce(in.Principal, in.Resource.Server, in.Resource.Name)
	if haveOnce {
		in.Grants = append(in.Grants, once)
	}
	dec := pep.Evaluate(ctx, s.r.PDP, *in)
	if !haveOnce {
		return dec, ""
	}
	if dec.Effect == pep.Allow {
		if r != nil {
			r.grant = &once
		}
		return dec, once.ID
	}
	s.r.Broker.ReturnOnce(once)
	in.Grants = in.Grants[:len(in.Grants)-1]
	return dec, ""
}

// granted decides again with the grant g of an approval (nil: declined).
func (s *Session) granted(ctx context.Context, in pep.Input, g *pep.Grant, err error, r *agentRound) (pep.Decision, string, pep.Input, any) {
	switch {
	case err != nil:
		s.log.Warn("approval failed", "err", err)
		return pep.Decision{Effect: pep.Deny, Reason: "approval failed"}, "", in, nil
	case g == nil:
		return pep.Decision{Effect: pep.Deny, Reason: "declined by user"}, "", in, nil
	}
	in.Grants = s.r.Broker.Grants(in.Principal, in.Resource.Server, in.Resource.Name)
	if g.Scope == "once" {
		in.Grants = append(in.Grants, *g)
	}
	dec := pep.Evaluate(ctx, s.r.PDP, in)
	if dec.Effect == pep.Ask {
		dec = pep.Decision{Effect: pep.Deny, Reason: "policy did not accept the approval"}
	}
	if dec.Effect == pep.Allow && g.Scope == "once" {
		r.grant = g
	}
	return dec, g.ID, in, nil
}

// signInModern signs a modern agent's principal in to b as rounds of the
// call (r nil: a request that cannot ask for input, or a client that
// cannot open links, gets the link to show). It reports whether the call
// goes on; if not, what to answer.
func (s *Session) signInModern(ctx context.Context, method string, b *config.Backend, r *agentRound) (bool, any, *jsonrpc.Error) {
	p := s.snapshotPrincipal()
	failed := func(err error) (bool, any, *jsonrpc.Error) {
		res, rerr := s.signInFailed(method, b.Name, err)
		return false, res, rerr
	}
	if r != nil && r.state != nil && r.state.SignIn != "" {
		id := r.state.SignIn
		if res, ok := r.response("sign_in"); ok && res.Action != "accept" {
			s.r.SignIns.Abandon(id, p)
			return failed(signin.ErrDeclined)
		}
		err := s.r.SignIns.Await(ctx, b.Name, id, p, s.r.settings().RetryWait)
		switch {
		case err == nil:
			return true, nil, nil
		case errors.Is(err, signin.ErrStillWaiting):
			return false, s.inputRequired(r, agentState{SignIn: id}, nil), nil
		}
		return failed(err)
	}
	if r == nil || !s.SupportsURL() {
		return failed(s.r.SignIns.LinkError(ctx, b, p))
	}
	id, params, err := s.r.SignIns.Link(ctx, b, p)
	if err != nil {
		return failed(err)
	}
	return false, s.inputRequired(r, agentState{SignIn: id}, map[string]inputRequest{
		"sign_in": {Method: "elicitation/create", Params: params}}), nil
}

// laterServerRound reports whether the round answers a modern server's
// input requests (not the call's first request to the server).
func (r *agentRound) laterServerRound() bool {
	return r != nil && r.state != nil && r.state.Server != nil
}

// serverRound puts the answers of the agent's retry and the server's
// state into params for a modern server's next round, and returns the
// round's number.
func (r *agentRound) serverRound(server string, params map[string]json.RawMessage) int {
	if r == nil || r.state == nil || r.state.Server == nil || r.state.Server.Name != server {
		return 0
	}
	sv := r.state.Server
	answers := maps.Clone(sv.Answers)
	if answers == nil {
		answers = map[string]json.RawMessage{}
	}
	for _, k := range sv.Forwarded {
		if v, ok := r.responses[k]; ok {
			answers[k] = v
		}
	}
	if len(answers) > 0 {
		params["inputResponses"], _ = json.Marshal(answers)
	}
	if sv.State != nil {
		params["requestState"], _ = json.Marshal(*sv.State)
	}
	return sv.Round
}

// forwardInput passes a modern server's InputRequiredResult (raw) on to
// a modern agent: each input request decided as a request from the
// server is; what policy refuses the gateway answers itself (an
// elicitation declined; a refused sampling or roots request ends the
// call). If nothing is left to ask the agent, it puts the answers into
// params and reports that the server is to be called again at once.
func (s *Session) forwardInput(r *agentRound, u *upstream, raw json.RawMessage, round int, params map[string]json.RawMessage) (any, bool, *jsonrpc.Error) {
	var ir inputRequired
	if err := json.Unmarshal(raw, &ir); err != nil {
		return nil, false, rpcError(jsonrpc.CodeInternalError, u.backend.Name+" asked for input in a malformed result")
	}
	keys := slices.Sorted(maps.Keys(ir.InputRequests))
	requests := map[string]inputRequest{}
	answers := map[string]json.RawMessage{}
	for _, k := range keys {
		in := ir.InputRequests[k]
		forwarded, ok := s.admitBackendRequest(u, in.Method, in.Params)
		switch {
		case ok:
			requests[k] = inputRequest{Method: in.Method, Params: forwarded}
		case in.Method == "elicitation/create":
			answers[k] = json.RawMessage(`{"action":"decline"}`)
		default:
			return nil, false, rpcError(jsonrpc.CodeInternalError, fmt.Sprintf("%s asked the client (%s): denied by mcp-gateway policy", u.backend.Name, in.Method))
		}
	}
	if len(requests) == 0 {
		delete(params, "inputResponses")
		delete(params, "requestState")
		if len(answers) > 0 {
			params["inputResponses"], _ = json.Marshal(answers)
		}
		if ir.RequestState != nil {
			params["requestState"], _ = json.Marshal(*ir.RequestState)
		}
		return nil, true, nil
	}
	sv := &serverInput{Name: u.backend.Name, State: ir.RequestState, Round: round, Answers: answers}
	sv.Forwarded = slices.Sorted(maps.Keys(requests))
	if len(sv.Answers) == 0 {
		sv.Answers = nil
	}
	return s.inputRequired(r, agentState{Server: sv}, requests), false, nil
}
