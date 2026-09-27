package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Client → backend requests forwarded without a policy decision. Their
// results are either harmless or filtered (the */list methods).
var passthroughRequests = map[string]bool{
	"initialize":               true,
	"ping":                     true,
	"tools/list":               true,
	"resources/list":           true,
	"resources/templates/list": true,
	"prompts/list":             true,
	"logging/setLevel":         true,
}

// Client → backend requests that need a policy decision, and their policy
// action names.
var enforcedRequests = map[string]string{
	"tools/call":            "tools.call",
	"resources/read":        "resources.read",
	"resources/subscribe":   "resources.subscribe",
	"resources/unsubscribe": "resources.unsubscribe",
	"prompts/get":           "prompts.get",
	"completion/complete":   "completion.complete",
}

// Backend → client requests and their policy action names. ping is
// always allowed.
var backendRequests = map[string]string{
	"sampling/createMessage": "sampling.create",
	"elicitation/create":     "elicitation.create",
	"roots/list":             "roots.list",
}

var clientNotifications = map[string]bool{
	"notifications/initialized":        true,
	"notifications/cancelled":          true,
	"notifications/progress":           true,
	"notifications/roots/list_changed": true,
}

var backendNotifications = map[string]bool{
	"notifications/message":                true,
	"notifications/progress":               true,
	"notifications/cancelled":              true,
	"notifications/tools/list_changed":     true,
	"notifications/resources/list_changed": true,
	"notifications/resources/updated":      true,
	"notifications/prompts/list_changed":   true,
}

// Session proxies one client connection to one backend instance.
type Session struct {
	server   string
	instance string
	client   *jsonrpc.Conn
	backend  *jsonrpc.Conn
	pdp      pep.PDP
	broker   *broker.Broker
	audit    *audit.Logger
	log      *slog.Logger

	nextID atomic.Int64

	mu         sync.Mutex
	principal  principal.Principal
	clientCaps map[string]json.RawMessage
	// Methods of client requests awaiting a backend response, by id key.
	pending map[string]string
	// Gateway-originated requests to the client, by id key.
	outbound map[string]chan *jsonrpc.Message
	// Backend requests forwarded to the client: gateway id key → backend id.
	backendIDs map[string]json.RawMessage
	// Tool annotations from the last tools/list, by tool name.
	annotations map[string]map[string]any
}

// SessionConfig holds a Session's collaborators.
type SessionConfig struct {
	Principal principal.Principal
	Server    string
	Instance  string
	Client    *jsonrpc.Conn
	Backend   *jsonrpc.Conn
	PDP       pep.PDP
	Broker    *broker.Broker
	Audit     *audit.Logger
	Log       *slog.Logger
}

// NewSession creates a session.
func NewSession(c SessionConfig) *Session {
	log := c.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Session{
		server:      c.Server,
		instance:    c.Instance,
		client:      c.Client,
		backend:     c.Backend,
		pdp:         c.PDP,
		broker:      c.Broker,
		audit:       c.Audit,
		log:         log.With("session", c.Principal.SessionID, "server", c.Server),
		principal:   c.Principal,
		pending:     map[string]string{},
		outbound:    map[string]chan *jsonrpc.Message{},
		backendIDs:  map[string]json.RawMessage{},
		annotations: map[string]map[string]any{},
	}
}

// Run proxies until either side closes or ctx ends. It closes both
// connections before returning.
func (s *Session) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- s.pumpClient(ctx) }()
	go func() { errc <- s.pumpBackend(ctx) }()
	var err error
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	cancel()
	_ = s.client.Close()
	_ = s.backend.Close()
	return err
}

func (s *Session) snapshotPrincipal() principal.Principal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.principal
}

// --- client → gateway ---------------------------------------------------

func (s *Session) pumpClient(ctx context.Context) error {
	for {
		m, err := s.client.Read()
		if err != nil {
			var rpcErr *jsonrpc.Error
			if errors.As(err, &rpcErr) {
				_ = s.client.Write(jsonrpc.NewError(nil, rpcErr.Code, rpcErr.Message))
				continue
			}
			return err
		}
		switch {
		case m.IsResponse():
			s.clientResponse(m)
		case m.IsNotification():
			if clientNotifications[m.Method] {
				_ = s.backend.Write(m)
			} else {
				s.log.Debug("dropped client notification", "method", m.Method)
			}
		case m.IsRequest():
			s.clientRequest(ctx, m)
		}
	}
}

func (s *Session) clientResponse(m *jsonrpc.Message) {
	s.mu.Lock()
	ch, isOutbound := s.outbound[m.Key()]
	delete(s.outbound, m.Key())
	backendID, isBackend := s.backendIDs[m.Key()]
	delete(s.backendIDs, m.Key())
	s.mu.Unlock()
	switch {
	case isOutbound:
		ch <- m
	case isBackend:
		m.ID = backendID
		_ = s.backend.Write(m)
	default:
		s.log.Debug("dropped unexpected client response", "id", m.Key())
	}
}

func (s *Session) clientRequest(ctx context.Context, m *jsonrpc.Message) {
	if m.Method == "initialize" {
		s.recordInitialize(m.Params)
	}
	if passthroughRequests[m.Method] {
		s.forward(m)
		return
	}
	action, enforced := enforcedRequests[m.Method]
	if !enforced {
		p := s.snapshotPrincipal()
		s.audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: m.Method,
			Server: s.server, Effect: string(pep.Deny), Reason: "method not permitted"})
		_ = s.client.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not permitted by gateway"))
		return
	}
	// Decisions may wait for a human; keep reading other messages meanwhile.
	go s.enforce(ctx, m, action)
}

func (s *Session) forward(m *jsonrpc.Message) {
	s.mu.Lock()
	s.pending[m.Key()] = m.Method
	s.mu.Unlock()
	if err := s.backend.Write(m); err != nil {
		_ = s.client.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "backend unavailable"))
	}
}

func (s *Session) recordInitialize(params json.RawMessage) {
	var p struct {
		Capabilities map[string]json.RawMessage `json:"capabilities"`
		ClientInfo   principal.Client           `json:"clientInfo"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return
	}
	s.mu.Lock()
	s.clientCaps = p.Capabilities
	s.principal.Client = p.ClientInfo
	s.mu.Unlock()
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	URI       string         `json:"uri"`
	Ref       struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"ref"`
}

// target extracts the resource an enforced request addresses.
func (s *Session) target(m *jsonrpc.Message) (pep.Resource, map[string]any, error) {
	var p callParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return pep.Resource{}, nil, err
	}
	r := pep.Resource{Server: s.server}
	switch m.Method {
	case "tools/call":
		r.Kind, r.Name = "tool", p.Name
		s.mu.Lock()
		r.Annotations = s.annotations[p.Name]
		s.mu.Unlock()
	case "prompts/get":
		r.Kind, r.Name = "prompt", p.Name
	case "completion/complete":
		r.Kind, r.Name = "completion", p.Ref.Name+p.Ref.URI
	default: // resources/*
		r.Kind, r.Name = "resource", p.URI
	}
	if r.Name == "" {
		return pep.Resource{}, nil, errors.New("missing target name")
	}
	return r, p.Arguments, nil
}

func (s *Session) enforce(ctx context.Context, m *jsonrpc.Message, action string) {
	res, args, err := s.target(m)
	if err != nil {
		_ = s.client.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidParams, "invalid params"))
		return
	}
	p := s.snapshotPrincipal()
	in := pep.Input{
		Principal: p,
		Action:    action,
		Resource:  res,
		Args:      args,
		Grants:    s.broker.Grants(p, res.Server, res.Name),
		Context:   s.policyContext(m),
	}
	dec := pep.Evaluate(ctx, s.pdp, in)
	var grantID string

	if dec.Effect == pep.Ask {
		g, err := s.broker.Approve(ctx, s, in, *dec.Ask)
		switch {
		case errors.Is(err, broker.ErrNoChannel):
			dec = pep.Decision{Effect: pep.Deny, Reason: fmt.Sprintf("approval via %s required but not available", dec.Ask.Channel)}
		case err != nil:
			s.log.Warn("approval failed", "err", err)
			dec = pep.Decision{Effect: pep.Deny, Reason: "approval failed"}
		case g == nil:
			dec = pep.Decision{Effect: pep.Deny, Reason: "declined by user"}
		default:
			grantID = g.ID
			// Stored grants now include g, unless it is a "once" grant,
			// which is only valid for this re-evaluation.
			in.Grants = s.broker.Grants(p, res.Server, res.Name)
			if g.Scope == "once" {
				in.Grants = append(in.Grants, *g)
			}
			dec = pep.Evaluate(ctx, s.pdp, in)
			if dec.Effect == pep.Ask {
				dec = pep.Decision{Effect: pep.Deny, Reason: "policy did not accept the approval"}
			}
		}
	}

	s.audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: action, Server: res.Server, Name: res.Name,
		Effect: string(dec.Effect), Reason: dec.Reason, GrantID: grantID, Instance: s.instance, Args: args})

	if dec.Effect == pep.Allow {
		s.forward(m)
		return
	}
	s.deny(m, dec.Reason)
}

func (s *Session) deny(m *jsonrpc.Message, reason string) {
	if reason == "" {
		reason = "denied by policy"
	}
	if m.Method == "tools/call" {
		// A tool error lets the agent see and reason about the denial.
		r, err := jsonrpc.NewResult(m.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": "mcp-gateway: " + reason}},
			"isError": true,
		})
		if err == nil {
			_ = s.client.Write(r)
			return
		}
	}
	_ = s.client.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeForbidden, reason))
}

func (s *Session) policyContext(m *jsonrpc.Message) pep.Context {
	s.mu.Lock()
	caps := map[string]any{}
	for k, v := range s.clientCaps {
		var x any
		if json.Unmarshal(v, &x) == nil {
			caps[k] = x
		}
	}
	transport := s.principal.Transport
	s.mu.Unlock()
	return pep.Context{
		Time:               time.Now().UTC().Format(time.RFC3339),
		Transport:          transport,
		RequestID:          m.Key(),
		ClientCapabilities: caps,
	}
}

// --- broker.Elicitor ----------------------------------------------------

// SupportsForm implements broker.Elicitor. Clients that declare an
// elicitation capability without modes support form mode.
func (s *Session) SupportsForm() bool {
	s.mu.Lock()
	raw, ok := s.clientCaps["elicitation"]
	s.mu.Unlock()
	if !ok {
		return false
	}
	var modes map[string]json.RawMessage
	if json.Unmarshal(raw, &modes) != nil {
		return false
	}
	if len(modes) == 0 {
		return true
	}
	_, form := modes["form"]
	return form
}

// Elicit implements broker.Elicitor.
func (s *Session) Elicit(ctx context.Context, p broker.ElicitParams) (broker.ElicitResult, error) {
	resp, err := s.requestClient(ctx, "elicitation/create", p)
	if err != nil {
		return broker.ElicitResult{}, err
	}
	var r broker.ElicitResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return broker.ElicitResult{}, err
	}
	return r, nil
}

func (s *Session) newID() json.RawMessage {
	return json.RawMessage(strconv.Quote("mcpgw-" + strconv.FormatInt(s.nextID.Add(1), 10)))
}

// requestClient sends a gateway-originated request to the client and
// waits for the response.
func (s *Session) requestClient(ctx context.Context, method string, params any) (*jsonrpc.Message, error) {
	id := s.newID()
	req, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	ch := make(chan *jsonrpc.Message, 1)
	s.mu.Lock()
	s.outbound[string(id)] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.outbound, string(id))
		s.mu.Unlock()
	}()
	if err := s.client.Write(req); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp, nil
	case <-ctx.Done():
		n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": id, "reason": "timeout"})
		_ = s.client.Write(n)
		return nil, ctx.Err()
	}
}

// --- backend → gateway --------------------------------------------------

func (s *Session) pumpBackend(ctx context.Context) error {
	for {
		m, err := s.backend.Read()
		if err != nil {
			var rpcErr *jsonrpc.Error
			if errors.As(err, &rpcErr) {
				s.log.Warn("invalid message from backend", "err", err)
				continue
			}
			return err
		}
		switch {
		case m.IsResponse():
			s.backendResponse(ctx, m)
		case m.IsNotification():
			if backendNotifications[m.Method] {
				_ = s.client.Write(m)
			} else {
				s.log.Debug("dropped backend notification", "method", m.Method)
			}
		case m.IsRequest():
			go s.backendRequest(ctx, m)
		}
	}
}

func (s *Session) backendResponse(ctx context.Context, m *jsonrpc.Message) {
	s.mu.Lock()
	method, ok := s.pending[m.Key()]
	delete(s.pending, m.Key())
	s.mu.Unlock()
	if !ok {
		s.log.Debug("dropped unexpected backend response", "id", m.Key())
		return
	}
	if method == "tools/list" && m.Error == nil {
		filtered, err := s.filterTools(ctx, m.Result)
		if err != nil {
			s.log.Warn("filtering tools/list failed", "err", err)
			filtered = json.RawMessage(`{"tools":[]}`)
		}
		m.Result = filtered
	}
	// Other */list results are not modelled by the policy yet: nothing
	// there is usable (reads are denied), so hide them entirely.
	switch method {
	case "resources/list":
		m.Result = json.RawMessage(`{"resources":[]}`)
	case "resources/templates/list":
		m.Result = json.RawMessage(`{"resourceTemplates":[]}`)
	case "prompts/list":
		m.Result = json.RawMessage(`{"prompts":[]}`)
	}
	_ = s.client.Write(m)
}

// filterTools removes tools the principal may not see from a tools/list
// result and remembers the tools' annotations.
func (s *Session) filterTools(ctx context.Context, result json.RawMessage) (json.RawMessage, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(result, &top); err != nil {
		return nil, err
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(top["tools"], &tools); err != nil {
		return nil, err
	}
	type toolHead struct {
		Name        string         `json:"name"`
		Annotations map[string]any `json:"annotations"`
	}
	heads := make([]toolHead, len(tools))
	resources := make([]pep.Resource, len(tools))
	annotations := map[string]map[string]any{}
	for i, t := range tools {
		if err := json.Unmarshal(t, &heads[i]); err != nil {
			return nil, err
		}
		resources[i] = pep.Resource{Server: s.server, Kind: "tool", Name: heads[i].Name}
		annotations[heads[i].Name] = heads[i].Annotations
	}
	s.mu.Lock()
	s.annotations = annotations
	s.mu.Unlock()

	visible, err := s.pdp.Visible(ctx, s.snapshotPrincipal(), resources)
	if err != nil {
		return nil, err
	}
	ok := map[string]bool{}
	for _, r := range visible {
		if r.Server == s.server && r.Kind == "tool" {
			ok[r.Name] = true
		}
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for i, t := range tools {
		if ok[heads[i].Name] {
			kept = append(kept, t)
		}
	}
	top["tools"], err = json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	return json.Marshal(top)
}

func (s *Session) backendRequest(ctx context.Context, m *jsonrpc.Message) {
	if m.Method != "ping" {
		action, known := backendRequests[m.Method]
		p := s.snapshotPrincipal()
		dec := pep.Decision{Effect: pep.Deny, Reason: "method not permitted"}
		if known {
			dec = pep.Evaluate(ctx, s.pdp, pep.Input{
				Principal: p,
				Action:    action,
				Resource:  pep.Resource{Server: s.server, Kind: "client", Name: m.Method},
				Context:   s.policyContext(m),
			})
		}
		s.audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: m.Method, Server: s.server,
			Effect: string(dec.Effect), Reason: dec.Reason, Instance: s.instance})
		if dec.Effect != pep.Allow {
			_ = s.backend.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeForbidden, "denied by mcp-gateway policy"))
			return
		}
		if m.Method == "elicitation/create" {
			m.Params = labelElicitation(m.Params, s.server)
		}
	}
	id := s.newID()
	s.mu.Lock()
	s.backendIDs[string(id)] = m.ID
	s.mu.Unlock()
	fwd := *m
	fwd.ID = id
	if err := s.client.Write(&fwd); err != nil {
		s.mu.Lock()
		delete(s.backendIDs, string(id))
		s.mu.Unlock()
		_ = s.backend.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "client unavailable"))
	}
}

// labelElicitation prefixes a backend's elicitation message with the
// backend's name, so the user always knows who is asking.
func labelElicitation(params json.RawMessage, server string) json.RawMessage {
	var p map[string]any
	if err := json.Unmarshal(params, &p); err != nil {
		return params
	}
	msg, _ := p["message"].(string)
	p["message"] = fmt.Sprintf("[%s] %s", server, msg)
	out, err := json.Marshal(p)
	if err != nil {
		return params
	}
	return out
}
