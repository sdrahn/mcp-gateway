package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// Servers of MCP 2026-07-28 and later ("modern", docs/architecture.md,
// section 5.11) have no initialize handshake: every request carries the
// protocol version and the client's capabilities in _meta, server/discover
// tells what a server speaks, and change notifications come on a
// subscriptions/listen stream. The gateway learns a server's era when it
// starts an instance by probing server/discover and falls back to
// initialize ("legacy") on any error that is not a modern one.

// modernVersion is the modern MCP version the gateway speaks to servers.
const modernVersion = "2026-07-28"

// Era of a server definition, as the pool remembers it.
type era int

const (
	eraUnknown era = iota
	eraLegacy
	eraModern
)

// probeTimeout bounds waiting for the answer to server/discover: a legacy
// server may not answer a request before initialize at all. (A variable
// for tests.)
var probeTimeout = 10 * time.Second

// Modern error codes (the range -32020 to -32099 is the specification's):
// one of them identifies a modern server.
const (
	codeHeaderMismatch          = -32020
	codeMissingClientCapability = -32021
	codeUnsupportedVersion      = -32022
)

// Reserved _meta keys of the per-request protocol fields.
const (
	metaPrefix             = "io.modelcontextprotocol/"
	metaProtocolVersion    = metaPrefix + "protocolVersion"
	metaClientInfo         = metaPrefix + "clientInfo"
	metaClientCapabilities = metaPrefix + "clientCapabilities"
	metaLogLevel           = metaPrefix + "logLevel"
	metaServerInfo         = metaPrefix + "serverInfo"
	metaSubscriptionID     = metaPrefix + "subscriptionId"
)

// errProbeEnded is returned when an instance exited while it was probed:
// some legacy servers end on a request before initialize. The pool starts
// the instance again without probing.
var errProbeEnded = errors.New("the instance exited when probed with server/discover")

// discoverResult is a modern server's answer to server/discover.
type discoverResult struct {
	SupportedVersions []string                   `json:"supportedVersions"`
	Capabilities      map[string]json.RawMessage `json:"capabilities"`
	Instructions      string                     `json:"instructions,omitempty"`
	Meta              map[string]json.RawMessage `json:"_meta,omitempty"`
}

// discover probes the instance with server/discover. It reports whether
// the server is modern, and for a modern server that speaks
// modernVersion its capabilities in the form of an initialize result. A
// modern server without that version is an error.
func (u *upstream) discover(ctx context.Context) (initResult, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	params, err := withMeta(nil, u.meta(nil, "server/discover"))
	if err != nil {
		return initResult{}, false, err
	}
	resp, err := u.probe(ctx, "server/discover", params)
	switch {
	case errors.Is(err, errBackendGone):
		return initResult{}, false, errProbeEnded
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil:
		return initResult{}, false, nil // silent: legacy
	case err != nil:
		return initResult{}, false, err
	}
	if e := resp.Error; e != nil {
		if strings.Contains(e.Message, signin.RejectedMarker) {
			// The connector's server refused the principal's token: an
			// answer about the sign-in, not the server's era.
			return initResult{}, false, e
		}
		switch e.Code {
		case codeUnsupportedVersion:
			var d struct {
				Supported []string `json:"supported"`
			}
			_ = json.Unmarshal(e.Data, &d)
			return initResult{}, true, fmt.Errorf("the server speaks MCP %s, the gateway %s and earlier", strings.Join(d.Supported, ", "), modernVersion)
		case codeMissingClientCapability, codeHeaderMismatch:
			return initResult{}, true, fmt.Errorf("server/discover: %s", e.Message)
		}
		return initResult{}, false, nil
	}
	var d discoverResult
	if err := json.Unmarshal(resp.Result, &d); err != nil {
		return initResult{}, false, nil // not a discover result: legacy
	}
	if !slices.Contains(d.SupportedVersions, modernVersion) {
		if len(d.SupportedVersions) == 0 {
			return initResult{}, false, nil
		}
		return initResult{}, true, fmt.Errorf("the server speaks MCP %s, the gateway %s and earlier", strings.Join(d.SupportedVersions, ", "), modernVersion)
	}
	return initResult{
		ProtocolVersion: modernVersion,
		Capabilities:    d.Capabilities,
		ServerInfo:      d.Meta[metaServerInfo],
		Instructions:    d.Instructions,
	}, true, nil
}

// probe sends a request that is not counted as in flight (a legacy
// server may never answer it, and must still idle) and waits for the
// answer.
func (u *upstream) probe(ctx context.Context, method string, params json.RawMessage) (*jsonrpc.Message, error) {
	id := json.RawMessage(strconv.Quote("probe-" + strconv.FormatInt(u.nextID.Add(1), 10)))
	req, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	ch := make(chan *jsonrpc.Message, 1)
	u.mu.Lock()
	u.pending[string(id)] = ch
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		delete(u.pending, string(id))
		u.mu.Unlock()
	}()
	if err := u.conn.Write(req); err != nil {
		return nil, errBackendGone
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.closed:
		return nil, errBackendGone
	}
}

// meta returns the per-request protocol fields for a request on behalf
// of session s (nil for the gateway's own). The gateway declares no
// client capabilities yet: a modern server then asks for nothing from the
// client (multi round-trip requests come with roadmap step 24's relay of
// input requests).
func (u *upstream) meta(s *Session, method string) map[string]any {
	caps := map[string]any{}
	if s != nil && inputMethods[method] {
		caps = s.serverCapabilities(u.backend)
	}
	m := map[string]any{
		metaProtocolVersion:    modernVersion,
		metaClientInfo:         map[string]any{"name": "mcp-gateway", "version": version.Version},
		metaClientCapabilities: caps,
	}
	if level := s.currentLogLevel(); level != "" {
		m[metaLogLevel] = level
	}
	return m
}

// withMeta returns params (an object, or nil) with the fields of add in
// its _meta. Reserved protocol fields a client put there are dropped
// first: what the gateway declares to a server is the gateway's.
func withMeta(params any, add map[string]any) (json.RawMessage, error) {
	obj := map[string]json.RawMessage{}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		if string(raw) != "null" {
			if err := json.Unmarshal(raw, &obj); err != nil {
				return nil, fmt.Errorf("params are not an object: %w", err)
			}
		}
	}
	meta := map[string]json.RawMessage{}
	if raw, ok := obj["_meta"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("_meta is not an object: %w", err)
		}
	}
	for k := range meta {
		if strings.HasPrefix(k, metaPrefix) {
			delete(meta, k)
		}
	}
	for k, v := range add {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		meta[k] = raw
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	obj["_meta"] = raw
	return json.Marshal(obj)
}

// currentLogLevel returns the level of the session's last
// logging/setLevel, "" if none (or s is nil).
func (s *Session) currentLogLevel() string {
	if s == nil {
		return ""
	}
	if s.modern {
		return s.agentLevel
	}
	s.mu.Lock()
	raw := s.logLevel
	s.mu.Unlock()
	var p struct {
		Level string `json:"level"`
	}
	_ = json.Unmarshal(raw, &p)
	return p.Level
}

// listChangedKinds maps a capability to the subscriptions/listen field of
// its list changes.
var listChangedKinds = map[string]string{
	"tools":     "toolsListChanged",
	"prompts":   "promptsListChanged",
	"resources": "resourcesListChanged",
}

// listen (re)opens the instance's subscriptions/listen stream for the
// list changes the server announces and the resources clients subscribed
// to, and cancels the previous one. The stream is a request that stays
// open; it is not counted as in flight, so that it keeps no instance from
// idling. u.mu must not be held.
func (u *upstream) listen() {
	u.mu.Lock()
	filter := map[string]any{}
	for capability, field := range listChangedKinds {
		var c struct {
			ListChanged bool `json:"listChanged"`
		}
		if raw, ok := u.init.Capabilities[capability]; ok && json.Unmarshal(raw, &c) == nil && c.ListChanged {
			filter[field] = true
		}
	}
	if len(u.subscribed) > 0 {
		uris := make([]string, 0, len(u.subscribed))
		for uri := range u.subscribed {
			uris = append(uris, uri)
		}
		slices.Sort(uris)
		filter["resourceSubscriptions"] = uris
	}
	old := u.listenID
	u.listenID = nil
	var id json.RawMessage
	if len(filter) > 0 {
		id = json.RawMessage(strconv.Quote("listen-" + strconv.FormatInt(u.nextID.Add(1), 10)))
		u.listenID = id
	}
	u.mu.Unlock()
	if old != nil {
		_ = u.notify("notifications/cancelled", map[string]any{"requestId": old, "reason": "subscriptions changed"})
	}
	if id == nil {
		return
	}
	params, err := withMeta(map[string]any{"notifications": filter}, u.meta(nil, "subscriptions/listen"))
	if err == nil {
		var req *jsonrpc.Message
		if req, err = jsonrpc.NewRequest(id, "subscriptions/listen", params); err == nil {
			err = u.conn.Write(req)
		}
	}
	if err != nil {
		u.log.Warn("opening the subscription stream", "err", err)
	}
}

// subscribe changes the resources clients subscribed to on a modern
// server: resources/subscribe and resources/unsubscribe of legacy clients
// become the stream's resourceSubscriptions.
func (u *upstream) subscribe(params json.RawMessage, on bool) *jsonrpc.Message {
	var p struct {
		URI string `json:"uri"`
	}
	if json.Unmarshal(params, &p) != nil || p.URI == "" {
		return &jsonrpc.Message{JSONRPC: jsonrpc.Version, Error: &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "uri required"}}
	}
	u.mu.Lock()
	n := u.subscribed[p.URI]
	switch {
	case on:
		u.subscribed[p.URI] = n + 1
	case n > 1:
		u.subscribed[p.URI] = n - 1
	default:
		delete(u.subscribed, p.URI)
	}
	changed := (on && n == 0) || (!on && n == 1)
	u.mu.Unlock()
	if changed {
		u.listen()
	}
	return &jsonrpc.Message{JSONRPC: jsonrpc.Version, Result: json.RawMessage(`{}`)}
}

// stripSubscriptionMeta removes the subscription id from a notification
// a modern server sent on its stream: the gateway's clients did not open
// that stream.
func stripSubscriptionMeta(m *jsonrpc.Message) *jsonrpc.Message {
	var p map[string]json.RawMessage
	if json.Unmarshal(m.Params, &p) != nil {
		return m
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(p["_meta"], &meta) != nil || meta[metaSubscriptionID] == nil {
		return m
	}
	delete(meta, metaSubscriptionID)
	if len(meta) == 0 {
		delete(p, "_meta")
	} else if raw, err := json.Marshal(meta); err == nil {
		p["_meta"] = raw
	}
	params, err := json.Marshal(p)
	if err != nil {
		return m
	}
	return &jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: m.Method, Params: params}
}

// completeResult checks a result's resultType (MCP 2026-07-28): it
// returns the result without it, as legacy clients know results, and
// reports an interim result that asks the client for input
// ("input_required"), which the gateway does not pass on yet.
func completeResult(raw json.RawMessage) (json.RawMessage, bool) {
	var p map[string]json.RawMessage
	if json.Unmarshal(raw, &p) != nil {
		return raw, false
	}
	t, ok := p["resultType"]
	if !ok {
		return raw, false
	}
	var s string
	_ = json.Unmarshal(t, &s)
	if s == "input_required" {
		return raw, true
	}
	delete(p, "resultType")
	out, err := json.Marshal(p)
	if err != nil {
		return raw, false
	}
	return out, false
}

// inputMethods are the requests a modern server may answer with an
// InputRequiredResult: those get the client's capabilities.
var inputMethods = map[string]bool{"tools/call": true, "resources/read": true, "prompts/get": true}

// maxInputRounds bounds the input rounds of one call.
const maxInputRounds = 8

// serverCapabilities returns what the gateway declares to a modern server
// b on a request of s: of what the client declared, the capabilities to
// ask it for input (elicitation, its modes, sampling, roots) that policy
// lets b use. Anything else the client declared (extensions, tasks,
// experimental) is not passed on.
func (s *Session) serverCapabilities(b *config.Backend) map[string]any {
	caps := map[string]any{}
	allowed := func(method string, args map[string]any) bool {
		return pep.Evaluate(s.ctx, s.r.PDP, pep.Input{
			Principal: s.snapshotPrincipal(),
			Action:    backendRequests[method],
			Resource:  pep.Resource{Server: b.Name, Kind: "client", Name: method, Privileged: b.Privileged},
			Args:      args,
			Context:   s.policyContext(newDecisionID()),
		}).Effect == pep.Allow
	}
	modes := map[string]any{}
	for mode, raw := range s.elicitationModes() {
		if !allowed("elicitation/create", map[string]any{"mode": mode, "fields": []string{}, "sensitive": false}) {
			continue
		}
		var v any = map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &v)
		}
		modes[mode] = v
	}
	if len(modes) > 0 {
		caps["elicitation"] = modes
	}
	s.mu.Lock()
	declared := map[string]json.RawMessage{"sampling": s.clientCaps["sampling"], "roots": s.clientCaps["roots"]}
	s.mu.Unlock()
	for name, method := range map[string]string{"sampling": "sampling/createMessage", "roots": "roots/list"} {
		var v any
		if declared[name] == nil || json.Unmarshal(declared[name], &v) != nil || !allowed(method, nil) {
			continue
		}
		caps[name] = v
	}
	return caps
}

// inputRequired is an InputRequiredResult (MCP 2026-07-28).
type inputRequired struct {
	InputRequests map[string]struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	} `json:"inputRequests"`
	RequestState *string `json:"requestState"`
}

// answerInput asks the client for what a modern server's
// InputRequiredResult (raw) requests, each request decided and relayed as
// a request from the server would be, and sets the answers and the
// server's state in params for the call's next round. An elicitation
// the gateway or the client refuses is declined; a refused sampling or
// roots request ends the call (the round's answers have no error form).
func (s *Session) answerInput(ctx context.Context, u *upstream, raw json.RawMessage, params map[string]json.RawMessage) *jsonrpc.Error {
	var r inputRequired
	if err := json.Unmarshal(raw, &r); err != nil {
		return rpcError(jsonrpc.CodeInternalError, u.backend.Name+" asked for input in a malformed result")
	}
	keys := make([]string, 0, len(r.InputRequests))
	for k := range r.InputRequests {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	responses := make(map[string]json.RawMessage, len(keys))
	for _, k := range keys {
		in := r.InputRequests[k]
		reply := s.relayBackendRequest(ctx, u, &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: json.RawMessage(strconv.Quote(k)), Method: in.Method, Params: in.Params}, requestOf(ctx))
		switch {
		case reply.Error == nil:
			responses[k] = reply.Result
		case in.Method == "elicitation/create":
			responses[k] = json.RawMessage(`{"action":"decline"}`)
		default:
			return &jsonrpc.Error{Code: reply.Error.Code, Message: fmt.Sprintf("%s asked the client (%s): %s", u.backend.Name, in.Method, reply.Error.Message)}
		}
	}
	delete(params, "inputResponses")
	delete(params, "requestState")
	if len(responses) > 0 {
		params["inputResponses"], _ = json.Marshal(responses)
	}
	if r.RequestState != nil {
		params["requestState"], _ = json.Marshal(*r.RequestState)
	}
	return nil
}
