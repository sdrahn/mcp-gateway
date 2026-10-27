package jsonrpc

import "encoding/json"

// RelatedMeta is the _meta key mcp-http-connector puts on a request or
// notification of an HTTP server that came on the event stream of one of
// the gateway's requests: that request's id. The gateway routes it to the
// client request the call serves (docs/architecture.md, roadmap step 44)
// and removes the key; over stdio, where nothing tells, it is not trusted.
const RelatedMeta = "io.github.sdrahn.mcp-gateway/relatedRequest"

// SetRelated returns the message raw (a request or notification) with
// RelatedMeta set to id in its params' _meta; raw as it is if it is not
// an object with object params.
func SetRelated(raw json.RawMessage, id json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return raw
	}
	params := map[string]json.RawMessage{}
	if p, ok := m["params"]; ok && json.Unmarshal(p, &params) != nil {
		return raw
	}
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	meta := map[string]json.RawMessage{}
	if mt, ok := params["_meta"]; ok && json.Unmarshal(mt, &meta) != nil {
		return raw
	}
	if meta == nil {
		meta = map[string]json.RawMessage{}
	}
	meta[RelatedMeta] = id
	params["_meta"], _ = json.Marshal(meta)
	m["params"], _ = json.Marshal(params)
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// TakeRelated removes RelatedMeta from m's params and returns its value
// (nil if absent). An emptied _meta goes too.
func TakeRelated(m *Message) json.RawMessage {
	var params map[string]json.RawMessage
	if len(m.Params) == 0 || json.Unmarshal(m.Params, &params) != nil || params == nil {
		return nil
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) != nil || meta == nil {
		return nil
	}
	id, ok := meta[RelatedMeta]
	if !ok {
		return nil
	}
	delete(meta, RelatedMeta)
	if len(meta) == 0 {
		delete(params, "_meta")
	} else {
		params["_meta"], _ = json.Marshal(meta)
	}
	if b, err := json.Marshal(params); err == nil {
		m.Params = b
	}
	return id
}
