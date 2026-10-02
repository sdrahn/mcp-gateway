package router

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Policy decides on parameters as the gateway decodes them, with exact
// keys. A server that decodes them case-insensitively (encoding/json into
// structs, as Go servers do) would read {"Arguments": …} or {"Path": …}
// where the gateway saw no arguments or no path. So a key that differs
// only in case from one the gateway reads, or from an argument the tool
// or prompt declares, is refused (jsonrpc.CheckKeys refuses repeated keys
// and keys that differ only in case within an object).

// paramKeys are the keys of request parameters the gateway reads.
var paramKeys = map[string][]string{
	"":      {"name", "arguments", "uri", "ref", "argument", "context", "_meta", "cursor"},
	"ref":   {"type", "name", "uri"},
	"_meta": {"progressToken"},
}

// checkParamKeys refuses keys of params (and of its ref and _meta) that
// equal a key the gateway reads but for case.
func checkParamKeys(params map[string]json.RawMessage) error {
	if err := caseVariant(params, paramKeys[""], "params"); err != nil {
		return err
	}
	for _, nested := range []string{"ref", "_meta"} {
		var m map[string]json.RawMessage
		if json.Unmarshal(params[nested], &m) != nil {
			continue
		}
		if err := caseVariant(m, paramKeys[nested], nested); err != nil {
			return err
		}
	}
	return nil
}

// caseVariant reports a key of m that is not in names but equals one of
// them but for case.
func caseVariant[V any](m map[string]V, names []string, where string) error {
	for k := range m {
		if slices.Contains(names, k) {
			continue
		}
		for _, n := range names {
			if strings.EqualFold(k, n) {
				return fmt.Errorf("%s: key %q differs from %q only in case", where, k, n)
			}
		}
	}
	return nil
}

// argNames returns the argument names a list item declares: the
// properties of a tool's inputSchema, the names of a prompt's arguments.
func argNames(kind string, raw map[string]json.RawMessage) []string {
	var names []string
	switch kind {
	case "tool":
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		_ = json.Unmarshal(raw["inputSchema"], &schema)
		for n := range schema.Properties {
			names = append(names, n)
		}
	case "prompt":
		var args []struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(raw["arguments"], &args)
		for _, a := range args {
			names = append(names, a.Name)
		}
	}
	slices.Sort(names)
	return names
}

func argKey(kind, server, name string) string { return kind + "\x00" + server + "\x00" + name }

// rememberArgs records the declared arguments of listed items.
func (s *Session) rememberArgs(kind string, items []listItem) {
	if kind != "tool" && kind != "prompt" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.declared == nil {
		s.declared = map[string][]string{}
	}
	for _, it := range items {
		s.declared[argKey(kind, it.server, it.name)] = argNames(kind, it.raw)
	}
}

// declaredArgs returns the argument names server declares for the tool or
// prompt name, listing the server's tools or prompts if this session has
// not. ok is false if they cannot be had.
func (s *Session) declaredArgs(ctx context.Context, kind, server, name string) (names []string, ok bool) {
	key := argKey(kind, server, name)
	s.mu.Lock()
	names, ok = s.declared[key]
	s.mu.Unlock()
	if ok {
		return names, true
	}
	method := map[string]string{"tool": "tools/list", "prompt": "prompts/list"}[kind]
	items, err := s.fetchList(ctx, server, method, listSpecs[method])
	if err != nil {
		return nil, false
	}
	s.rememberArgs(kind, items)
	s.mu.Lock()
	names, ok = s.declared[key]
	s.mu.Unlock()
	return names, ok
}

// checkArgNames refuses arguments whose name equals a declared argument
// but for case.
func (s *Session) checkArgNames(ctx context.Context, t *callTarget) error {
	if len(t.args) == 0 || (t.resource.Kind != "tool" && t.resource.Kind != "prompt") {
		return nil
	}
	names, ok := s.declaredArgs(ctx, t.resource.Kind, t.server, t.resource.Name)
	if !ok {
		return nil // unknown to the server: it will refuse the call itself
	}
	return caseVariant(t.args, names, "arguments")
}
