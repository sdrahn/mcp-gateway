package httpsetup

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// Change is a key of the http block that the setup changes.
type Change struct {
	Key, Old, New string
}

// scalars are the keys of the http block the setup asks about, but
// scopes, with their values in h ("" keeps what the block has).
func scalars(h config.HTTP) []struct{ key, v string } {
	return []struct{ key, v string }{
		{"listen", h.Listen}, {"cert_file", h.CertFile}, {"key_file", h.KeyFile},
		{"issuer", h.Issuer}, {"audience", h.Audience},
		{"groups_claim", h.GroupsClaim}, {"local_user_claim", h.LocalUserClaim},
	}
}

// Changes returns what setting the keys the setup asks about from h
// changes in cur, the http block in force (gateway.yaml and its
// drop-ins).
func Changes(cur, h config.HTTP) []Change {
	var out []Change
	have := map[string]string{}
	for _, kv := range scalars(cur) {
		have[kv.key] = kv.v
	}
	for _, kv := range scalars(h) {
		if kv.v != "" && kv.v != have[kv.key] {
			out = append(out, Change{"http." + kv.key, have[kv.key], kv.v})
		}
	}
	if h.Scopes != nil && fmt.Sprint(cur.Scopes) != fmt.Sprint(h.Scopes) {
		out = append(out, Change{"http.scopes", fmt.Sprint(cur.Scopes), fmt.Sprint(h.Scopes)})
	}
	return out
}

// Node is the YAML value of key (http.listen, …) in h, as the drop-in
// has it.
func Node(h config.HTTP, key string) *yaml.Node {
	if key == "http.scopes" {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle, Tag: "!!seq"}
		for _, s := range h.Scopes {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s})
		}
		return seq
	}
	for _, kv := range scalars(h) {
		if "http."+kv.key == key {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv.v}
		}
	}
	return nil
}
