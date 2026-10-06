package policydata

import (
	"reflect"
	"testing"
)

// The ceiling is chosen as the shipped policy does: the token's scopes in
// the map, else "default", else none.
func TestCeilingOf(t *testing.T) {
	data := []byte(`{"scopes": {
	  "mcp:read": {"roles": ["viewer"]},
	  "mcp:git": {"roles": ["viewer"], "permissions": [{"server": "git", "tool": "*"}]},
	  "mcp:admin": {"unlimited": true},
	  "default": {"roles": ["guest"]}
	}}`)
	for _, tc := range []struct {
		scopes []string
		want   Ceiling
	}{
		{[]string{"openid", "mcp:read"}, Ceiling{Map: true, Scopes: []string{"mcp:read"}, Roles: []string{"viewer"}}},
		{[]string{"mcp:read", "mcp:git"}, Ceiling{Map: true, Scopes: []string{"mcp:git", "mcp:read"}, Roles: []string{"viewer"}, Permissions: 1}},
		{[]string{"mcp:admin", "default"}, Ceiling{Map: true, Scopes: []string{"mcp:admin"}, Unlimited: true}},
		{[]string{"openid"}, Ceiling{Map: true, Scopes: []string{"default"}, Roles: []string{"guest"}}},
	} {
		if got, err := CeilingOf(data, tc.scopes); err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: %+v %v, want %+v", tc.scopes, got, err, tc.want)
		}
	}
	if got, _ := CeilingOf([]byte(`{"scopes": {"mcp:read": {"roles": ["viewer"]}}}`), []string{"mcp"}); !got.Map || got.Scopes != nil {
		t.Errorf("no default: %+v", got)
	}
	if got, _ := CeilingOf([]byte(`{"roles": {}}`), []string{"mcp:read"}); got.Map || got.Scopes != nil {
		t.Errorf("no map: %+v", got)
	}
}
