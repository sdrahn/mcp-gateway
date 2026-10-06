package policydata

import (
	"encoding/json"
	"slices"
)

// Ceiling is what a token's scopes let a remote principal do at most
// (docs/architecture.md, section 6.7), as the shipped policy chooses it
// from the role data's scopes map: the ceilings of the token's scopes in
// the map, else that of "default", else none.
type Ceiling struct {
	// Map reports whether the role data has a scopes map.
	Map bool
	// Scopes are the scopes whose ceilings apply (["default"] for the
	// default); none means the token is not limited.
	Scopes []string
	// Unlimited reports whether one of them is unlimited.
	Unlimited bool
	// Roles and Permissions are what the ceilings name (roles sorted,
	// permissions counted).
	Roles       []string
	Permissions int
}

// CeilingOf returns the ceiling of a token with tokenScopes under the
// role data data.
func CeilingOf(data []byte, tokenScopes []string) (Ceiling, error) {
	var d struct {
		Scopes map[string]struct {
			Roles       []string          `json:"roles"`
			Permissions []json.RawMessage `json:"permissions"`
			Unlimited   bool              `json:"unlimited"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return Ceiling{}, err
	}
	c := Ceiling{Map: d.Scopes != nil}
	for _, s := range tokenScopes {
		if _, ok := d.Scopes[s]; ok && s != "default" && !slices.Contains(c.Scopes, s) {
			c.Scopes = append(c.Scopes, s)
		}
	}
	if _, ok := d.Scopes["default"]; ok && len(c.Scopes) == 0 {
		c.Scopes = []string{"default"}
	}
	slices.Sort(c.Scopes)
	for _, s := range c.Scopes {
		e := d.Scopes[s]
		c.Unlimited = c.Unlimited || e.Unlimited
		c.Roles = append(c.Roles, e.Roles...)
		c.Permissions += len(e.Permissions)
	}
	slices.Sort(c.Roles)
	c.Roles = slices.Compact(c.Roles)
	return c, nil
}
