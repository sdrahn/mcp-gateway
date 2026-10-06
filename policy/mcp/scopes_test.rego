package mcp.scopes_test

import rego.v1

import data.mcp.authz
import data.mcp.filter

alice := {"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "unix", "session_id": "s1"}

call(principal, server, tool, args) := {
	"principal": principal,
	"action": "tools.call",
	"resource": {"server": server, "kind": "tool", "name": tool},
	"args": args,
	"grants": [],
}

# Token scopes as a ceiling (docs/architecture.md, section 6.7, D17).

scope_map := {
	"mcp:read": {"roles": ["viewer"]},
	"mcp:git": {"permissions": [{"server": "git", "tool": "*"}]},
	"mcp:admin": {"unlimited": true},
}

with_scopes(token_scopes) := object.union(alice, {"transport": "http", "iss": "https://idp.example.com", "scopes": token_scopes})

test_scope_ceiling_narrows if {
	# The roles allow git commit; mcp:read allows only read_* and the like.
	d := authz.decision with input as call(with_scopes(["mcp:read"]), "git", "commit", {})
		with data.mcp.rbac.scopes as scope_map
	d.effect == "deny"
	d.outside_scopes == true
	d.reason == "outside the token's scopes"
	d.required_scopes == ["mcp:git", "mcp:admin"]

	authz.decision.effect == "allow" with input as call(with_scopes(["mcp:read"]), "git", "read_log", {})
		with data.mcp.rbac.scopes as scope_map
}

test_scope_ceilings_add_up if {
	authz.decision.effect == "allow" with input as call(with_scopes(["mcp:read", "mcp:git"]), "git", "commit", {})
		with data.mcp.rbac.scopes as scope_map
	authz.decision.effect == "allow" with input as call(with_scopes(["mcp:admin"]), "git", "commit", {})
		with data.mcp.rbac.scopes as scope_map
}

test_scope_ceiling_never_grants if {
	# admin's ceiling is unlimited, but alice's roles do not allow db.
	d := authz.decision with input as call(with_scopes(["mcp:admin"]), "db", "query", {})
		with data.mcp.rbac.scopes as scope_map
	d.effect == "deny"
	d.reason == "no matching permission"
	not d.outside_scopes
}

test_scope_ceiling_denies_instead_of_asking if {
	# The roles ask for write_file; outside the ceiling it is denied, so
	# no approval can lift it.
	d := authz.decision with input as call(with_scopes(["mcp:git"]), "fs", "write_file", {"path": "/home/alice/x"})
		with data.mcp.rbac.scopes as scope_map
	d.effect == "deny"
	d.outside_scopes == true
	d.required_scopes == ["mcp:admin"]
}

test_scope_explicit_deny_first if {
	d := authz.decision with input as call(with_scopes(["mcp:git"]), "fs", "delete_file", {"path": "/home/alice/x"})
		with data.mcp.rbac.scopes as scope_map
	d.reason == "denied by policy"
}

test_scope_unnamed_scopes_and_default if {
	# No named scope and no default: as without a map.
	authz.decision.effect == "allow" with input as call(with_scopes(["openid", "profile"]), "git", "commit", {})
		with data.mcp.rbac.scopes as scope_map

	# A default ceiling applies to tokens without a named scope.
	narrow := object.union(scope_map, {"default": {"permissions": []}})
	d := authz.decision with input as call(with_scopes(["openid"]), "git", "commit", {})
		with data.mcp.rbac.scopes as narrow
	d.outside_scopes == true

	# ... but not to tokens that carry one.
	authz.decision.effect == "allow" with input as call(with_scopes(["mcp:git"]), "git", "commit", {})
		with data.mcp.rbac.scopes as narrow
}

test_scope_local_principals_unlimited if {
	# Local principals have no token: the default does not apply to them.
	narrow := object.union(scope_map, {"default": {"permissions": []}})
	authz.decision.effect == "allow" with input as call(alice, "git", "commit", {})
		with data.mcp.rbac.scopes as narrow
}

test_scope_ceiling_role_denies_ignored if {
	# developer's "delete_*" deny is not part of a ceiling of its permissions;
	# it still denies through the roles.
	c := {"mcp:dev": {"roles": ["developer"]}}
	authz.decision.effect == "allow" with input as call(with_scopes(["mcp:dev"]), "git", "commit", {})
		with data.mcp.rbac.scopes as c
}

test_scope_ceiling_args if {
	c := {"mcp:tmp": {"permissions": [{"server": "fs", "tool": "write_file", "args": {"path": "^/home/alice/tmp/"}}]}}
	authz.decision.effect == "ask" with input as call(with_scopes(["mcp:tmp"]), "fs", "write_file", {"path": "/home/alice/tmp/x"})
		with data.mcp.rbac.scopes as c
	authz.decision.outside_scopes with input as call(with_scopes(["mcp:tmp"]), "fs", "write_file", {"path": "/home/alice/x"})
		with data.mcp.rbac.scopes as c
}

test_filter_hides_outside_scopes if {
	resources := [
		{"server": "git", "kind": "tool", "name": "commit"},
		{"server": "git", "kind": "tool", "name": "read_log"},
		{"server": "fs", "kind": "tool", "name": "write_file"},
	]
	v := filter.visible with input as {"principal": with_scopes(["mcp:read"]), "resources": resources}
		with data.mcp.rbac.scopes as scope_map
	v == {{"server": "git", "kind": "tool", "name": "read_log"}}
}
