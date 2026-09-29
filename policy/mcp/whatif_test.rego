package mcp.whatif_test

import rego.v1

import data.mcp.whatif

rbac := {
	"roles": {
		"viewer": {"permissions": [{"server": "*", "tool": "read_*"}]},
		"writer": {"permissions": [{"server": "fs", "tool": "write_*", "require_approval": true}]},
	},
	"bindings": {"users": {"alice": ["viewer"]}, "groups": {}},
}

principals := [
	{"label": "user:alice", "principal": {"sub": "alice", "uid": 1000, "groups": ["users"], "transport": "unix"}},
	{"label": "group:dev", "principal": {"sub": "", "groups": ["dev"], "transport": "unix"}},
]

resources := [
	{"server": "fs", "kind": "tool", "name": "read_file"},
	{"server": "fs", "kind": "tool", "name": "write_file"},
	{"server": "fs", "kind": "client", "name": "sampling/createMessage"},
]

query(proposed) := {"principals": principals, "resources": resources, "proposed": proposed}

test_no_change if {
	count(whatif.changes) == 0 with input as query(rbac) with data.mcp.rbac as rbac
}

test_binding_added if {
	proposed := object.union(rbac, {"bindings": {"users": {"alice": ["viewer", "writer"]}, "groups": {"dev": ["viewer"]}}})
	whatif.changes == {
		{"principal": "user:alice", "server": "fs", "kind": "tool", "name": "write_file", "before": "deny", "after": "ask"},
		{"principal": "group:dev", "server": "fs", "kind": "tool", "name": "read_file", "before": "deny", "after": "allow"},
	} with input as query(proposed) with data.mcp.rbac as rbac
}

test_deny_added if {
	proposed := object.union(rbac, {"roles": {
		"viewer": {"permissions": [
			{"server": "*", "tool": "read_*"},
			{"server": "fs", "tool": "read_*", "effect": "deny"},
		]},
		"writer": rbac.roles.writer,
	}})
	whatif.changes == {
		{"principal": "user:alice", "server": "fs", "kind": "tool", "name": "read_file", "before": "allow", "after": "deny"},
	} with input as query(proposed) with data.mcp.rbac as rbac
}

test_client_requests if {
	proposed := object.union(rbac, {"roles": {
		"viewer": {"permissions": [{"server": "*", "tool": "read_*"}, {"server": "*", "client": "sampling/*"}]},
		"writer": rbac.roles.writer,
	}})
	whatif.changes == {
		{"principal": "user:alice", "server": "fs", "kind": "client", "name": "sampling/createMessage", "before": "deny", "after": "allow"},
	} with input as query(proposed) with data.mcp.rbac as rbac
}

# Data from other files below data.mcp.rbac is kept.
test_other_data_kept if {
	with_extra := object.union(rbac, {"managers": {"alice": "bob"}})
	whatif.proposed.managers == {"alice": "bob"} with input as {"proposed": rbac} with data.mcp.rbac as with_extra
}
