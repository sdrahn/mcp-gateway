package mcp.hints_test

import rego.v1

import data.mcp.filter

bob := {"sub": "bob", "groups": [], "home": "/home/bob", "transport": "unix", "session_id": "s1"}

rbac := {
	"roles": {"ops": {"permissions": [
		{"server": "systemd", "tool": "get_file", "args": {"path": "^/(etc|usr/lib)/systemd/"}},
		{"server": "systemd", "tool": "restart_unit", "require_approval": true, "approval_channel": "oob"},
		{"server": "systemd", "tool": "list_units"},
		{"server": "fs", "tool": "write_file", "args": {"path": "^${home}/"}},
		{"server": "fs", "tool": "write_file", "args": {"path": "^/srv/share/"}},
		{"server": "fs", "tool": "read_file", "args": {"path": "^${home}/"}},
		{"server": "fs", "tool": "read_*"},
		{"server": "fs", "tool": "delete_file", "effect": "deny"},
	]}},
	"bindings": {"users": {"bob": ["ops"]}, "groups": {}},
}

tool(server, name) := {"server": server, "kind": "tool", "name": name}

# Argument constraints, expanded for the principal; a tool covered by
# several permissions lists each.
test_hints_args if {
	resources := [tool("systemd", "get_file"), tool("fs", "write_file")]
	h := filter.hints with input as {"principal": bob, "resources": resources}
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	h == {
		{"server": "systemd", "name": "get_file", "approval": "", "args": [{"path": "^/(etc|usr/lib)/systemd/"}]},
		{"server": "fs", "name": "write_file", "approval": "", "args": [{"path": "^/home/bob/"}, {"path": "^/srv/share/"}]},
	}
}

# An approval names its channel.
test_hints_approval if {
	h := filter.hints with input as {"principal": bob, "resources": [tool("systemd", "restart_unit")]}
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	h == {{"server": "systemd", "name": "restart_unit", "approval": "oob", "args": []}}
}

# No hint for a tool allowed without limits (also when one of several
# permissions has none), a denied tool, an unknown one, or a non-tool.
test_hints_none if {
	resources := [
		tool("systemd", "list_units"),
		tool("fs", "read_file"),
		tool("fs", "delete_file"),
		tool("db", "query"),
		{"server": "fs", "kind": "prompt", "name": "x"},
	]
	h := filter.hints with input as {"principal": bob, "resources": resources}
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	count(h) == 0
}
