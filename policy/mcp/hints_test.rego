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

call(server, name, args) := {
	"principal": bob,
	"action": "tools.call",
	"resource": tool(server, name),
	"args": args,
	"grants": [],
}

# A denial for arguments outside the roles' constraints names them
# (expanded, one per permission), never the arguments sent.
test_reason_names_arg_limits if {
	d := data.mcp.authz.decision with input as call("systemd", "get_file", {"path": "/run/netns/x"})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	d.effect == "deny"
	d.reason == "no matching permission: the arguments are outside what your roles allow (path: ^/(etc|usr/lib)/systemd/)"
	not contains(d.reason, "/run/netns")

	w := data.mcp.authz.decision with input as call("fs", "write_file", {"path": "/etc/x"})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	w.reason == "no matching permission: the arguments are outside what your roles allow (path: ^/home/bob/; or path: ^/srv/share/)"
}

# Without a permission naming the tool, and for an explicit deny, the
# reasons stay as they were; arguments within the limits are allowed.
test_reason_unchanged_otherwise if {
	d := data.mcp.authz.decision with input as call("systemd", "stop_unit", {})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	d.reason == "no matching permission"

	x := data.mcp.authz.decision with input as call("fs", "delete_file", {"path": "/home/bob/x"})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	x.reason == "denied by policy"

	a := data.mcp.authz.decision with input as call("systemd", "get_file", {"path": "/etc/systemd/system.conf"})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	a.effect == "allow"
}

capabilities(principal) := {
	"principal": principal,
	"action": "tools.call",
	"resource": {"server": "mcp-gateway", "kind": "tool", "name": "capabilities", "builtin": true},
	"args": {},
	"grants": [],
}

# gateway_capabilities: allowed to a principal holding a permission
# without approval, denied to one without any.
test_capabilities_tool if {
	d := data.mcp.authz.decision with input as capabilities(bob)
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	d.effect == "allow"

	n := data.mcp.authz.decision with input as capabilities({"sub": "nobody", "session_id": "s2"})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	n.effect == "deny"

	# Not for a resource of a server that is not marked builtin.
	r := data.mcp.authz.decision with input as call("mcp-gateway", "capabilities", {})
		with data.mcp.rbac as rbac
		with data.mcp.profiles as {}
	r.effect == "deny"
}
