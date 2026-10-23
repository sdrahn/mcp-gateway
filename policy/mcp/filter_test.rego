package mcp.filter_test

import rego.v1

import data.mcp.authz
import data.mcp.filter

# The filter works out the principal's parts of the decision once per
# listing; what it shows and hints must still be what deciding every
# resource on its own gives (as the filter did before 1.7).

roles := {
	"viewer": {"permissions": [
		{"server": "*", "tool": "list_*"},
		{"server": "*", "tool": "read_*"},
		{"server": "*", "prompt": "*"},
	]},
	"developer": {"permissions": [
		{"server": "fs", "tool": "read_*"},
		{"server": "fs", "resource": "file://${home}/*"},
		{"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "url", "args": {"path": "^${home}/"}},
		{"server": "fs", "tool": "delete_*", "effect": "deny"},
		{"server": "f?", "tool": "move_file", "args": {"source": "^${home}/", "destination": "^/srv/${sub}/"}},
		{"server": "git", "tool": "*", "require_client_cert": true},
	]},
	"ops": {"permissions": [
		{"server": "systemd", "tool": "*"},
		{"server": "systemd", "tool": "stop_unit", "require_approval": true, "approval_channel": "oob"},
	]},
}

# A role a server setup ships, and one the administrator replaces.
profiles := {"podman": {"roles": {
	"podman-user": {"permissions": [{"server": "podman", "tool": "*"}]},
	"ops": {"permissions": [{"server": "nothing", "tool": "*"}]},
}}}

rbac := {
	"roles": roles,
	"bindings": {
		"users": {"carol": ["ops", "podman-user"]},
		"groups": {"dev": ["developer", "viewer"], "users": ["viewer"]},
	},
	"scopes": {
		"mcp:read": {"roles": ["viewer"]},
		"mcp:fs": {"permissions": [{"server": "fs", "tool": "*"}, {"server": "fs", "resource": "*"}]},
	},
}

principals := [
	{"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "unix", "session_id": "s1"},
	{"sub": "alice", "groups": ["dev"], "transport": "unix", "session_id": "s2"},
	{"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "http", "session_id": "s3", "cert": {"subject": "CN=alice"}},
	{"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "http", "session_id": "s4", "scopes": ["mcp:read"]},
	{"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "http", "session_id": "s5", "scopes": ["mcp:fs"]},
	{"sub": "carol", "groups": ["users"], "transport": "unix", "session_id": "s6"},
	{"sub": "dave", "groups": [], "roles": ["ops"], "transport": "unix", "session_id": "s7"},
	{"sub": "nobody", "groups": [], "transport": "unix", "session_id": "s8"},
]

tool(server, name) := {"server": server, "kind": "tool", "name": name}

resources := [
	tool("fs", "read_file"),
	tool("fs", "write_file"),
	tool("fs", "delete_file"),
	tool("fs", "move_file"),
	tool("fs", "list_directory"),
	tool("git", "commit"),
	tool("git", "read_log"),
	tool("systemd", "stop_unit"),
	tool("systemd", "list_units"),
	object.union(tool("systemd", "restart_unit"), {"privileged": true}),
	tool("podman", "list_containers"),
	tool("nothing", "x"),
	object.union(tool("crm", "sign_in"), {"sign_in": true}),
	object.union(tool("mcp-gateway", "capabilities"), {"builtin": true}),
	{"server": "fs", "kind": "prompt", "name": "summarize"},
	{"server": "fs", "kind": "resource", "name": "file:///home/alice/notes.txt"},
	{"server": "fs", "kind": "resource", "name": "file:///home/alice/../bob/x"},
	{"server": "fs", "kind": "resource_template", "name": "file:///{path}"},
	{"server": "git", "kind": "resource_template", "name": "git://{repo}"},
]

# The input of each resource's own decision, as the filter's before 1.7.
own_input(p, r, action) := {
	"principal": p,
	"action": action,
	"resource": r,
	"grants": [],
	"discovery": true,
}

test_visible_as_decided_one_by_one if {
	every p in principals {
		v := filter.visible with input as {"principal": p, "resources": resources}
			with data.mcp.rbac as rbac
			with data.mcp.profiles as profiles
		want := {r |
			some r in resources
			d := authz.decision with input as own_input(p, r, filter.use_action[r.kind])
			d.effect != "deny"
		} with data.mcp.rbac as rbac with data.mcp.profiles as profiles
		v == want
	}
}

# The test above is not vacuous: listings differ by principal.
test_visible_differs_by_principal if {
	sizes := {n |
		some p in principals
		v := filter.visible with input as {"principal": p, "resources": resources}
			with data.mcp.rbac as rbac
			with data.mcp.profiles as profiles
		n := count(v)
	}
	count(sizes) > 3
}

test_hints_as_decided_one_by_one if {
	every p in principals {
		h := filter.hints with input as {"principal": p, "resources": resources}
			with data.mcp.rbac as rbac
			with data.mcp.profiles as profiles
		want := {hint |
			some r in resources
			r.kind == "tool"
			d := authz.decision with input as own_input(p, r, "tools.call")
			d.effect != "deny"
			m := authz.matching with input as own_input(p, r, "tools.call")
			perms := {q | some q in m; not q.effect == "deny"}
			args := filter.arg_limits(perms) with input as {"principal": p}
			approval := object.get(object.get(d, "ask", {}), "channel", "")
			count(args) + count(approval) > 0
			hint := {"server": r.server, "name": r.name, "approval": approval, "args": args}
		} with data.mcp.rbac as rbac with data.mcp.profiles as profiles
		h == want
	}
}

test_hints_found if {
	h := filter.hints with input as {"principal": principals[0], "resources": resources}
		with data.mcp.rbac as rbac
		with data.mcp.profiles as profiles
	{[x.name, x.approval] | some x in h} == {["write_file", "url"], ["move_file", ""]}
}

# Filtering gives no obligations to work out; calls get them.
test_discovery_decision_without_obligations if {
	with_obligation := {"crm": {"permissions": [{"server": "crm", "tool": "*", "obligations": {"redact_output": ["x"]}}]}}
	in_doc := {"principal": {"sub": "eve", "roles": ["crm"], "transport": "unix"}, "action": "tools.call", "resource": tool("crm", "get"), "grants": []}
	call := authz.decision with input as in_doc with data.mcp.rbac.roles as with_obligation
	call.obligations.redact_output == ["x"]
	listed := authz.decision with input as object.union(in_doc, {"discovery": true}) with data.mcp.rbac.roles as with_obligation
	listed == {"effect": "allow"}
}
