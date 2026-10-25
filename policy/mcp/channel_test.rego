package mcp.channel_test

import rego.v1

import data.mcp.authz
import data.mcp.filter

alice := {"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "unix", "session_id": "s1"}

call(principal, server, tool) := {
	"principal": principal,
	"action": "tools.call",
	"resource": {"server": server, "kind": "tool", "name": tool},
	"args": {},
	"grants": [],
}

roles(perms) := {"developer": {"permissions": perms}}

# Several approvable permissions with different channels: the strictest
# (oob, then url, then form), never a conflict that fails the decision.
test_strictest_of_three if {
	perms := [
		{"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "form"},
		{"server": "fs", "tool": "write_*", "require_approval": true},
		{"server": "fs", "tool": "*", "require_approval": true, "approval_channel": "oob"},
	]
	d := authz.decision with input as call(alice, "fs", "write_file") with data.mcp.rbac.roles as roles(perms)
	d.effect == "ask"
	d.ask.channel == "oob"
}

# form is answered by the agent's own client: url is the stricter one.
test_url_over_form if {
	perms := [
		{"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "form"},
		{"server": "fs", "tool": "write_*", "require_approval": true, "approval_channel": "url"},
	]
	d := authz.decision with input as call(alice, "fs", "write_file") with data.mcp.rbac.roles as roles(perms)
	d.ask.channel == "url"
}

test_single_channel_kept if {
	perms := [{"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "form"}]
	d := authz.decision with input as call(alice, "fs", "write_file") with data.mcp.rbac.roles as roles(perms)
	d.ask.channel == "form"
}

test_default_url if {
	perms := [{"server": "fs", "tool": "write_file", "require_approval": true}]
	d := authz.decision with input as call(alice, "fs", "write_file") with data.mcp.rbac.roles as roles(perms)
	d.ask.channel == "url"
}

# An unknown channel counts as the strictest; two of them, by name: one.
test_unknown_channels_one_answer if {
	perms := [
		{"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "pager"},
		{"server": "fs", "tool": "write_*", "require_approval": true, "approval_channel": "chat"},
		{"server": "fs", "tool": "*", "require_approval": true, "approval_channel": "oob"},
	]
	d := authz.decision with input as call(alice, "fs", "write_file") with data.mcp.rbac.roles as roles(perms)
	d.ask.channel == "pager"
}

# Issue #298: a member of wheel (admin, server "*", default channel url)
# also bound to a setup role that asks out of band. On a privileged
# server admin's wildcard asks too; the ask goes out of band.
test_privileged_admin_and_oob_operator if {
	op := {"sub": "drahn", "groups": ["wheel"], "home": "/home/drahn", "transport": "unix", "session_id": "s1"}
	inp := object.union(call(op, "tukit", "reboot"), {"resource": {"server": "tukit", "kind": "tool", "name": "reboot", "privileged": true}})
	d := authz.decision with input as inp
		with data.mcp.rbac.roles as {
			"admin": {"permissions": [{"server": "*", "tool": "*"}]},
			"tukit-operator": {"permissions": [{"server": "tukit", "tool": "*", "require_approval": true, "approval_channel": "oob"}]},
		}
		with data.mcp.rbac.bindings as {"groups": {"wheel": ["admin", "tukit-operator"]}, "users": {}}
	d.effect == "ask"
	d.ask.channel == "oob"
}

# The listing works with such permissions (it once failed whole, hiding
# every tool of every server).
test_listing_with_differing_channels if {
	resources := [
		{"server": "fs", "kind": "tool", "name": "read_file"},
		{"server": "fs", "kind": "tool", "name": "write_file"},
	]
	v := filter.visible with input as {"principal": alice, "resources": resources}
		with data.mcp.rbac.roles as {"developer": {"permissions": [
			{"server": "fs", "tool": "read_file"},
			{"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "oob"},
			{"server": "fs", "tool": "write_*", "require_approval": true},
		]}}
	count(v) == 2
}
