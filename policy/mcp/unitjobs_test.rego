package mcp.unitjobs_test

import rego.v1

import data.mcp.authz

# User guide, chapter 13, "Root jobs as units": a role starts the one unit
# without approval; any other unit or action of change_unit_state falls
# through to the approval permission.

unit_rbac := {
	"roles": {"sysops": {"permissions": [
		{"server": "systemd", "tool": "change_unit_state", "args": {"name": "^zypper-refresh\\.service$", "action": "^start$"}},
		{"server": "systemd", "tool": "*", "require_approval": true, "approval_channel": "oob"},
	]}},
	"bindings": {"users": {"alice": ["sysops"]}, "groups": {}},
}

alice := {"sub": "alice", "groups": ["alice"], "transport": "unix", "session_id": "s1"}

change(args) := {
	"principal": alice,
	"action": "tools.call",
	"resource": {"server": "systemd", "kind": "tool", "name": "change_unit_state"},
	"args": args,
	"grants": [],
}

test_unit_job_started_without_approval if {
	d := authz.decision with input as change({"name": "zypper-refresh.service", "action": "start", "timeout": 30})
		with data.mcp.rbac as unit_rbac
	d.effect == "allow"
}

test_other_action_on_the_unit_asks if {
	d := authz.decision with input as change({"name": "zypper-refresh.service", "action": "stop"})
		with data.mcp.rbac as unit_rbac
	d.effect == "ask"
}

test_other_unit_asks if {
	d := authz.decision with input as change({"name": "sshd.service", "action": "start"})
		with data.mcp.rbac as unit_rbac
	d.effect == "ask"
}

test_unit_name_is_anchored if {
	d := authz.decision with input as change({"name": "zypper-refresh.service.d/../sshd.service", "action": "start"})
		with data.mcp.rbac as unit_rbac
	d.effect == "ask"
}
