package mcp.denyreasons_test

import rego.v1

import data.mcp.authz

# Reasons a policy module gives for a denial (deny_reasons) and for a
# request that matches no permission (unmatched_reasons). A module's
# rules are stood in for with "with".

alice := {"sub": "alice", "groups": ["alice"], "home": "/home/alice", "transport": "unix", "session_id": "s1"}

rbac := {
	"roles": {"ops": {"permissions": [
		{"server": "fs", "tool": "read_*"},
		{"server": "fs", "tool": "write_file", "args": {"path": "^${home}/"}},
		{"server": "fs", "tool": "delete_file", "effect": "deny"},
		{"server": "systemd", "tool": "restart_unit", "require_approval": true, "approval_channel": "oob"},
	]}},
	"bindings": {"users": {"alice": ["ops"]}, "groups": {}},
}

call(server, tool, args) := {
	"principal": alice,
	"action": "tools.call",
	"resource": {"server": server, "kind": "tool", "name": tool},
	"args": args,
	"grants": [],
}

test_module_denial_names_its_reason if {
	d := authz.decision with input as call("fs", "read_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.denied as true
		with data.mcp.authz.deny_reasons as {"the agent is paused"}
	d == {"effect": "deny", "reason": "the agent is paused"}
}

test_reasons_of_two_modules_sorted if {
	d := authz.decision with input as call("fs", "read_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.denied as true
		with data.mcp.authz.deny_reasons as {"the agent is paused", "emergency stop"}
	d.reason == "emergency stop; the agent is paused"
}

test_module_denial_without_reason_as_before if {
	d := authz.decision with input as call("fs", "read_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.denied as true
	d == {"effect": "deny", "reason": "denied by policy"}
}

test_denying_permission_as_before if {
	d := authz.decision with input as call("fs", "delete_file", {})
		with data.mcp.rbac as rbac
	d == {"effect": "deny", "reason": "denied by policy"}
}

test_unmatched_explained if {
	d := authz.decision with input as call("fs", "move_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.unmatched_reasons as {"task category files-cleanup is not enabled on this host"}
	d == {"effect": "deny", "reason": "task category files-cleanup is not enabled on this host"}
}

test_unmatched_reasons_sorted if {
	d := authz.decision with input as call("fs", "move_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.unmatched_reasons as {"b: not enabled", "a: not enabled"}
	d.reason == "a: not enabled; b: not enabled"
}

test_unmatched_without_reason_as_before if {
	d := authz.decision with input as call("fs", "move_file", {})
		with data.mcp.rbac as rbac
	d == {"effect": "deny", "reason": "no matching permission"}
}

# An unmatched reason explains no match only: an allowed call, one that
# asks and one whose arguments a permission limits are decided as before.
test_unmatched_reasons_only_for_no_match if {
	reasons := {"task category x is not enabled on this host"}
	allowed := authz.decision with input as call("fs", "read_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.unmatched_reasons as reasons
	allowed.effect == "allow"
	asks := authz.decision with input as call("systemd", "restart_unit", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.unmatched_reasons as reasons
	asks.effect == "ask"
	limited := authz.decision with input as call("fs", "write_file", {"path": "/etc/passwd"})
		with data.mcp.rbac as rbac
		with data.mcp.authz.unmatched_reasons as reasons
	startswith(limited.reason, "no matching permission: the arguments are outside what your roles allow")
}

# A module's deny reason goes with its denial only.
test_deny_reasons_only_when_denied if {
	d := authz.decision with input as call("fs", "read_file", {})
		with data.mcp.rbac as rbac
		with data.mcp.authz.deny_reasons as {"the agent is paused"}
	d.effect == "allow"
}
