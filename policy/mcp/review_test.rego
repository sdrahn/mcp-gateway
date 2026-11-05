package mcp.review_test

import rego.v1

import data.mcp.authz

# The obligation "review": from a permission, or from a module's rule
# review_wanted; only on allows. The principal is not named agent-…:
# Custos runs these tests with its modules, which deny an agent-* user
# with a bound role.

review_rbac := {
	"roles": {"bot": {"permissions": [
		{"server": "systemd", "tool": "restart_unit", "obligations": {"review": true}},
		{"server": "systemd", "tool": "list_units"},
		{"server": "systemd", "tool": "stop_unit", "require_approval": true, "obligations": {"review": true}},
	]}},
	"bindings": {"users": {"ops-bot": ["bot"]}, "groups": {}},
}

call(tool) := {
	"principal": {"sub": "ops-bot", "groups": [], "transport": "unix", "session_id": "s1"},
	"action": "tools.call",
	"resource": {"server": "systemd", "kind": "tool", "name": tool},
	"args": {},
	"grants": [],
}

test_permission_marks_review if {
	d := authz.decision with input as call("restart_unit") with data.mcp.rbac as review_rbac
	d.effect == "allow"
	d.obligations.review == true
}

test_no_review_without_the_mark if {
	d := authz.decision with input as call("list_units") with data.mcp.rbac as review_rbac
	d.effect == "allow"
	not d.obligations.review
}

test_module_marks_review if {
	d := authz.decision with input as call("list_units") with data.mcp.rbac as review_rbac
		with authz.review_wanted as true
	d.obligations.review == true
}

test_ask_carries_no_review if {
	d := authz.decision with input as call("stop_unit") with data.mcp.rbac as review_rbac
	d.effect == "ask"
	not d.obligations
}
