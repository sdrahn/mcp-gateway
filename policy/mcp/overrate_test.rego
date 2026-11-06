package mcp.overrate_test

import rego.v1

import data.mcp.authz

# The obligation approval_over_rate reaches the decision from matching
# permissions, merged as rate_limit is (the lists add up).

overrate_rbac := {
	"roles": {
		"patcher": {"permissions": [{"server": "zypp", "tool": "patch", "obligations": {"approval_over_rate": "20/h", "rate_limit": ["60/h"]}}]},
		"nightly": {"permissions": [{"server": "zypp", "tool": "patch", "obligations": {"approval_over_rate": ["2/m"]}}]},
	},
	"bindings": {"users": {"ops-bot": ["patcher", "nightly"]}, "groups": {}},
}

patch_call := {
	"principal": {"sub": "ops-bot", "groups": [], "transport": "unix", "session_id": "s1"},
	"action": "tools.call",
	"resource": {"server": "zypp", "kind": "tool", "name": "patch"},
	"args": {},
	"grants": [],
}

test_merged_across_permissions if {
	d := authz.decision with input as patch_call with data.mcp.rbac as overrate_rbac
	d.effect == "allow"
	d.obligations.approval_over_rate == ["2/m", "20/h"]
	d.obligations.rate_limit == ["60/h"]
}
