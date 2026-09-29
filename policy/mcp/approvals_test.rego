package mcp.approvals_test

import rego.v1

import data.mcp.approvals

alice_req := {"principal": {"sub": "alice", "uid": 1001}, "server": "fs", "name": "write_file", "action": "tools.call"}

remote_req := {"principal": {"sub": "u-7f3a", "iss": "https://idp"}, "server": "fs", "name": "write_file", "action": "tools.call"}

alice := {"name": "alice", "uid": 1001, "groups": ["users"]}

bob := {"name": "bob", "uid": 1002, "groups": ["users"]}

carol := {"name": "carol", "uid": 1003, "groups": ["users", "wheel"]}

test_self_by_default if {
	approvals.allow with input as {"approver": alice, "request": alice_req} with data.mcp.rbac as {}
	not approvals.allow with input as {"approver": bob, "request": alice_req} with data.mcp.rbac as {}
	not approvals.allow with input as {"approver": carol, "request": alice_req} with data.mcp.rbac as {}
}

test_shipped_data_admins if {
	# policy/mcp/rbac/data.json: default ["self", "role:admin"], wheel → admin
	approvals.allow with input as {"approver": alice, "request": alice_req}
	approvals.allow with input as {"approver": carol, "request": alice_req}
	not approvals.allow with input as {"approver": bob, "request": alice_req}
}

test_remote_principal_only_by_role if {
	approvals.allow with input as {"approver": carol, "request": remote_req}

	# a local user named like the remote subject is not "self"
	not approvals.allow with input as {"approver": {"name": "u-7f3a", "uid": 1500, "groups": []}, "request": remote_req}
}

test_per_server_rules if {
	rbac := {"approvers": {"default": ["self"], "db": ["group:dba", "user:dave"]}, "bindings": {}}
	db_req := object.union(alice_req, {"server": "db"})
	not approvals.allow with input as {"approver": alice, "request": db_req} with data.mcp.rbac as rbac
	approvals.allow with input as {"approver": {"name": "dave", "uid": 1004, "groups": []}, "request": db_req} with data.mcp.rbac as rbac
	approvals.allow with input as {"approver": {"name": "erin", "uid": 1005, "groups": ["dba"]}, "request": db_req} with data.mcp.rbac as rbac
	approvals.allow with input as {"approver": alice, "request": alice_req} with data.mcp.rbac as rbac
}

test_manage_grant if {
	g := {"id": "g-1", "sub": "alice", "uid": 1001, "server": "fs", "tool": "write_file"}
	approvals.manage_grant with input as {"approver": alice, "grant": g}
	approvals.manage_grant with input as {"approver": carol, "grant": g}
	not approvals.manage_grant with input as {"approver": bob, "grant": g}
	remote := {"id": "g-2", "sub": "bob", "iss": "https://idp", "server": "fs", "tool": "write_file"}
	not approvals.manage_grant with input as {"approver": bob, "grant": remote}
}

test_manage_instance if {
	own := {"server": "fs", "uid": 1001}
	approvals.manage_instance with input as {"approver": alice, "instance": own}
	not approvals.manage_instance with input as {"approver": bob, "instance": own}
	approvals.manage_instance with input as {"approver": carol, "instance": own}

	# An unmapped remote principal's instance: admins only.
	remote := {"server": "fs", "uid": null}
	not approvals.manage_instance with input as {"approver": alice, "instance": remote}
	approvals.manage_instance with input as {"approver": carol, "instance": remote}
}

test_notify if {
	# policy/mcp/rbac/data.json: default ["self", "role:admin"], wheel → admin
	approvals.notify == {"user:alice", "group:wheel"} with input as {"request": alice_req}

	# An unmapped remote principal has no local account to tell.
	approvals.notify == {"group:wheel"} with input as {"request": remote_req}

	rbac := {
		"approvers": {"fs": ["user:carol", "group:ops", "role:auditor"]},
		"bindings": {"users": {"dave": ["auditor"]}, "groups": {"sec": ["auditor"]}},
	}
	approvals.notify == {"user:carol", "group:ops", "user:dave", "group:sec"} with input as {"request": alice_req}
		with data.mcp.rbac as rbac
}

test_review_policy if {
	# policy/mcp/rbac/data.json: default ["self", "role:admin"], wheel → admin
	approvals.review_policy with input as {"approver": carol}
	not approvals.review_policy with input as {"approver": alice}

	# "self" alone names nobody.
	not approvals.review_policy with input as {"approver": carol} with data.mcp.rbac as {}
	approvals.review_policy with input as {"approver": bob}
		with data.mcp.rbac.approvers as {"default": ["self", "user:bob"]}
}
