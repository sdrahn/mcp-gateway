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
	# policy/mcp/rbac/data.yaml: default ["self", "role:admin"], wheel → admin
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

test_manage_task if {
	own := {"server": "zypp", "tool": "confirm_install", "sub": "alice", "uid": 1001, "transport": "unix"}
	approvals.manage_task with input as {"approver": alice, "task": own}
	not approvals.manage_task with input as {"approver": bob, "task": own}
	approvals.manage_task with input as {"approver": carol, "task": own}

	# An unmapped remote principal's task: admins only.
	remote := {"server": "zypp", "tool": "confirm_install", "sub": "u-remote", "uid": null, "transport": "http"}
	not approvals.manage_task with input as {"approver": alice, "task": remote}
	approvals.manage_task with input as {"approver": carol, "task": remote}
}

test_manage_session if {
	own := {"sub": "alice", "uid": 1001, "transport": "unix", "endpoint": "all", "servers": ["fs", "zypp"], "client": {"name": "claude-code"}}
	approvals.manage_session with input as {"approver": alice, "session": own}
	not approvals.manage_session with input as {"approver": bob, "session": own}
	approvals.manage_session with input as {"approver": carol, "session": own}

	# An unmapped remote principal's session: admins only.
	remote := object.union(own, {"sub": "u-remote", "uid": null, "transport": "http"})
	not approvals.manage_session with input as {"approver": alice, "session": remote}
	approvals.manage_session with input as {"approver": carol, "session": remote}

	# Every server of the endpoint must grant it: an approver of one is
	# not an approver of the others.
	fs_helpdesk := {"default": ["self"], "fs": ["self", "user:bob"]}
	approvals.manage_session with input as {"approver": bob, "session": object.union(own, {"servers": ["fs"]})}
		with data.mcp.rbac.approvers as fs_helpdesk
	not approvals.manage_session with input as {"approver": bob, "session": own}
		with data.mcp.rbac.approvers as fs_helpdesk

	# An endpoint without servers: the default rules.
	approvals.manage_session with input as {"approver": alice, "session": object.union(own, {"servers": []})}
	not approvals.manage_session with input as {"approver": bob, "session": object.union(own, {"servers": []})}
}

test_manage_sign_in if {
	own := {"server": "tickets", "uid": 1001}
	approvals.manage_sign_in with input as {"approver": alice, "sign_in": own}
	not approvals.manage_sign_in with input as {"approver": bob, "sign_in": own}
	approvals.manage_sign_in with input as {"approver": carol, "sign_in": own}

	# An unmapped remote principal's sign-in: admins only.
	remote := {"server": "tickets", "uid": null}
	not approvals.manage_sign_in with input as {"approver": alice, "sign_in": remote}
	approvals.manage_sign_in with input as {"approver": carol, "sign_in": remote}
}

test_notify if {
	# policy/mcp/rbac/data.yaml: default ["self", "role:admin"], wheel → admin
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
	# policy/mcp/rbac/data.yaml: default ["self", "role:admin"], wheel → admin
	approvals.review_policy with input as {"approver": carol}
	not approvals.review_policy with input as {"approver": alice}

	# "self" alone names nobody.
	not approvals.review_policy with input as {"approver": carol} with data.mcp.rbac as {}
	approvals.review_policy with input as {"approver": bob}
		with data.mcp.rbac.approvers as {"default": ["self", "user:bob"]}
}

# Signed in on the approval page without a local account: never by a
# local name or group (user:, group:, role: through bindings), only by
# the remote- rules.
zed := {"name": "zed", "groups": ["wheel", "ops"], "remote": true, "issuer": "https://idp"}

test_remote_approver_explicit_rules_only if {
	rbac := {
		"approvers": {"fs": ["user:zed", "group:wheel", "role:admin"]},
		"bindings": {"users": {"zed": ["admin"]}, "groups": {"wheel": ["admin"]}},
	}
	not approvals.allow with input as {"approver": zed, "request": alice_req} with data.mcp.rbac as rbac
	not approvals.manage_grant with input as {"approver": zed, "grant": {"server": "fs", "uid": 1001}} with data.mcp.rbac as rbac
	not approvals.review_policy with input as {"approver": zed} with data.mcp.rbac as {"approvers": {"default": ["role:admin"]}, "bindings": rbac.bindings}

	# the same names, as a local approver: allowed
	approvals.allow with input as {"approver": {"name": "zed", "uid": 1600, "groups": ["wheel"]}, "request": alice_req} with data.mcp.rbac as rbac

	by_sub := {"approvers": {"fs": ["remote-user:zed"]}, "bindings": {}}
	approvals.allow with input as {"approver": zed, "request": alice_req} with data.mcp.rbac as by_sub
	by_group := {"approvers": {"fs": ["remote-group:ops"]}, "bindings": {}}
	approvals.allow with input as {"approver": zed, "request": alice_req} with data.mcp.rbac as by_group
	not approvals.allow with input as {"approver": object.union(zed, {"groups": []}), "request": alice_req} with data.mcp.rbac as by_group
}

# remote- rules never match a local approver, nor a sign-in that maps to
# a local account (that is the account, matched by the local rules).
test_remote_rules_not_for_local_accounts if {
	rbac := {"approvers": {"fs": ["remote-user:jack", "remote-group:ops"]}, "bindings": {}}
	jack := {"name": "jack", "uid": 1004, "groups": ["ops"]}
	not approvals.allow with input as {"approver": jack, "request": alice_req} with data.mcp.rbac as rbac
	mapped := object.union(jack, {"remote": true, "issuer": "https://idp"})
	not approvals.allow with input as {"approver": mapped, "request": alice_req} with data.mcp.rbac as rbac
	approvals.allow with input as {"approver": mapped, "request": alice_req} with data.mcp.rbac as {"approvers": {"fs": ["user:jack"]}, "bindings": {}}
}
