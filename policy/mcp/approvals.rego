# Who may decide on a pending approval (data.mcp.approvals.allow), see or
# revoke a grant (data.mcp.approvals.manage_grant) and see or stop a
# backend instance (data.mcp.approvals.manage_instance). The gateway queries
# these from its control API; the approver is identified by the kernel
# (uid, user and group names), never by the agent.
#
# data.rbac.approvers maps a server name, or "default", to rules:
#   "self"          the principal themself (same local uid)
#   "role:<role>"   approvers holding the role (data.rbac.bindings)
#   "group:<group>" members of a local group
#   "user:<user>"   a local user
# Without data.rbac.approvers, only "self" applies.
package mcp.approvals

import rego.v1

default allow := false

allow if {
	some rule in rules_for(input.request.server)
	grants(rule, input.request.principal)
}

default manage_grant := false

manage_grant if {
	some rule in rules_for(input.grant.server)
	grants(rule, input.grant)
}

default manage_instance := false

manage_instance if {
	some rule in rules_for(input.instance.server)
	grants(rule, input.instance)
}

rules_for(server) := rules if {
	rules := data.rbac.approvers[server]
} else := rules if {
	rules := data.rbac.approvers["default"]
} else := ["self"]

approver_roles contains r if some r in data.rbac.bindings.users[input.approver.name]

approver_roles contains r if {
	some g in input.approver.groups
	some r in data.rbac.bindings.groups[g]
}

# subject is the pending request's principal, the grant or the instance;
# all carry the principal's local uid if it has one.
grants("self", subject) if subject.uid == input.approver.uid

grants(rule, _) if {
	startswith(rule, "role:")
	substring(rule, 5, -1) in approver_roles
}

grants(rule, _) if {
	startswith(rule, "group:")
	substring(rule, 6, -1) in input.approver.groups
}

grants(rule, _) if {
	startswith(rule, "user:")
	substring(rule, 5, -1) == input.approver.name
}
