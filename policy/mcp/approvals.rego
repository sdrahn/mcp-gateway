# Who may decide on a pending approval (data.mcp.approvals.allow), see or
# revoke a grant (data.mcp.approvals.manage_grant), see or stop a backend
# instance (data.mcp.approvals.manage_instance) and see or end a
# principal's sign-in to a server (data.mcp.approvals.manage_sign_in). The gateway queries
# these from its control API; the approver is identified by the kernel
# (uid, user and group names), never by the agent.
#
# data.mcp.rbac.approvers maps a server name, or "default", to rules:
#   "self"          the principal themself (same local uid)
#   "role:<role>"   approvers holding the role (data.mcp.rbac.bindings)
#   "group:<group>" members of a local group
#   "user:<user>"   a local user
# Without data.mcp.rbac.approvers, only "self" applies.
package mcp.approvals

import rego.v1

# METADATA
# description: May the approver decide on the pending request?
# entrypoint: true
default allow := false

allow if {
	some rule in rules_for(input.request.server)
	grants(rule, input.request.principal)
}

# METADATA
# description: May the caller see and revoke the grant?
# entrypoint: true
default manage_grant := false

manage_grant if {
	some rule in rules_for(input.grant.server)
	grants(rule, input.grant)
}

# METADATA
# description: May the caller see and stop the backend instance?
# entrypoint: true
default manage_instance := false

manage_instance if {
	some rule in rules_for(input.instance.server)
	grants(rule, input.instance)
}

# METADATA
# description: May the caller see and end the principal's sign-in to the server?
# entrypoint: true
default manage_sign_in := false

manage_sign_in if {
	some rule in rules_for(input.sign_in.server)
	grants(rule, input.sign_in)
}

# METADATA
# description: >-
#   May the caller see how a role data change would change decisions
#   (everyone's)? Those whom the default approver rules name other than
#   "self": with the shipped data, the admin role.
# entrypoint: true
default review_policy := false

review_policy if {
	some rule in rules_for("default")
	rule != "self"
	grants(rule, {})
}

# Whom to tell about a pending approval (e-mail notifications): the
# approvers its server's rules name, as "user:<name>" and "group:<name>".
# "self" is the principal's local account, if it has one.
# METADATA
# description: Who to notify of a pending request, as "user:<name>" and "group:<name>".
# entrypoint: true
notify contains sprintf("user:%s", [input.request.principal.sub]) if {
	"self" in rules_for(input.request.server)
	is_number(input.request.principal.uid)
}

notify contains rule if {
	some rule in rules_for(input.request.server)
	startswith(rule, "user:")
}

notify contains rule if {
	some rule in rules_for(input.request.server)
	startswith(rule, "group:")
}

notify contains sprintf("user:%s", [user]) if {
	some rule in rules_for(input.request.server)
	startswith(rule, "role:")
	some user, roles in data.mcp.rbac.bindings.users
	substring(rule, 5, -1) in roles
}

notify contains sprintf("group:%s", [group]) if {
	some rule in rules_for(input.request.server)
	startswith(rule, "role:")
	some group, roles in data.mcp.rbac.bindings.groups
	substring(rule, 5, -1) in roles
}

rules_for(server) := rules if {
	rules := data.mcp.rbac.approvers[server]
} else := rules if {
	rules := data.mcp.rbac.approvers["default"]
} else := ["self"]

approver_roles contains r if some r in data.mcp.rbac.bindings.users[input.approver.name]

approver_roles contains r if {
	some g in input.approver.groups
	some r in data.mcp.rbac.bindings.groups[g]
}

# subject is the pending request's principal, the grant, the instance or
# the sign-in;
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
