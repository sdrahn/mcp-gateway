# "What changes?" for a role data edit. Before the administrator saves new
# role data, the gateway queries data.mcp.whatif.changes with
#   input.principals  [{label, principal}]: the users and groups named in
#                     the bindings, as the gateway resolves them
#   input.resources   [{server, kind, name, annotations}]: what the MCP
#                     servers offer; kind "client" for the requests they
#                     send to the agent
#   input.proposed    the new role data (roles, bindings, approvers)
# and shows every decision that would change. Arguments are not known, so
# decisions are made as for discovery (argument constraints are ignored),
# and grants are left out: the result is what each principal may use at
# all, and whether it needs approval.
package mcp.whatif

import rego.v1

# The action that using a resource of each kind means (as mcp.filter).
action := {
	"tool": "tools.call",
	"prompt": "prompts.get",
	"resource": "resources.read",
	"resource_template": "completion.complete",
	"client": "client",
}

# Requests MCP servers send to the agent, by method.
client_action := {
	"sampling/createMessage": "sampling.create",
	"elicitation/create": "elicitation.create",
	"roots/list": "roots.list",
}

action_for(r) := client_action[r.name] if r.kind == "client"

action_for(r) := action[r.kind] if r.kind != "client"

# The proposed role data replaces what rbac/data.json holds; data from
# other files below data.mcp.rbac (rbac/<name>/data.json) stays.
default current := {}

current := data.mcp.rbac

proposed := object.union(object.remove(current, ["roles", "bindings", "approvers"]), input.proposed)

# METADATA
# description: The decisions that change with the proposed role data.
# entrypoint: true
changes contains change if {
	some p in input.principals
	some r in input.resources
	req := {
		"principal": p.principal,
		"action": action_for(r),
		"resource": r,
		"grants": [],
		"discovery": true,
		"version": object.get(input, "version", 1),
	}

	# regal ignore:with-outside-test-context
	before := data.mcp.authz.decision.effect with input as req

	# regal ignore:with-outside-test-context
	after := data.mcp.authz.decision.effect with input as req with data.mcp.rbac as proposed
	before != after
	change := {
		"principal": p.label,
		"server": r.server,
		"kind": r.kind,
		"name": r.name,
		"before": before,
		"after": after,
	}
}
