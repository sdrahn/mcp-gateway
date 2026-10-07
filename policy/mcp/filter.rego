# Discovery filtering. For */list responses the gateway queries
# data.mcp.filter.visible once, with input.principal and input.resources
# (a list of {server, kind, name}); the result is the subset to show.
#
# An item is visible unless using it would be denied outright: items that
# need approval stay visible so the approval can be requested, and
# argument constraints are ignored because arguments are not known yet.
package mcp.filter

import rego.v1

# The action that "using" an item of each kind means.
use_action := {
	"tool": "tools.call",
	"prompt": "prompts.get",
	"resource": "resources.read",
	"resource_template": "completion.complete",
}

# METADATA
# description: The resources of input.resources the principal may see.
# entrypoint: true
visible contains r if {
	some r in input.resources

	# The decision each resource would get if it were used.
	# regal ignore:with-outside-test-context
	d := data.mcp.authz.decision with input as {
		"principal": input.principal,
		"action": use_action[r.kind],
		"resource": r,
		"grants": [],
		"discovery": true,
	}
	d.effect != "deny"
}

# METADATA
# description: >-
#   What the principal's roles say about calling each tool of
#   input.resources, for the gateway to add to the tool's description
#   (docs/architecture.md, roadmap step 29): the approval channel if
#   calls need an approval, and the argument constraints if every
#   permission that covers the tool has some (one object per permission,
#   with "${home}" and "${sub}" expanded). Tools without either, and
#   tools the principal may not see, have no hint. Advice only: every
#   call is still decided.
# entrypoint: true
hints contains hint if {
	some r in input.resources
	r.kind == "tool"
	in_doc := {
		"principal": input.principal,
		"action": "tools.call",
		"resource": r,
		"grants": [],
		"discovery": true,
	}

	# regal ignore:with-outside-test-context
	d := data.mcp.authz.decision with input as in_doc
	d.effect != "deny"

	# regal ignore:with-outside-test-context
	matching := data.mcp.authz.matching with input as in_doc
	perms := {p | some p in matching; not p.effect == "deny"}
	args := arg_limits(perms)
	approval := object.get(object.get(d, "ask", {}), "channel", "")
	count(args) + count(approval) > 0
	hint := {"server": r.server, "name": r.name, "approval": approval, "args": args}
}

# No limit if one of the permissions has no argument constraints. The
# patterns are expanded for input.principal, as the decision does.
arg_limits(perms) := [] if {
	some p in perms
	object.get(p, "args", {}) == {}
} else := sort({limit |
	some p in perms
	limit := {name: data.mcp.authz.expand(pattern) | some name, pattern in p.args}
})
