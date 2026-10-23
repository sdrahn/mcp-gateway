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

	# The decision the resource would get if it were used.
	d := data.mcp.authz.decision with input as discovery_input(use_action[r.kind], r)
		with data.mcp.authz.role_defs as listing.role_defs
		with data.mcp.authz.roles as listing.roles
		with data.mcp.authz.perms as listing.perms
		with data.mcp.authz.ceiling_perms as listing.ceiling_perms
		with data.mcp.authz.candidate_perms as listing.candidates[r.server]
	d.effect != "deny"
}

discovery_input(action, r) := {
	"principal": input.principal,
	"action": action,
	"resource": r,
	"grants": [],
	"discovery": true,
}

# A listing asks for many resources of one principal. The parts of the
# decision that depend on the principal only (roles, permissions, role
# definitions, the ceilings of token scopes) are worked out once per
# listing and given to every resource's decision ("with"), as are, per
# server, the permissions whose server glob matches it: otherwise OPA
# works them out again for each resource, as "with" starts afresh.
# Additions to mcp.authz.roles or perms (user guide, chapter 12) are
# therefore taken from the principal alone in a listing, without an
# action or resource.
listing := {
	"role_defs": data.mcp.authz.role_defs,
	"roles": data.mcp.authz.roles,
	"perms": data.mcp.authz.perms,
	"ceiling_perms": data.mcp.authz.ceiling_perms,
	"candidates": {s: {p | some p in data.mcp.authz.candidate_perms; glob.match(p.server, null, s)} |
		some s in {r.server | some r in input.resources}
	},
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
	[d, matching] := [data.mcp.authz.decision, data.mcp.authz.matching] with input as discovery_input("tools.call", r)
		with data.mcp.authz.role_defs as listing.role_defs
		with data.mcp.authz.roles as listing.roles
		with data.mcp.authz.perms as listing.perms
		with data.mcp.authz.ceiling_perms as listing.ceiling_perms
		with data.mcp.authz.candidate_perms as listing.candidates[r.server]
	d.effect != "deny"
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
