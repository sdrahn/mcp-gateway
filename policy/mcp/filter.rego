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
