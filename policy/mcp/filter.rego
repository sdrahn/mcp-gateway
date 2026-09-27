# Discovery filtering. For */list responses the gateway queries
# data.mcp.filter.visible once, with input.principal and input.resources
# (a list of {server, kind, name}); the result is the subset to show.
#
# A resource is visible unless calling it would be denied outright; tools
# that need approval stay visible so the approval can be requested, and
# argument constraints are ignored because arguments are not known yet.
package mcp.filter

import rego.v1

visible contains r if {
	some r in input.resources
	d := data.mcp.authz.decision with input as {
		"principal": input.principal,
		"action": "tools.call",
		"resource": r,
		"grants": [],
		"discovery": true,
	}
	d.effect != "deny"
}
