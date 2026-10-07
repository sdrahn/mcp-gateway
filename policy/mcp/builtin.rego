# The gateway's own tool gateway_capabilities (input.resource.builtin),
# which tells the principal what its roles allow (docs/architecture.md,
# roadmap step 29). Every principal that holds some permission may call
# it: it shows only what those permissions already allow.
package mcp.authz

import rego.v1

covering contains p if {
	input.action == "tools.call"
	input.resource.builtin == true
	some p in perms
	not p.effect == "deny"
	not p.require_approval
}
