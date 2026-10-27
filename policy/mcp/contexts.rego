# The tools gateway_new_context and gateway_end_context the gateway offers
# modern agents for a server with contexts (input.resource.context,
# decision D22) follow the server's tools as sign_in does (authz.rego): a
# permission naming any tool of the server covers them, a denial only if
# it names every tool ("*"), not because it denies some.
package mcp.authz

import rego.v1

covering contains p if {
	input.action == "tools.call"
	input.resource.context == true
	some p in candidate_perms
	server_ok(p)
	is_string(p.tool)
	context_relevant(p)
}

context_relevant(p) if not p.effect == "deny"

context_relevant(p) if p.tool == "*"
