# Main authorization policy. The gateway queries data.mcp.authz.decision
# with the input document described in docs/architecture.md, section 6.2,
# and expects a decision document as described in section 6.3.
#
# Precedence: explicit deny > allow > allow with a valid grant > ask > deny.
package mcp.authz

import rego.v1

# Roles of the principal: from the input (if the gateway resolved them) and
# from the bindings in data.rbac.
roles contains r if some r in input.principal.roles

roles contains r if some r in data.rbac.bindings.users[input.principal.sub]

roles contains r if {
	some g in input.principal.groups
	some r in data.rbac.bindings.groups[g]
}

perms contains p if {
	some role in roles
	some p in data.rbac.roles[role].permissions
}

# Permissions that apply to this request. Only tools.call is modelled so
# far; every other action falls through to the default deny.
matching contains p if {
	input.action == "tools.call"
	some p in perms
	glob.match(p.server, [], input.resource.server)
	glob.match(p.tool, [], input.resource.name)
	args_ok(p)
}

# Every argument constraint of p is a regular expression the argument must
# match; "${sub}" is replaced by the principal's subject. Path arguments
# are expected to be normalised by the gateway before evaluation.
# During discovery filtering (input.discovery) arguments are not known yet
# and constraints are not applied.
args_ok(_) if input.discovery == true

args_ok(p) if {
	not input.discovery
	every name, pattern in object.get(p, "args", {}) {
		value := input.args[name]
		is_string(value)
		regex.match(replace(pattern, "${sub}", input.principal.sub), value)
	}
}

denied if {
	some p in matching
	p.effect == "deny"
}

allowed if {
	some p in matching
	not p.effect == "deny"
	not p.require_approval
}

approvable contains p if {
	some p in matching
	not p.effect == "deny"
	p.require_approval
}

granted if {
	some g in input.grants
	g.sub == input.principal.sub
	g.server == input.resource.server
	g.tool == input.resource.name
	grant_in_scope(g)
	time.parse_rfc3339_ns(g.expires) > time.now_ns()
}

grant_in_scope(g) if g.scope in {"once", "duration"}

grant_in_scope(g) if {
	g.scope == "session"
	g.session_id == input.principal.session_id
}

ask_channel := c if {
	some p in approvable
	c := object.get(p, "approval_channel", "url")
}

decision := {"effect": "deny", "reason": "denied by policy"} if {
	denied
} else := {"effect": "allow"} if {
	allowed
} else := {"effect": "allow", "reason": "approved"} if {
	count(approvable) > 0
	granted
} else := {
	"effect": "ask",
	"ask": {
		"channel": ask_channel,
		"prompt": sprintf("Allow %s to call %s/%s?", [input.principal.sub, input.resource.server, input.resource.name]),
		"scopes": ["once", "session"],
		"fallback": "oob",
	},
} if {
	count(approvable) > 0
} else := {"effect": "deny", "reason": "no matching permission"}
