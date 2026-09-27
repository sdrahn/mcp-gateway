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

# The permission field naming the target of each action. A permission
# applies to a request if its "server" glob matches the backend and the
# glob in this field matches the target: a tool or prompt name, a resource
# URI, or the method of a request a backend sends to the client
# ("roots/list", ...). Actions not listed here are denied.
target_field := {
	"tools.call": "tool",
	"prompts.get": "prompt",
	"resources.read": "resource",
	"resources.subscribe": "resource",
	"resources.unsubscribe": "resource",
	"sampling.create": "client",
	"elicitation.create": "client",
	"roots.list": "client",
}

matching contains p if {
	field := target_field[input.action]
	some p in perms
	server_ok(p)
	glob.match(expand_glob(p[field]), null, input.resource.name)
	target_ok(field)
	args_ok(p)
}

# Completions follow what they complete: a prompt like prompts.get, a
# resource template wherever the principal may read some resource of that
# server. The same rules decide the visibility of resource templates.
matching contains p if {
	input.action == "completion.complete"
	input.resource.kind == "prompt"
	some p in perms
	server_ok(p)
	glob.match(expand_glob(p.prompt), null, input.resource.name)
}

matching contains p if {
	input.action == "completion.complete"
	input.resource.kind == "resource_template"
	some p in perms
	server_ok(p)
	is_string(p.resource)
}

server_ok(p) if glob.match(p.server, null, input.resource.server)

# Resource URIs with ".." segments (plain or percent-encoded) never match,
# so "file://${home}/*" cannot be escaped.
target_ok(field) if field != "resource"

target_ok("resource") if {
	not regex.match(`(^|/)\.\.(/|$)`, input.resource.name)
	not regex.match(`(?i)%2e%2e`, input.resource.name)
}

# expand_glob substitutes "${sub}" and "${home}" in a glob; a glob using
# "${home}" is undefined (never matches) for a principal without one.
expand_glob(pattern) := replace(pattern, "${sub}", glob_escape(input.principal.sub)) if {
	not contains(pattern, "${home}")
}

expand_glob(pattern) := replace(replace(pattern, "${home}", glob_escape(home)), "${sub}", glob_escape(input.principal.sub)) if {
	contains(pattern, "${home}")
	home := input.principal.home
	home != ""
}

glob_escape(s) := regex.replace(s, `[*?\[\]{}\\]`, `\$0`)

# Every argument constraint of p is a regular expression the argument must
# match. "${sub}" and "${home}" are replaced by the principal's (escaped)
# subject and home directory; a constraint using "${home}" never matches
# for a principal without one. String arguments containing a ".." path
# segment never satisfy a constraint, so "^${home}/" cannot be escaped with
# "/home/alice/../bob". (Symlinks are left to DAC and SELinux.)
#
# During discovery filtering (input.discovery) arguments are not known yet
# and constraints are not applied.
args_ok(_) if input.discovery == true

args_ok(p) if {
	not input.discovery
	every name, pattern in object.get(p, "args", {}) {
		value := input.args[name]
		is_string(value)
		not regex.match(`(^|/)\.\.(/|$)`, value)
		regex.match(expand(pattern), value)
	}
}

expand(pattern) := replace(pattern, "${sub}", escape(input.principal.sub)) if {
	not contains(pattern, "${home}")
}

expand(pattern) := replace(replace(pattern, "${home}", escape(home)), "${sub}", escape(input.principal.sub)) if {
	contains(pattern, "${home}")
	home := input.principal.home
	home != ""
}

# Escapes regular expression metacharacters.
escape(s) := regex.replace(s, `[.+*?()|\[\]{}^$\\]`, `\$0`)

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
		"prompt": sprintf("Allow %s: %s %s/%s?", [input.principal.sub, input.action, input.resource.server, input.resource.name]),
		"scopes": ["once", "session"],
		"fallback": "oob",
	},
} if {
	count(approvable) > 0
} else := {"effect": "deny", "reason": "no matching permission"}
