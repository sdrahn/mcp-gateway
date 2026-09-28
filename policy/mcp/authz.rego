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
	cert_ok(p)
}

# A permission with "require_client_cert": true applies only to remote
# clients that presented a verified TLS client certificate (mTLS).
# Explicit denies always apply.
cert_ok(p) if not p.require_client_cert == true

cert_ok(p) if p.effect == "deny"

cert_ok(_) if is_object(input.principal.cert)

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
	not sensitive_blocked(field, p)
}

# A backend's elicitation that looks like it asks for secrets (the gateway
# sets input.args.sensitive) is only covered by permissions that say
# "allow_sensitive": true.
sensitive_blocked("client", p) if {
	input.args.sensitive == true
	not p.allow_sensitive == true
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

# Obligations of all matching (non-deny) permissions, merged: redaction
# patterns, rate limits and argument constraints add up (every constraint
# must hold), the smallest output limit wins, and "full" audit wins.
applicable contains p if {
	some p in matching
	not p.effect == "deny"
}

obligation_sets[key] := vs if {
	some key in {"redact_output", "rate_limit"}
	vs := {v |
		some p in applicable
		some v in as_list(object.get(p, ["obligations", key], []))
	}
}

output_limits contains n if {
	some p in applicable
	n := p.obligations.max_output_bytes
}

arg_constraints[name] := patterns if {
	some p in applicable
	some name, _ in object.get(p, ["obligations", "arg_constraints"], {})
	patterns := {pattern |
		some q in applicable
		some pattern in as_list(object.get(q, ["obligations", "arg_constraints", name], []))
	}
}

obligation_entries contains [key, sort(vs)] if {
	some key, vs in obligation_sets
	count(vs) > 0
}

obligation_entries contains ["max_output_bytes", min(output_limits)] if count(output_limits) > 0

obligation_entries contains ["arg_constraints", {name: sort(ps) | some name, ps in arg_constraints}] if {
	count(arg_constraints) > 0
}

obligation_entries contains ["audit", "full"] if {
	some p in applicable
	p.obligations.audit == "full"
}

# Pseudonymization: detectors add up, and so do named patterns and field
# rules (the same name with two different definitions is a conflict, and
# the decision fails, which denies). Arguments to re-identify add up too.
pseudo_detect contains d if {
	some p in applicable
	some d in as_list(object.get(p, ["obligations", "pseudonymize", "detect"], []))
}

pseudo_patterns[name] := re if {
	some p in applicable
	some name, re in object.get(p, ["obligations", "pseudonymize", "patterns"], {})
}

pseudo_fields[key] := class if {
	some p in applicable
	some key, class in object.get(p, ["obligations", "pseudonymize", "fields"], {})
}

# Each part is present only when some permission sets it (an object
# comprehension with a condition yields an empty object otherwise).
pseudonymize := object.union_n([
	{"detect": sort(pseudo_detect) | count(pseudo_detect) > 0},
	{"patterns": pseudo_patterns | count(pseudo_patterns) > 0},
	{"fields": pseudo_fields | count(pseudo_fields) > 0},
])

obligation_entries contains ["pseudonymize", pseudonymize] if count(pseudonymize) > 0

reidentify_args contains name if {
	some p in applicable
	some name in as_list(object.get(p, ["obligations", "reidentify"], []))
}

obligation_entries contains ["reidentify", sort(reidentify_args)] if count(reidentify_args) > 0

obligations := {e[0]: e[1] | some e in obligation_entries}

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

# An allow decision, with the obligations if there are any.
allow_with(d) := object.union(d, {"obligations": obligations}) if count(obligations) > 0

else := d

decision := {"effect": "deny", "reason": "denied by policy"} if {
	denied
} else := allow_with({"effect": "allow"}) if {
	allowed
} else := allow_with({"effect": "allow", "reason": "approved"}) if {
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
