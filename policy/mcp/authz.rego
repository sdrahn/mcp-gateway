# Main authorization policy. The gateway queries data.mcp.authz.decision
# with the input document described in docs/architecture.md, section 6.2,
# and expects a decision document as described in section 6.3.
#
# Precedence: explicit deny > outside the token's scopes > allow > allow
# with a valid grant > ask > deny.
package mcp.authz

import rego.v1

# Roles of the principal: from the input (if the gateway resolved them) and
# from the bindings in data.mcp.rbac.
roles contains r if some r in input.principal.roles

roles contains r if some r in data.mcp.rbac.bindings.users[input.principal.sub]

roles contains r if {
	some g in input.principal.groups
	some r in data.mcp.rbac.bindings.groups[g]
}

perms contains p if {
	some role in roles
	some p in role_defs[role].permissions
	cert_ok(p)
}

# Role definitions: the administrator's (data.mcp.rbac.roles) and those
# shipped with server setups (data.mcp.profiles.<setup>.roles, installed
# by the setup packages). A role the administrator defines replaces a
# shipped one of the same name. Bindings and approvers are always the
# administrator's.
role_defs := object.union(shipped_roles, object.get(data.mcp.rbac, "roles", {}))

shipped_roles[name] := role if {
	some profile in data.mcp.profiles
	some name, role in profile.roles
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
	some p in perms
	p in covering
}

# The permissions that cover the request, among the principal's and those
# of the ceilings of the scope map (below).
candidate_perms := perms | {p | some ps in ceiling_perms; some p in ps}

covering contains p if {
	field := target_field[input.action]
	target_ok(field)
	some p in candidate_perms
	server_ok(p)
	glob.match(expand_glob(p[field]), null, input.resource.name)
	args_ok(p)
	not sensitive_blocked(field, p)
}

# The tool sign_in, which the gateway offers in place of a server's tools
# until the principal signed in to it (input.resource.sign_in), follows
# the server's tools: a permission naming any tool of the server covers
# it (docs/architecture.md, section 5.7.3).
covering contains p if {
	input.action == "tools.call"
	input.resource.sign_in == true
	some p in candidate_perms
	server_ok(p)
	is_string(p.tool)
}

# Completions follow what they complete: a prompt like prompts.get, a
# resource template wherever the principal may read some resource of that
# server. The same rules decide the visibility of resource templates.
covering contains p if {
	input.action == "completion.complete"
	input.resource.kind == "prompt"
	some p in candidate_perms
	server_ok(p)
	glob.match(expand_glob(p.prompt), null, input.resource.name)
}

covering contains p if {
	input.action == "completion.complete"
	input.resource.kind == "resource_template"
	some p in candidate_perms
	server_ok(p)
	is_string(p.resource)
}

# A backend's elicitation that looks like it asks for secrets (the gateway
# sets input.args.sensitive) is only covered by permissions that say
# "allow_sensitive": true.
sensitive_blocked("client", p) if {
	input.args.sensitive == true
	not p.allow_sensitive == true
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

expand_glob(pattern) := replace(with_home, "${sub}", glob_escape(input.principal.sub)) if {
	contains(pattern, "${home}")
	home := input.principal.home
	home != ""
	with_home := replace(pattern, "${home}", glob_escape(home))
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
	unconditional(p)
}

approvable contains p if {
	some p in matching
	not p.effect == "deny"
	p.require_approval
}

# Privileged servers run without the kernel sandbox (docs/architecture.md,
# section 5.7.1). A permission allows their calls without approval only
# if it names server and target without wildcards; others, like admin's
# "*", ask.
approvable contains p if {
	some p in matching
	not p.effect == "deny"
	not p.require_approval
	not unconditional(p)
}

unconditional(_) if not input.resource.privileged == true

unconditional(p) if {
	input.resource.privileged == true
	not has_glob(p.server)
	not has_glob(object.get(p, target_field[input.action], "*"))
}

has_glob(s) if regex.match(`[*?\[\]{}]`, s)

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

# Approval scopes: "once" always, and the scopes every approvable
# permission offers (approval_scopes, default "once" and "session"), so
# the most restrictive permission decides. Durations ("1h", up to 720h)
# come last, shortest first; invalid entries are ignored.
default_approval_scopes := ["once", "session"]

max_grant_duration_ns := time.parse_duration_ns("720h")

offered_scopes contains s if {
	some p in approvable
	some s in object.get(p, "approval_scopes", default_approval_scopes)
	valid_scope(s)
	every q in approvable {
		s in object.get(q, "approval_scopes", default_approval_scopes)
	}
}

valid_scope(s) if s in {"once", "session"}

valid_scope(s) if {
	is_string(s)
	regex.match(`^[1-9][0-9]*[mh]$`, s)
	time.parse_duration_ns(s) <= max_grant_duration_ns
}

default first_scopes := ["once"]

first_scopes := ["once", "session"] if "session" in offered_scopes

duration_scopes := [d[1] | some d in sort({[time.parse_duration_ns(s), s] |
	some s in offered_scopes
	not s in {"once", "session"}
})]

ask_scopes := array.concat(first_scopes, duration_scopes)

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

obligation_entries contains ["pseudonymize", pseudonymize] if count(pseudonymize) > 0

obligation_entries contains ["reidentify", sort(reidentify_args)] if count(reidentify_args) > 0

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

reidentify_args contains name if {
	some p in applicable
	some name in as_list(object.get(p, ["obligations", "reidentify"], []))
}

obligations[e[0]] := e[1] if some e in obligation_entries

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

# Token scopes as a ceiling (docs/architecture.md, section 6.7, D17).
# The role data may map scopes to ceilings: the permissions of named
# roles, permissions of their own, or "unlimited". A remote principal's
# request must lie within the union of the ceilings of its token's
# scopes, or within the "default" ceiling if the token has none of the
# named scopes. A ceiling only takes away: what the roles do not allow
# stays denied, and what lies outside it is denied, not asked.
scope_map := object.get(data.mcp.rbac, "scopes", {})

token_scopes := {s | some s in object.get(input.principal, "scopes", [])}

named_scopes contains s if {
	some s in token_scopes
	s != "default"
	is_object(scope_map[s])
}

# The scopes whose ceilings bound the request: the token's named scopes,
# else "default" if the map has one.
default ceiling_scopes := set()

ceiling_scopes := named_scopes if count(named_scopes) > 0

ceiling_scopes := {"default"} if {
	count(named_scopes) == 0
	is_object(scope_map.default)
}

# The permissions of each ceiling: its own, and those of the roles it
# names. A role's explicit denies are not part of a ceiling (they still
# deny through the roles).
ceiling_perms[s] := own | roled if {
	some s, c in scope_map
	is_object(c)
	own := {p | some p in object.get(c, "permissions", [])}
	roled := {p |
		some r in object.get(c, "roles", [])
		some p in role_defs[r].permissions
		not p.effect == "deny"
	}
}

# The scopes whose ceilings are unlimited.
unlimited_scopes contains s if {
	some s, c in scope_map
	c.unlimited == true
}

# The scopes whose ceilings cover the request.
covering_scopes contains s if some s in unlimited_scopes

covering_scopes contains s if {
	some s, ps in ceiling_perms
	some p in ps
	p in covering
}

# Without a ceiling nothing is narrowed: local principals (no token),
# role data without a map, or a token with none of its scopes and no
# "default".
within_ceiling if input.principal.transport != "http"

within_ceiling if count(ceiling_scopes) == 0

within_ceiling if {
	some s in ceiling_scopes
	s in covering_scopes
}

# The roles would allow the request, or allow it after an approval.
roles_allow if allowed

roles_allow if count(approvable) > 0

outside_scopes if {
	roles_allow
	not within_ceiling
}

# The scopes whose ceilings would allow the request, for a client to
# step up to: the narrower ones first, unlimited ones last (the gateway
# asks for the first).
required_scopes := array.concat(
	sort((covering_scopes - unlimited_scopes) - {"default"}),
	sort(unlimited_scopes - {"default"}),
)

scope_denial := {
	"effect": "deny",
	"reason": "outside the token's scopes",
	"outside_scopes": true,
	"required_scopes": required_scopes,
}

# An allow decision, with the obligations if there are any.
allow_with(d) := object.union(d, {"obligations": obligations}) if count(obligations) > 0

else := d

# METADATA
# description: The decision on a request (docs/architecture.md, section 6.3).
# entrypoint: true
default decision := {"effect": "deny", "reason": "no matching permission"}

decision := {"effect": "deny", "reason": "denied by policy"} if {
	denied
} else := scope_denial if {
	outside_scopes
} else := allow_with({"effect": "allow"}) if {
	allowed
} else := allow_with({"effect": "allow", "reason": "approved"}) if {
	count(approvable) > 0
	granted
} else := {
	"effect": "ask",
	"ask": {
		"channel": ask_channel,
		"prompt": sprintf("Allow %s: %s %s/%s?", [
			input.principal.sub, input.action,
			input.resource.server, input.resource.name,
		]),
		"scopes": ask_scopes,
		"fallback": "oob",
	},
} if {
	count(approvable) > 0
}
