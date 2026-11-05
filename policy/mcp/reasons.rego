# Reasons of denials that tell the agent what its roles allow
# (docs/architecture.md, roadmap step 29).
package mcp.authz

import rego.v1

# The argument constraints of the principal's permissions that name the
# target but whose constraints the arguments fail, one text per
# permission ("path: ^/home/alice/"), for the reason of the denial: the
# agent learns what its roles allow instead of trying again blindly. The
# values the agent sent are not repeated (the decision log keeps no
# arguments).
args_limits contains limit if {
	field := target_field[input.action]
	target_ok(field)
	some p in perms
	not p.effect == "deny"
	server_ok(p)
	glob.match(expand_glob(p[field]), null, input.resource.name)
	count(object.get(p, "args", {})) > 0
	not args_ok(p)
	limit := concat(", ", sort([sprintf("%s: %s", [name, expand(pattern)]) | some name, pattern in p.args]))
}

args_reason := sprintf(
	"no matching permission: the arguments are outside what your roles allow (%s)",
	[concat("; or ", sort(args_limits))],
)

# METADATA
# description: |
#   Why a request is denied, for a module that adds to `denied`: each
#   text is one reason, and the decision's reason is all of them, sorted
#   and joined with "; " (an empty set: "denied by policy"). The shipped
#   policy names a permission that denies the request; a module adds its
#   own (`deny_reasons contains "the agent is paused" if { … }`).
deny_reasons contains "denied by policy" if {
	some p in matching
	p.effect == "deny"
}

default denial_reason := "denied by policy"

denial_reason := concat("; ", sort(deny_reasons)) if {
	count(deny_reasons) > 0
}

# METADATA
# scope: document
# description: |
#   The reason of a request that matches no permission. A module that
#   leaves a permission out ("this would have been permitted, but …")
#   explains it with `unmatched_reasons contains "…" if { … }`: the
#   reason is all of them, sorted and joined with "; ", instead of "no
#   matching permission". The shipped policy defines no such rule, so
#   it is referred to by its full path (undefined without a module).
default unmatched_reason := "no matching permission"

unmatched_reason := concat("; ", sort(data.mcp.authz.unmatched_reasons)) if {
	count(data.mcp.authz.unmatched_reasons) > 0
}
