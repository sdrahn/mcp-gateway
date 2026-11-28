package mcp.discovered_test

# Servers discovered from a cluster's Services (docs/architecture.md,
# section 5.12.8, D25): a server glob reaches them only with
# "discovered": true; a permission that names one does.

import rego.v1

import data.mcp.authz
import data.mcp.filter

bob := {"sub": "bob", "groups": [], "transport": "http", "session_id": "s1"}

rbac(perms) := {
	"version": 1,
	"roles": {"r": {"permissions": perms}},
	"bindings": {"users": {"bob": ["r"]}, "groups": {}},
}

found := {"namespace": "team-a", "service": "tickets"}

call(server, discovered) := {
	"principal": bob,
	"action": "tools.call",
	"resource": object.union({"server": server, "kind": "tool", "name": "open"}, discovered),
	"args": {},
	"grants": [],
}

discovered := {"discovered": found}

test_a_glob_does_not_reach_a_discovered_server if {
	d := authz.decision with input as call("team-a-tickets", discovered)
		with data.mcp.rbac as rbac([{"server": "*", "tool": "*"}])
	d.effect == "deny"
	d.reason == "no matching permission"
}

test_a_glob_reaches_a_server_of_the_files if {
	d := authz.decision with input as call("team-a-tickets", {})
		with data.mcp.rbac as rbac([{"server": "*", "tool": "*"}])
	d.effect == "allow"
}

test_a_glob_with_discovered_reaches_it if {
	d := authz.decision with input as call("team-a-tickets", discovered)
		with data.mcp.rbac as rbac([{"server": "team-a-*", "discovered": true, "tool": "*"}])
	d.effect == "allow"
}

test_a_permission_naming_it_reaches_it if {
	d := authz.decision with input as call("team-a-tickets", discovered)
		with data.mcp.rbac as rbac([{"server": "team-a-tickets", "tool": "open"}])
	d.effect == "allow"
}

test_a_glob_with_discovered_false_does_not if {
	d := authz.decision with input as call("team-a-tickets", discovered)
		with data.mcp.rbac as rbac([{"server": "team-a-*", "discovered": false, "tool": "*"}])
	d.effect == "deny"
}

# The default role data's viewer (list, read and get on '*') reaches
# nothing discovered: a team's Service does not give anyone access.
test_the_default_viewer_lists_nothing_discovered if {
	res := [
		{"server": "team-a-tickets", "kind": "tool", "name": "open", "discovered": found},
		{"server": "git", "kind": "tool", "name": "log"},
	]
	vs := filter.visible with input as {"principal": {"sub": "v", "groups": [], "transport": "http"}, "resources": res}
		with data.mcp.rbac as {
			"version": 1, "roles": {"viewer": {"permissions": [
				{"server": "*", "tool": "*"},
				{"server": "*", "resource": "*"},
				{"server": "*", "prompt": "*"},
			]}},
			"bindings": {"users": {"v": ["viewer"]}, "groups": {}},
		}
	count([r | some r in vs; r.server == "team-a-tickets"]) == 0
	count([r | some r in vs; r.server == "git"]) == 1
}
