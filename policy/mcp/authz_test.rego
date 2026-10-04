package mcp.authz_test

import rego.v1

import data.mcp.authz
import data.mcp.filter

alice := {"sub": "alice", "groups": ["dev"], "home": "/home/alice", "transport": "unix", "session_id": "s1"}

call(principal, server, tool, args) := {
	"principal": principal,
	"action": "tools.call",
	"resource": {"server": server, "kind": "tool", "name": tool},
	"args": args,
	"grants": [],
}

future := "2200-01-01T00:00:00Z"

past := "2000-01-01T00:00:00Z"

test_developer_may_use_git if {
	authz.decision.effect == "allow" with input as call(alice, "git", "commit", {})
}

test_unknown_user_denied if {
	d := authz.decision with input as call({"sub": "mallory", "session_id": "s9"}, "git", "commit", {})
	d.effect == "deny"
	d.reason == "no matching permission"
}

test_explicit_deny_wins if {
	admin_dev := object.union(alice, {"groups": ["dev", "wheel"]})
	d := authz.decision with input as call(admin_dev, "fs", "delete_file", {"path": "/home/alice/x"})
	d.effect == "deny"
	d.reason == "denied by policy"
}

test_write_in_own_home_asks if {
	d := authz.decision with input as call(alice, "fs", "write_file", {"path": "/home/alice/x.txt"})
	d.effect == "ask"
	d.ask.channel == "url"
}

test_write_outside_home_denied if {
	d := authz.decision with input as call(alice, "fs", "write_file", {"path": "/etc/passwd"})
	d.effect == "deny"
}

test_write_with_dotdot_denied if {
	d := authz.decision with input as call(alice, "fs", "write_file", {"path": "/home/alice/../bob/x"})
	d.effect == "deny"
}

test_home_constraint_needs_home if {
	homeless := object.remove(alice, ["home"])
	d := authz.decision with input as call(homeless, "fs", "write_file", {"path": "/x"})
	d.effect == "deny"
}

test_home_is_escaped if {
	dotted := object.union(alice, {"home": "/home/a.b"})
	authz.decision.effect == "ask" with input as call(dotted, "fs", "write_file", {"path": "/home/a.b/x"})
	authz.decision.effect == "deny" with input as call(dotted, "fs", "write_file", {"path": "/home/aXb/x"})
}

test_write_with_missing_arg_denied if {
	authz.decision.effect == "deny" with input as call(alice, "fs", "write_file", {})
}

test_session_grant_allows if {
	g := {"sub": "alice", "server": "fs", "tool": "write_file", "scope": "session", "session_id": "s1", "expires": future}
	inp := object.union(call(alice, "fs", "write_file", {"path": "/home/alice/x.txt"}), {"grants": [g]})
	authz.decision.effect == "allow" with input as inp
}

test_grant_from_other_session_ignored if {
	g := {"sub": "alice", "server": "fs", "tool": "write_file", "scope": "session", "session_id": "s2", "expires": future}
	inp := object.union(call(alice, "fs", "write_file", {"path": "/home/alice/x.txt"}), {"grants": [g]})
	authz.decision.effect == "ask" with input as inp
}

test_expired_grant_ignored if {
	g := {"sub": "alice", "server": "fs", "tool": "write_file", "scope": "duration", "expires": past}
	inp := object.union(call(alice, "fs", "write_file", {"path": "/home/alice/x.txt"}), {"grants": [g]})
	authz.decision.effect == "ask" with input as inp
}

test_grant_of_other_user_ignored if {
	g := {"sub": "bob", "server": "fs", "tool": "write_file", "scope": "duration", "expires": future}
	inp := object.union(call(alice, "fs", "write_file", {"path": "/home/alice/x.txt"}), {"grants": [g]})
	authz.decision.effect == "ask" with input as inp
}

test_grant_does_not_bypass_arg_constraints if {
	g := {"sub": "alice", "server": "fs", "tool": "write_file", "scope": "duration", "expires": future}
	inp := object.union(call(alice, "fs", "write_file", {"path": "/etc/passwd"}), {"grants": [g]})
	authz.decision.effect == "deny" with input as inp
}

req(principal, action, server, kind, name) := {
	"principal": principal,
	"action": action,
	"resource": {"server": server, "kind": kind, "name": name},
	"grants": [],
}

test_unknown_action_denied if {
	authz.decision.effect == "deny" with input as req(alice, "tools.frobnicate", "git", "tool", "commit")
}

test_resource_in_home_allowed if {
	authz.decision.effect == "allow" with input as req(alice, "resources.read", "fs", "resource", "file:///home/alice/notes.txt")
	authz.decision.effect == "allow" with input as req(alice, "resources.subscribe", "fs", "resource", "file:///home/alice/a/b.txt")
}

test_resource_outside_home_denied if {
	authz.decision.effect == "deny" with input as req(alice, "resources.read", "fs", "resource", "file:///etc/passwd")
	authz.decision.effect == "deny" with input as req(alice, "resources.read", "git", "resource", "file:///home/alice/x")
}

test_resource_dotdot_denied if {
	authz.decision.effect == "deny" with input as req(alice, "resources.read", "fs", "resource", "file:///home/alice/../bob/x")
	authz.decision.effect == "deny" with input as req(alice, "resources.read", "fs", "resource", "file:///home/alice/%2E%2e/bob/x")
}

test_resource_home_glob_escaped if {
	starry := object.union(alice, {"home": "/home/a*"})
	authz.decision.effect == "allow" with input as req(starry, "resources.read", "fs", "resource", "file:///home/a*/x")
	authz.decision.effect == "deny" with input as req(starry, "resources.read", "fs", "resource", "file:///home/abc/x")
}

test_tool_permission_does_not_grant_resource if {
	# developers may use every git tool, but no git resource
	authz.decision.effect == "deny" with input as req(alice, "resources.read", "git", "resource", "git://repo")
}

test_prompts if {
	authz.decision.effect == "allow" with input as req(alice, "prompts.get", "git", "prompt", "summarize")
	authz.decision.effect == "deny" with input as req({"sub": "mallory", "session_id": "s9"}, "prompts.get", "git", "prompt", "summarize")
}

test_completion if {
	authz.decision.effect == "allow" with input as req(alice, "completion.complete", "git", "prompt", "summarize")
	authz.decision.effect == "allow" with input as req(alice, "completion.complete", "fs", "resource_template", "file:///{path}")
	authz.decision.effect == "deny" with input as req(alice, "completion.complete", "git", "resource_template", "git://{repo}")
}

test_backend_requests if {
	admin := object.union(alice, {"groups": ["wheel"]})
	authz.decision.effect == "allow" with input as req(admin, "roots.list", "fs", "client", "roots/list")
	authz.decision.effect == "deny" with input as req(alice, "roots.list", "fs", "client", "roots/list")
	authz.decision.effect == "deny" with input as req(alice, "sampling.create", "fs", "client", "sampling/createMessage")
}

test_filter_hides_denied_tools if {
	resources := [
		{"server": "git", "kind": "tool", "name": "commit"},
		{"server": "fs", "kind": "tool", "name": "write_file"},
		{"server": "fs", "kind": "tool", "name": "delete_file"},
		{"server": "db", "kind": "tool", "name": "query"},
	]
	v := filter.visible with input as {"principal": alice, "resources": resources}
	v == {
		{"server": "git", "kind": "tool", "name": "commit"},
		{"server": "fs", "kind": "tool", "name": "write_file"},
	}
}

test_filter_resources_prompts_templates if {
	resources := [
		{"server": "fs", "kind": "resource", "name": "file:///home/alice/a.txt"},
		{"server": "fs", "kind": "resource", "name": "file:///etc/passwd"},
		{"server": "fs", "kind": "resource_template", "name": "file:///{path}"},
		{"server": "git", "kind": "resource_template", "name": "git://{repo}"},
		{"server": "git", "kind": "prompt", "name": "summarize"},
	]
	v := filter.visible with input as {"principal": alice, "resources": resources}
	v == {
		{"server": "fs", "kind": "resource", "name": "file:///home/alice/a.txt"},
		{"server": "fs", "kind": "resource_template", "name": "file:///{path}"},
		{"server": "git", "kind": "prompt", "name": "summarize"},
	}
}

test_obligations_merged if {
	perms := {"developer": {"permissions": [
		{"server": "fs", "tool": "read_*", "obligations": {"redact_output": "token=\\S+", "max_output_bytes": 4096, "arg_constraints": {"path": "^/srv/"}}},
		{"server": "fs", "tool": "read_file", "obligations": {"redact_output": ["AKIA\\w+"], "max_output_bytes": 1024, "rate_limit": "10/m", "arg_constraints": {"path": "\\.txt$"}, "audit": "full"}},
		{"server": "fs", "tool": "read_file"},
	]}}
	d := authz.decision with input as call(alice, "fs", "read_file", {}) with data.mcp.rbac.roles as perms
	d.effect == "allow"
	d.obligations == {
		"redact_output": ["AKIA\\w+", "token=\\S+"],
		"max_output_bytes": 1024,
		"rate_limit": ["10/m"],
		"arg_constraints": {"path": ["\\.txt$", "^/srv/"]},
		"audit": "full",
	}
}

test_pseudonymize_merged if {
	perms := {"developer": {"permissions": [
		{"server": "crm", "tool": "*", "obligations": {"pseudonymize": {"detect": ["email"], "fields": {"name": "person"}}}},
		{"server": "crm", "tool": "update_*", "obligations": {"pseudonymize": {"detect": "iban", "patterns": {"customer": "CUST-[0-9]+"}}, "reidentify": ["id", "note"]}},
		{"server": "crm", "tool": "update_customer", "obligations": {"reidentify": "id"}},
		{"server": "crm", "tool": "update_customer"},
	]}}
	d := authz.decision with input as call(alice, "crm", "update_customer", {}) with data.mcp.rbac.roles as perms
	d.effect == "allow"
	d.obligations == {
		"pseudonymize": {
			"detect": ["email", "iban"],
			"patterns": {"customer": "CUST-[0-9]+"},
			"fields": {"name": "person"},
		},
		"reidentify": ["id", "note"],
	}
}

test_no_obligations_no_field if {
	d := authz.decision with input as call(alice, "git", "commit", {})
	d == {"effect": "allow"}
}

test_obligations_on_approved if {
	perms := {"developer": {"permissions": [{"server": "fs", "tool": "write_file", "require_approval": true, "obligations": {"audit": "full"}}]}}
	g := {"sub": "alice", "server": "fs", "tool": "write_file", "scope": "duration", "expires": future}
	inp := object.union(call(alice, "fs", "write_file", {}), {"grants": [g]})
	d := authz.decision with input as inp with data.mcp.rbac.roles as perms
	d.effect == "allow"
	d.obligations.audit == "full"
}

test_sensitive_elicitation if {
	admin := object.union(alice, {"groups": ["wheel"]})
	plain := object.union(req(admin, "elicitation.create", "fs", "client", "elicitation/create"), {"args": {"mode": "form", "fields": ["color"], "sensitive": false}})
	authz.decision.effect == "allow" with input as plain
	secret := object.union(plain, {"args": {"mode": "form", "fields": ["password"], "sensitive": true}})
	authz.decision.effect == "deny" with input as secret
	perms := {"admin": {"permissions": [{"server": "fs", "client": "elicitation/create", "allow_sensitive": true}]}}
	authz.decision.effect == "allow" with input as secret with data.mcp.rbac.roles as perms
}

cert_rbac := {
	"roles": {"ops": {"permissions": [
		{"server": "fs", "tool": "read_*"},
		{"server": "fs", "tool": "write_*", "require_client_cert": true},
		# Nonsensical, but an explicit deny must never depend on it.
		{"server": "fs", "tool": "read_secret", "effect": "deny", "require_client_cert": true},
	]}},
	"bindings": {"users": {"u-remote": ["ops"]}, "groups": {}},
}

remote := {"sub": "u-remote", "iss": "https://idp", "transport": "http", "session_id": "r1"}

remote_with_cert := object.union(remote, {"cert": {"subject": "CN=agent", "x5t#S256": "abc"}})

test_require_client_cert if {
	authz.decision.effect == "allow" with input as call(remote_with_cert, "fs", "write_file", {}) with data.mcp.rbac as cert_rbac
	d := authz.decision with input as call(remote, "fs", "write_file", {}) with data.mcp.rbac as cert_rbac
	d.effect == "deny"
	d.reason == "no matching permission"
}

test_deny_applies_without_client_cert if {
	d := authz.decision with input as call(remote, "fs", "read_secret", {}) with data.mcp.rbac as cert_rbac
	d.reason == "denied by policy"
}

test_default_approval_scopes if {
	d := authz.decision with input as call(alice, "fs", "write_file", {"path": "/home/alice/x.txt"})
	d.ask.scopes == ["once", "session"]
}

test_approval_scopes_from_permission if {
	perms := {"developer": {"permissions": [{
		"server": "fs", "tool": "write_file", "require_approval": true,
		"approval_scopes": ["8h", "session", "30m", "1h"],
	}]}}
	d := authz.decision with input as call(alice, "fs", "write_file", {}) with data.mcp.rbac.roles as perms
	d.effect == "ask"
	d.ask.scopes == ["once", "session", "30m", "1h", "8h"]
}

test_approval_scopes_once_always if {
	perms := {"developer": {"permissions": [{
		"server": "fs", "tool": "write_file", "require_approval": true,
		"approval_scopes": ["1h"],
	}]}}
	d := authz.decision with input as call(alice, "fs", "write_file", {}) with data.mcp.rbac.roles as perms
	d.ask.scopes == ["once", "1h"]
}

test_approval_scopes_most_restrictive_permission if {
	perms := {"developer": {"permissions": [
		{"server": "fs", "tool": "write_file", "require_approval": true, "approval_scopes": ["session", "1h", "8h"]},
		{"server": "fs", "tool": "write_*", "require_approval": true, "approval_scopes": ["1h"]},
	]}}
	d := authz.decision with input as call(alice, "fs", "write_file", {}) with data.mcp.rbac.roles as perms
	d.ask.scopes == ["once", "1h"]
}

test_approval_scopes_invalid_ignored if {
	perms := {"developer": {"permissions": [{
		"server": "fs", "tool": "write_file", "require_approval": true,
		"approval_scopes": ["forever", "721h", "0h", "1d", "2h"],
	}]}}
	d := authz.decision with input as call(alice, "fs", "write_file", {}) with data.mcp.rbac.roles as perms
	d.ask.scopes == ["once", "2h"]
}

test_duration_grant_survives_new_session if {
	perms := {"developer": {"permissions": [{
		"server": "fs", "tool": "write_file", "require_approval": true,
		"approval_scopes": ["1h"],
	}]}}
	g := {"sub": "alice", "server": "fs", "tool": "write_file", "scope": "duration", "session_id": "old", "expires": future}
	inp := object.union(call(alice, "fs", "write_file", {}), {"grants": [g]})
	d := authz.decision with input as inp with data.mcp.rbac.roles as perms
	d == {"effect": "allow", "reason": "approved"}
}

privileged_call(tool) := json.patch(call(alice, "zypp", tool, {}), [{"op": "add", "path": "/resource/privileged", "value": true}])

test_privileged_wildcard_asks if {
	perms := {"developer": {"permissions": [{"server": "*", "tool": "*"}]}}
	d := authz.decision with input as privileged_call("confirm_install") with data.mcp.rbac.roles as perms
	d.effect == "ask"
	d.ask.scopes == ["once", "session"]
}

test_privileged_tool_wildcard_asks if {
	perms := {"developer": {"permissions": [{"server": "zypp", "tool": "plan_*"}]}}
	d := authz.decision with input as privileged_call("plan_install") with data.mcp.rbac.roles as perms
	d.effect == "ask"
}

test_privileged_exact_name_allows if {
	perms := {"developer": {"permissions": [{"server": "zypp", "tool": "search_packages"}]}}
	d := authz.decision with input as privileged_call("search_packages") with data.mcp.rbac.roles as perms
	d.effect == "allow"
}

test_privileged_deny_still_denies if {
	perms := {"developer": {"permissions": [
		{"server": "*", "tool": "*"},
		{"server": "zypp", "tool": "confirm_*", "effect": "deny"},
	]}}
	d := authz.decision with input as privileged_call("confirm_remove") with data.mcp.rbac.roles as perms
	d.effect == "deny"
}

test_privileged_wildcard_granted if {
	perms := {"developer": {"permissions": [{"server": "*", "tool": "*"}]}}
	granted_in := json.patch(privileged_call("confirm_install"), [{"op": "add", "path": "/grants", "value": [{
		"sub": "alice", "server": "zypp", "tool": "confirm_install",
		"scope": "once", "expires": future,
	}]}])
	d := authz.decision with input as granted_in with data.mcp.rbac.roles as perms
	d.effect == "allow"
	d.reason == "approved"
}

test_unprivileged_wildcard_allows if {
	perms := {"developer": {"permissions": [{"server": "*", "tool": "*"}]}}
	d := authz.decision with input as call(alice, "zypp", "confirm_install", {}) with data.mcp.rbac.roles as perms
	d.effect == "allow"
}

shipped := {"systemd": {"roles": {"systemd-reader": {
	"description": "read systemd",
	"permissions": [{"server": "systemd", "tool": "list_units"}],
}}}}

test_shipped_role_applies if {
	d := authz.decision with input as call(alice, "systemd", "list_units", {})
		with data.mcp.profiles as shipped
		with data.mcp.rbac.bindings as {"users": {"alice": ["systemd-reader"]}}
	d.effect == "allow"
}

test_shipped_role_needs_binding if {
	d := authz.decision with input as call(alice, "systemd", "list_units", {})
		with data.mcp.profiles as shipped
		with data.mcp.rbac.bindings as {"users": {}}
	d.effect == "deny"
}

test_admin_role_replaces_shipped_role if {
	d := authz.decision with input as call(alice, "systemd", "list_units", {})
		with data.mcp.profiles as shipped
		with data.mcp.rbac.roles as {"systemd-reader": {"permissions": [{"server": "systemd", "tool": "list_units", "effect": "deny"}]}}
		with data.mcp.rbac.bindings as {"users": {"alice": ["systemd-reader"]}}
	d.effect == "deny"
}

# The tool sign_in of a server the principal has not signed in to follows
# the server's tools; a server's own tool of that name does not.
test_sign_in_follows_server_tools if {
	rbac := {
		"bindings": {"users": {"alice": ["tickets-user"]}},
		"roles": {"tickets-user": {"permissions": [{"server": "tickets", "tool": "whoami"}]}},
	}
	signin := {
		"principal": alice, "action": "tools.call", "args": {}, "grants": [],
		"resource": {"server": "tickets", "kind": "tool", "name": "sign_in", "sign_in": true},
	}
	authz.decision.effect == "allow" with input as signin with data.mcp.rbac as rbac
	authz.decision.effect == "deny" with input as call(alice, "tickets", "sign_in", {}) with data.mcp.rbac as rbac
	other := object.union(signin, {"resource": {"server": "fs", "kind": "tool", "name": "sign_in", "sign_in": true}})
	authz.decision.effect == "deny" with input as other with data.mcp.rbac as rbac
}
