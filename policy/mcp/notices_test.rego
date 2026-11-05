package mcp.notices_test

import rego.v1

import data.mcp.approvals

# Notices to approvers (POST /v1/notices): the audience is decided as
# for a request of the notice's principal on one of its servers, by the
# same allow and notify rules; post_notice decides who may post.

agent := {"sub": "agent-patch-pilot", "uid": 1100}

notice_req(server) := {"principal": agent, "server": server, "name": "", "action": "notice", "servers": ["zypp"]}

notice := {"principal": "agent-patch-pilot", "servers": ["zypp"], "severity": "warning", "title": "patch-errata demoted"}

rbac := {
	"approvers": {"default": ["self"], "zypp": ["group:patchers", "role:admin"]},
	"bindings": {"users": {}, "groups": {"wheel": ["admin"]}},
}

pat := {"name": "pat", "uid": 1200, "groups": ["patchers"]}

carol := {"name": "carol", "uid": 1003, "groups": ["users", "wheel"]}

bob := {"name": "bob", "uid": 1002, "groups": ["users"]}

test_approvers_of_the_server_read_it if {
	approvals.allow with input as {"approver": pat, "request": notice_req("zypp"), "notice": notice} with data.mcp.rbac as rbac
	approvals.allow with input as {"approver": carol, "request": notice_req("zypp"), "notice": notice} with data.mcp.rbac as rbac
	not approvals.allow with input as {"approver": bob, "request": notice_req("zypp"), "notice": notice} with data.mcp.rbac as rbac
}

test_mail_goes_to_the_servers_recipients if {
	got := approvals.notify with input as {"request": notice_req("zypp"), "notice": notice} with data.mcp.rbac as rbac
	got == {"group:patchers", "group:wheel"}
}

test_post_notice_default_nobody if {
	not approvals.post_notice with input as {"approver": carol, "notice": notice}
	not approvals.post_notice with input as {"approver": pat, "notice": notice}
}
