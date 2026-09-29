package mcp.log_test

import rego.v1

import data.mcp.log

test_args_masked if {
	"/input/args" in log.mask with input as {
		"input": {"action": "tools.call", "args": {"path": "/etc/shadow"}},
		"result": {"effect": "allow"},
	}
}

test_args_kept_with_full_audit if {
	not "/input/args" in log.mask with input as {
		"input": {"action": "tools.call", "args": {"path": "/etc/shadow"}},
		"result": {"effect": "allow", "obligations": {"audit": "full"}},
	}
}

test_args_masked_for_filter_results if {
	"/input/args" in log.mask with input as {"input": {"resources": []}, "result": []}
}

test_approval_request_args_masked if {
	"/input/request/args" in log.mask with input as {"input": {"request": {"args": {"x": 1}}}, "result": true}
}

test_whatif_catalog_masked if {
	"/input/resources" in log.mask with input as {
		"path": "mcp/whatif/changes",
		"input": {"principals": [], "resources": [{"server": "fs"}], "proposed": {}},
		"result": [],
	}
	not "/input/resources" in log.mask with input as {"path": "mcp/filter/visible", "input": {"resources": []}, "result": []}
}
