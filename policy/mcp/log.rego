# Masking for OPA's decision log (mcp-opa.service logs every decision to
# the journal). OPA uses it because mcp-opa.service sets
# decision_logs.mask_decision to /mcp/log/mask; OPA's default,
# data.system.log.mask, stays free for other policies in a shared OPA. Tool arguments may carry personal data or secrets, so they
# are removed unless the decision asked for a full audit (obligation
# "audit": "full"), matching what the gateway's own audit record contains.
# The gateway's audit record carries the same decision_id
# (input.context.decision_id) and a keyed digest of the arguments.
package mcp.log

import rego.v1

mask contains "/input/args" if not full_audit

# Approver checks include the arguments of the pending request.
mask contains "/input/request/args"

full_audit if input.result.obligations.audit == "full"
