# Masking for OPA's decision log (mcp-opa.service logs every decision to
# the journal). Tool arguments may carry personal data or secrets, so they
# are removed unless the decision asked for a full audit (obligation
# "audit": "full"), matching what the gateway's own audit record contains.
# The gateway's audit record carries the same decision_id
# (input.context.decision_id) and a keyed digest of the arguments.
package system.log

import rego.v1

mask contains "/input/args" if not full_audit

# Approver checks include the arguments of the pending request.
mask contains "/input/request/args"

full_audit if input.result.obligations.audit == "full"
