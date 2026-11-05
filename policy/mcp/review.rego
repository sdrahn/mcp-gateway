package mcp.authz

import rego.v1

# METADATA
# scope: document
# description: |
#   Calls to review after they ran (the obligation "review": a review
#   item for the call's approvers, chapter 7). A permission marks them
#   with obligations: {review: true}; a module marks a sample of them
#   with `review_wanted if { … }`, its own rule deciding which.
default review_wanted := false

obligation_entries contains ["review", true] if review_wanted

obligation_entries contains ["review", true] if {
	some p in applicable
	p.obligations.review == true
}
