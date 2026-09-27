// Package router is the protocol-aware core of the gateway. It terminates
// the client's MCP session, maps requests onto backend instances
// (namespacing tools as "<server>__<tool>" on the aggregated endpoint),
// filters discovery results per principal, and passes every enforced
// method through the policy enforcement point before forwarding it.
//
// Requests sent by a backend to the client (sampling, elicitation, roots)
// are enforced as well. Unknown methods are denied.
//
// See docs/architecture.md, section 5.3.
package router
