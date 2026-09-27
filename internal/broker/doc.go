// Package broker implements permission elicitation: when policy answers
// "ask", the broker suspends the request, obtains a human decision via
// form-mode elicitation, URL-mode elicitation or an out-of-band channel,
// and records the outcome as a grant that is fed back into policy.
//
// It also vets elicitation requests that backends send to the client.
//
// See docs/architecture.md, section 5.6.
package broker
