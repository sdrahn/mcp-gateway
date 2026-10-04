// Package signin signs principals in to MCP servers defined with url and
// sign_in, and keeps their tokens (docs/architecture.md, section 5.7.3,
// decision D16): the pending sign-ins, the callback, the token store,
// refreshes, and the access token each instance gets as a credential.
// Every request to a server or its authorization server is made by
// mcp-oauth-helper, never by the gateway.
package signin
