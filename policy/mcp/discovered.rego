package mcp.authz

# A server discovered from a cluster's Service (input.resource.discovered;
# docs/architecture.md, section 5.12.8, D25) is matched by a permission
# that names it, or whose server glob says "discovered": true: discovery
# grants no access, so a glob written for the servers the administrator
# defined ('*', 'git-*') does not reach what a team's Service adds.
discovered_ok(_) if not input.resource.discovered

discovered_ok(p) if not has_glob(p.server)

discovered_ok(p) if p.discovered == true
