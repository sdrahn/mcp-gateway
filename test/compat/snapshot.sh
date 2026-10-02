#!/bin/bash
# Takes the configuration a release ships, laid out as installed, into
# test/compat/<major.minor>; compat_test.go checks that the gateway still
# reads it. When a minor release is made, take a snapshot of it and remove
# the one before: the configuration of the previous minor release must
# work, older ones may use keys that were deprecated and removed since
# (docs/architecture.md, decision D10).
#
# Usage: test/compat/snapshot.sh <tag>, e.g. v0.3.2
set -euo pipefail
tag=${1:?usage: $0 <tag>}
cd "$(dirname "$0")/../.."
minor=$(echo "${tag#v}" | cut -d. -f1,2)
out=test/compat/$minor
rm -rf "$out"
mkdir -p "$out/servers.d" "$out/admin-servers.d" "$out/policy/rbac"

show() { git show "$tag:$1" >"$2"; }
show config/gateway.yaml "$out/gateway.yaml"
show config/servers.d/fs.yaml "$out/servers.d/fs.yaml"
show policy/mcp/rbac/data.json "$out/policy/rbac/data.json"
# Server setups (from 0.4 on).
profiles=$(git ls-tree --name-only "$tag:profiles" 2>/dev/null || true)
for p in $profiles; do
	git cat-file -e "$tag:profiles/$p/$p.yaml" 2>/dev/null || continue
	show "profiles/$p/$p.yaml" "$out/servers.d/$p.yaml"
	mkdir -p "$out/policy/mcp/profiles/$p"
	show "profiles/$p/roles.json" "$out/policy/mcp/profiles/$p/data.json"
done
# The privileged variant, as an administrator links it into
# /etc/mcp-gateway/servers.d.
if git cat-file -e "$tag:profiles/zypp/zypp-privileged.yaml" 2>/dev/null; then
	show profiles/zypp/zypp-privileged.yaml "$out/admin-servers.d/zypp.yaml"
fi
echo "$tag" >"$out/TAG"
