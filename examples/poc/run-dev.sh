#!/bin/sh
# Runs the proof of concept in development mode as the current user:
# OPA with the shipped policy and the PoC role data, and the gateway with
# the exec supervisor (no systemd, no SELinux confinement) in front of
# mcp-fs-demo operating on $HOME.
#
# Usage: examples/poc/run-dev.sh [workdir]   (default: a new temp dir)
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=${1:-$(mktemp -d /tmp/mcpgw.XXXXXX)}
opa=${OPA:-opa}
command -v "$opa" >/dev/null || { echo "opa not found (set \$OPA)" >&2; exit 1; }

make -C "$repo" build >/dev/null
mkdir -p "$work/servers.d" "$work/data/rbac"

# PoC role data, with the current user bound to "developer".
sed "s/\"users\": {}/\"users\": {\"$(id -un)\": [\"developer\"]}/" \
    "$repo/examples/poc/rbac/data.json" >"$work/data/rbac/data.json"

cat >"$work/servers.d/fs.yaml" <<YAML
name: fs
command: ["$repo/bin/mcp-fs-demo", "--root", "\${HOME}"]
run_as: gateway
YAML

cat >"$work/gateway.yaml" <<YAML
socket: $work/mcp.sock
servers_dir: $work/servers.d
state_dir: $work/state
approvals:
  control_socket: $work/control.sock
policy:
  opa_socket: $work/opa.sock
supervisor:
  mode: exec
YAML

# The policy logic (without the default role data in policy/mcp/rbac) and
# the PoC role data below data.mcp, as mcp-opa.service loads them.
"$opa" run --server --addr "unix://$work/opa.sock" \
    --set=decision_logs.mask_decision=/mcp/log/mask \
    "$repo"/policy/mcp/*.rego "mcp:$work/data" >"$work/opa.log" 2>&1 &
opa_pid=$!
trap 'kill $opa_pid 2>/dev/null' EXIT INT TERM
while [ ! -S "$work/opa.sock" ]; do sleep 0.1; done

cat <<MSG
Gateway socket: $work/mcp.sock
MCP client configuration:

  { "command": "$repo/bin/mcp-connect",
    "args": ["--socket", "$work/mcp.sock", "--server", "fs"] }

Approvals inbox (control API, as you):
  curl --unix-socket $work/control.sock http://x/v1/approvals

Logs: $work/opa.log (OPA); gateway and audit records below.
MSG
"$repo/bin/mcp-gateway" --config "$work/gateway.yaml"
