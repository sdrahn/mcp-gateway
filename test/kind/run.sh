#!/bin/bash
# The container image in a kind cluster (roadmap step 46, D23): builds the
# gateway's image and a server that speaks HTTP (echo), deploys
# deploy/kubernetes with test/kind's overlay, and checks as an agent with
# a ServiceAccount token of the cluster (no other identity provider):
#   - the call reaches echo through the gateway, which runs as one pod
#     with OPA and the role data renderer beside it;
#   - a token for another audience is refused;
#   - a server added to the servers ConfigMap is served once the kubelet
#     updates the mounted files (the ..data swap; docs/architecture.md,
#     section 12);
#   - role data changed in its ConfigMap takes effect (mcp-policy-render
#     and OPA follow the swap too).
# DEPLOY=helm deploys the chart (deploy/helm/mcp-gateway, with
# test/kind/values.yaml) instead of the manifests. Needs docker (or
# CONTAINER=podman), kind, kubectl, openssl, curl, jq, go, and helm for
# DEPLOY=helm. KEEP=1 keeps the cluster.
set -euo pipefail
cd "$(dirname "$0")/../.."

KIND=${KIND:-kind}
KUBECTL=${KUBECTL:-kubectl}
CONTAINER=${CONTAINER:-docker}
CLUSTER=${CLUSTER:-mcpgw}
DEPLOY=${DEPLOY:-kustomize}
HELM=${HELM:-helm}
IMAGE_BASE=${IMAGE_BASE:-registry.suse.com/bci/bci-micro:15.7}
NS=mcp-gateway
PORT=${PORT:-18443}

work=$(mktemp -d)
pf=
cleanup() {
	status=$?
	if [ "$status" != 0 ]; then
		echo "--- failed; the pods and their logs:" >&2
		k -n "$NS" get pods -o wide >&2 || true
		for c in gateway policy-render opa; do
			echo "--- $c" >&2
			k -n "$NS" logs deploy/mcp-gateway -c "$c" --tail=60 >&2 || true
		done
	fi
	[ -n "$pf" ] && kill "$pf" 2>/dev/null || true
	rm -rf "$work"
	if [ "${KEEP:-}" != 1 ]; then
		"$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
	fi
	exit "$status"
}
trap cleanup EXIT
k() { "$KUBECTL" --context "kind-$CLUSTER" "$@"; }
apply() { k apply -f - >/dev/null; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

echo "--- images"
make image IMAGE=mcp-gateway:test IMAGE_BASE="$IMAGE_BASE" CONTAINER="$CONTAINER"
CGO_ENABLED=0 go build -o "$work/echo" ./test/kind/echo
"$CONTAINER" build -q -f test/kind/echo/Containerfile --build-arg BASE="$IMAGE_BASE" -t mcp-echo:test "$work" >/dev/null

echo "--- cluster"
"$KIND" get clusters 2>/dev/null | grep -qx "$CLUSTER" || "$KIND" create cluster --name "$CLUSTER" --wait 180s
"$KIND" load docker-image mcp-gateway:test mcp-echo:test --name "$CLUSTER"

k create namespace "$NS" --dry-run=client -o yaml | apply
k create namespace agents --dry-run=client -o yaml | apply
k -n agents create serviceaccount custos --dry-run=client -o yaml | apply
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=mcp-gateway \
	-addext "subjectAltName=IP:127.0.0.1,DNS:mcp-gateway.$NS.svc" \
	-keyout "$work/tls.key" -out "$work/tls.crt" 2>/dev/null
k -n "$NS" create secret tls mcp-gateway-tls --cert "$work/tls.crt" --key "$work/tls.key" --dry-run=client -o yaml | apply

echo "--- deploy ($DEPLOY)"
case "$DEPLOY" in
kustomize) k apply -k test/kind >/dev/null ;;
helm)
	k -n "$NS" apply -f test/kind/echo.yaml >/dev/null
	"$HELM" --kube-context "kind-$CLUSTER" -n "$NS" upgrade --install mcp-gateway deploy/helm/mcp-gateway \
		-f test/kind/values.yaml >/dev/null
	;;
*) fail "DEPLOY: kustomize or helm, not $DEPLOY" ;;
esac
k -n "$NS" rollout status deploy/mcp-echo --timeout=180s
k -n "$NS" rollout status deploy/mcp-gateway --timeout=240s

k -n "$NS" port-forward svc/mcp-gateway "$PORT:443" >"$work/pf.log" 2>&1 &
pf=$!
for _ in $(seq 60); do
	curl -s --cacert "$work/tls.crt" -o /dev/null "https://127.0.0.1:$PORT/.well-known/oauth-protected-resource/mcp" && break
	sleep 1
done
meta=$(curl -sf --cacert "$work/tls.crt" "https://127.0.0.1:$PORT/.well-known/oauth-protected-resource/mcp") ||
	fail "the gateway does not answer: $(cat "$work/pf.log")"
[ "$(jq -r '.authorization_servers[0]' <<<"$meta")" = https://kubernetes.default.svc.cluster.local ] ||
	fail "metadata: $meta"
pass "metadata names the cluster's issuer"

token=$(k -n agents create token custos --audience mcp-gateway --duration 30m)

# post SERVER TOKEN BODY [SESSION]: the response body; the session id
# goes to $work/session.
post() {
	local h=()
	[ -n "${4:-}" ] && h=(-H "Mcp-Session-Id: $4" -H "MCP-Protocol-Version: 2025-06-18")
	curl -s --cacert "$work/tls.crt" -D "$work/headers" -w '\n%{http_code}' \
		-H "Authorization: Bearer $2" -H 'Content-Type: application/json' -H 'Accept: application/json' \
		"${h[@]}" -d "$3" "https://127.0.0.1:$PORT/mcp/$1"
	tr -d '\r' <"$work/headers" | sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: //p' >"$work/session"
}
# call SERVER TEXT: the echo tool's answer through the gateway, as custos.
call() {
	local out session
	out=$(post "$1" "$token" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"kind-test"}}}')
	[ "$(tail -n1 <<<"$out")" = 200 ] || { echo "initialize: $out"; return; }
	session=$(cat "$work/session")
	post "$1" "$token" '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$session" >/dev/null
	out=$(post "$1" "$token" "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"$2\"}}}" "$session")
	head -n -1 <<<"$out" | jq -r 'if .result then (if .result.isError then "error: " else "" end) + .result.content[0].text else "error: " + .error.message end'
}
# until SECONDS COMMAND...: retries COMMAND until it succeeds.
until_ok() {
	local deadline=$((SECONDS + $1))
	shift
	until "$@"; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 3
	done
}

got=$(call echo hi)
[[ "$got" == "echo: hi (call 1)" ]] || fail "call as the ServiceAccount: $got"
pass "a ServiceAccount token's call reaches echo, once"

wrong=$(k -n agents create token custos --duration 10m)
code=$(post echo "$wrong" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | tail -n1)
[ "$code" = 401 ] || fail "a token for the API server's audience: HTTP $code"
pass "a token for another audience is refused"

echo "--- a server added to the ConfigMap"
k -n "$NS" patch configmap mcp-gateway-servers --type merge \
	-p "{\"data\":{\"echo2.yaml\":\"name: echo2\\nurl: http://mcp-echo.$NS.svc:8080/mcp\\n\"}}" >/dev/null
echo2_served() { [[ "$(call echo2 again)" == "echo: again"* ]]; }
until_ok 180 echo2_served || fail "echo2 not served after the ConfigMap changed: $(call echo2 again)"
pass "the gateway reloads the servers ConfigMap"

echo "--- role data changed in the ConfigMap"
k -n "$NS" patch configmap mcp-gateway-rbac --type merge -p '{"data":{"data.yaml":"version: 1\nroles: {}\nbindings: {users: {}, groups: {}}\n"}}' >/dev/null
denied() { [[ "$(call echo bye)" != "echo: "* ]]; }
until_ok 180 denied || fail "still allowed after the role data changed: $(call echo bye)"
pass "role data from the ConfigMap takes effect"

echo "PASS"
