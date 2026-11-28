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
#   - a stdio server runs in pods of its own (the Kubernetes launcher):
#     one per principal, each with a NetworkPolicy without egress (the
#     server cannot reach another pod), owned by the pod, and deleted
#     after the idle timeout;
#   - a rolling update of the replicas cuts no call off: a caller in the
#     cluster calls through the Service all along;
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
IMAGE_BASE=${IMAGE_BASE:-registry.suse.com/bci/bci-micro:16.0}
NS=mcp-gateway
PORT=${PORT:-18443}
# The gateway's replicas (replicas.yaml, values.yaml).
REPLICAS=3
MPORT=${MPORT:-19464}

work=$(mktemp -d)
pf=
pfs=()
cleanup() {
	status=$?
	if [ "$status" != 0 ]; then
		echo "--- failed; the pods and their logs:" >&2
		k -n "$NS" get pods -o wide >&2 || true
		for c in gateway policy-render opa; do
			echo "--- $c" >&2
			k -n "$NS" logs deploy/mcp-gateway -c "$c" --tail=60 >&2 || true
		done
		if k -n agents get pod caller >/dev/null 2>&1; then
			echo "--- the caller" >&2
			k -n agents logs caller --tail=30 >&2 || true
		fi
		echo "--- mcp-instances" >&2
		k -n mcp-instances get pods,networkpolicies,secrets -o wide >&2 || true
		for pod in $(k -n mcp-instances get pods -o name 2>/dev/null); do
			k -n mcp-instances describe "$pod" | tail -20 >&2 || true
			k -n mcp-instances logs "$pod" --all-containers --tail=20 >&2 || true
		done
	fi
	[ -n "$pf" ] && kill "$pf" 2>/dev/null || true
	for p in "${pfs[@]}"; do kill "$p" 2>/dev/null || true; done
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
k -n agents create serviceaccount other --dry-run=client -o yaml | apply
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=mcp-gateway \
	-addext "subjectAltName=IP:127.0.0.1,DNS:mcp-gateway.$NS.svc" \
	-keyout "$work/tls.key" -out "$work/tls.crt" 2>/dev/null
k -n "$NS" create secret tls mcp-gateway-tls --cert "$work/tls.crt" --key "$work/tls.key" --dry-run=client -o yaml | apply
# The replicas' certificate (replication.peer_*): a CA of its own, and a
# certificate for mcp-gateway-peer, for the server and the client.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=mcp-gateway-peers \
	-keyout "$work/peer-ca.key" -out "$work/peer-ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=mcp-gateway-peer \
	-keyout "$work/peer.key" -out "$work/peer.csr" 2>/dev/null
printf 'subjectAltName=DNS:mcp-gateway-peer\nextendedKeyUsage=serverAuth,clientAuth\n' >"$work/peer.ext"
openssl x509 -req -in "$work/peer.csr" -CA "$work/peer-ca.crt" -CAkey "$work/peer-ca.key" -CAcreateserial -days 1 \
	-extfile "$work/peer.ext" -out "$work/peer.crt" 2>/dev/null
k -n "$NS" create secret generic mcp-gateway-peer --from-file=tls.crt="$work/peer.crt" --from-file=tls.key="$work/peer.key" \
	--from-file=ca.crt="$work/peer-ca.crt" --dry-run=client -o yaml | apply

echo "--- deploy ($DEPLOY)"
case "$DEPLOY" in
kustomize) k apply -k test/kind >/dev/null ;;
helm)
	k -n "$NS" apply -f test/kind/echo.yaml >/dev/null
	# A Secret the chart mounts (values.yaml, secrets).
	k -n "$NS" create secret generic mcp-gateway-kind --from-literal=value=kind-secret-value --dry-run=client -o yaml | apply
	"$HELM" --kube-context "kind-$CLUSTER" -n "$NS" upgrade --install mcp-gateway deploy/helm/mcp-gateway \
		-f test/kind/values.yaml >/dev/null
	;;
*) fail "DEPLOY: kustomize or helm, not $DEPLOY" ;;
esac
k -n "$NS" rollout status deploy/mcp-echo --timeout=180s
k -n "$NS" rollout status deploy/mcp-gateway --timeout=240s

# forward: a port-forward to the Service (to one of its pods), again after
# a pod went.
forward() {
	[ -n "$pf" ] && kill "$pf" 2>/dev/null || true
	k -n "$NS" port-forward svc/mcp-gateway "$PORT:443" "$MPORT:9464" >"$work/pf.log" 2>&1 &
	pf=$!
	for _ in $(seq 60); do
		curl -s --cacert "$work/tls.crt" -o /dev/null "https://127.0.0.1:$PORT/.well-known/oauth-protected-resource/mcp" && break
		sleep 1
	done
}
forward
meta=$(curl -sf --cacert "$work/tls.crt" "https://127.0.0.1:$PORT/.well-known/oauth-protected-resource/mcp") ||
	fail "the gateway does not answer: $(cat "$work/pf.log")"
[ "$(jq -r '.authorization_servers[0]' <<<"$meta")" = https://kubernetes.default.svc.cluster.local ] ||
	fail "metadata: $meta"
pass "metadata names the cluster's issuer"

# The probes (the pod is ready, so /readyz passed) and the metrics.
[ "$(curl -s "http://127.0.0.1:$MPORT/readyz")" = ready ] && [ "$(curl -s "http://127.0.0.1:$MPORT/healthz")" = ok ] ||
	fail "probes: $(curl -s "http://127.0.0.1:$MPORT/readyz")"
curl -s "http://127.0.0.1:$MPORT/metrics" | grep -q '^mcp_gateway_instances ' || fail "no metrics"
pass "/readyz, /healthz and /metrics on the metrics port"

if [ "$DEPLOY" = helm ]; then
	# The chart's secrets: mounted for the gateway's account, for no one else.
	got=$(k -n "$NS" exec deploy/mcp-gateway -c gateway -- cat /etc/mcp-gateway/secrets/mcp-gateway-kind/value)
	[ "$got" = kind-secret-value ] || fail "the Secret as the gateway's account reads it: $got"
	mode=$(k -n "$NS" exec deploy/mcp-gateway -c gateway -- stat -L -c '%a %g' /etc/mcp-gateway/secrets/mcp-gateway-kind/value)
	[ "$mode" = "440 10001" ] || fail "the Secret's file: mode and group $mode, want 440 10001"
	pass "a Secret of the chart's secrets: the gateway's account reads it, others do not ($mode)"
fi

# The doctor in the gateway, asked as the gateway's account in its
# container (the control socket): nothing fails, and the cluster's
# checks ran.
doc=$(k -n "$NS" exec deploy/mcp-gateway -c gateway -- mcp-gateway-admin doctor --config /etc/mcp-gateway/config/gateway.yaml --json) || true
[ "$(jq '[.[] | select(.status == "fail")] | length' <<<"$doc" 2>/dev/null)" = 0 ] || fail "doctor: $doc"
[ "$(jq '[.[] | select(.id == "policy" or .id == "state-volume" or .id == "kubernetes-api" or .id == "identity-provider" or
	.id == "shared-store")] | length >= 5 and all(.status == "ok")' <<<"$doc")" = true ] || fail "doctor: $doc"
pass "the doctor in the gateway: $(jq -r '[.[] | .id + " " + .status] | join(", ")' <<<"$doc")"

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
# call_as TOKEN SERVER TOOL ARGUMENTS: the tool's answer through the
# gateway, in a session of its own, which it ends.
call_as() {
	local out session
	out=$(post "$2" "$1" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"kind-test"}}}')
	[ "$(tail -n1 <<<"$out")" = 200 ] || { echo "initialize: $out"; return; }
	session=$(cat "$work/session")
	post "$2" "$1" '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$session" >/dev/null
	out=$(post "$2" "$1" "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$3\",\"arguments\":$4}}" "$session")
	head -n -1 <<<"$out" | jq -r 'if .result then (if .result.isError then "error: " else "" end) + .result.content[0].text else "error: " + .error.message end'
	curl -s --cacert "$work/tls.crt" -o /dev/null -X DELETE -H "Authorization: Bearer $1" -H "Mcp-Session-Id: $session" \
		-H "MCP-Protocol-Version: 2025-06-18" "https://127.0.0.1:$PORT/mcp/$2"
}
# call SERVER TEXT: the echo tool's answer, as custos.
call() { call_as "$token" "$1" echo "{\"text\":\"$2\"}"; }
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

echo "--- the shared store"
# records COLLECTION: the gateway's Secrets of that collection.
records() {
	k -n "$NS" get secrets -l "app.kubernetes.io/managed-by=mcp-gateway,mcp-gateway.io/collection=$1" -o json
}
[ "$(records keys | jq '[.items[].metadata.annotations["mcp-gateway.io/name"]] | index("audit") != null and index("imported") != null')" = true ] ||
	fail "keys in the shared store: $(records keys | jq -c '[.items[].metadata.annotations]')"
kept() { [ "$(records clients | jq '.items | length')" -ge 1 ]; }
until_ok 30 kept || fail "the client of the call is not in the shared store"
pass "the audit key and the client of the call are records of the shared store"

echo "--- a server added to the ConfigMap"
k -n "$NS" patch configmap mcp-gateway-servers --type merge \
	-p "{\"data\":{\"echo2.yaml\":\"name: echo2\\nurl: http://mcp-echo.$NS.svc:8080/mcp\\n\"}}" >/dev/null
echo2_served() { [[ "$(call echo2 again)" == "echo: again"* ]]; }
until_ok 180 echo2_served || fail "echo2 not served after the ConfigMap changed: $(call echo2 again)"
pass "the gateway reloads the servers ConfigMap"

echo "--- a stdio server in pods of its own"
INS=mcp-instances
other=$(k -n agents create token other --audience mcp-gateway --duration 30m)
pods() {
	k -n "$INS" get pods -l mcp-gateway.sdrahn.github.io/server=stdio \
		-o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort
}
before=$(pods)
got=$(call_as "$token" stdio echo '{"text":"in a pod"}')
[[ "$got" == "echo: in a pod (call 1)" ]] || fail "call to the stdio server as custos: $got"
got=$(call_as "$other" stdio echo '{"text":"in a pod"}')
# Another principal's instance: its own count.
[[ "$got" == "echo: in a pod (call 1)" ]] || fail "call to the stdio server as other: $got"
# The principals' pods (a shared discovery instance may have come too):
# whom each serves is in its MCP_GATEWAY_PRINCIPAL.
serves() {
	k -n "$INS" get pod "$1" -o json |
		jq -r '.spec.containers[0].env[] | select(.name == "MCP_GATEWAY_PRINCIPAL") | .value | fromjson | .sub // ""'
}
mine=$(for pod in $(comm -13 <(echo "$before") <(pods)); do
	case "$(serves "$pod")" in *agents:custos | *agents:other) echo "$pod" ;; esac
done)
[ "$(grep -c . <<<"$mine")" = 2 ] || fail "pods of the two principals: $mine (all: $(pods | tr '\n' ' '))"
[ "$(for pod in $mine; do serves "$pod"; done | sort -u | wc -l)" = 2 ] || fail "both pods serve one principal: $mine"
pass "a stdio server runs in a pod per principal"

# replicas: the holders of the replicas' Leases (replication;
# docs/architecture.md, section 5.12.5), each a gateway pod not being
# deleted.
replicas() {
	k -n "$NS" get leases -l mcp-gateway.io/role=replica -o jsonpath='{range .items[*]}{.spec.holderIdentity}{"\n"}{end}'
}
live_pod() { [ -z "$(k -n "$NS" get pod "$1" -o jsonpath='{.metadata.deletionTimestamp}')" ]; }
# replica_of POD: the replica an instance pod names.
replica_of() { k -n "$INS" get pod "$1" -o jsonpath='{.metadata.labels.mcp-gateway\.sdrahn\.github\.io/replica}'; }
# The three replicas hold their Leases, and each instance pod names one
# of them, the one that serves its principal.
gws=$(replicas | sort)
[ "$(grep -c . <<<"$gws")" = "$REPLICAS" ] || fail "replica Leases: $gws (want $REPLICAS)"
for r in $gws; do live_pod "$r" || fail "the replica $r is not a live pod"; done
for pod in $mine; do
	grep -qx "$(replica_of "$pod")" <<<"$gws" || fail "pod $pod names $(replica_of "$pod"), not a replica of $(tr '\n' ' ' <<<"$gws")"
done
pass "$REPLICAS replicas hold their Leases; the instance pods name theirs"

for pod in $mine; do
	np=$(k -n "$INS" get networkpolicy "$pod" -o json) || fail "no NetworkPolicy for $pod"
	[ "$(jq '.spec.egress | length' <<<"$np")" = 0 ] && [ "$(jq -r '.metadata.ownerReferences[0].kind' <<<"$np")" = Pod ] ||
		fail "NetworkPolicy of $pod: $np"
	spec=$(k -n "$INS" get pod "$pod" -o json)
	[ "$(jq '.spec.securityContext.runAsUser >= 100000 and .spec.securityContext.runAsNonRoot and
		(.spec.containers[0].securityContext.readOnlyRootFilesystem) and
		(.spec.automountServiceAccountToken == false)' <<<"$spec")" = true ] || fail "pod $pod: $(jq .spec <<<"$spec")"
done
pass "each pod: its own NetworkPolicy without egress, a uid of its own, read-only, no token"

# Another pod (the echo server's Service, which the gateway reaches):
# denied by the instance's NetworkPolicy, as everything is.
echo_ip=$(k -n "$NS" get service mcp-echo -o jsonpath='{.spec.clusterIP}')
got=$(call_as "$token" stdio reach "{\"address\":\"$echo_ip:8080\"}")
[[ "$got" == unreachable* ]] || fail "the stdio server reached another pod, $echo_ip:8080: $got"
pass "the stdio server reaches no other pod (no egress)"
# The API server's endpoint is on the host network, which a NetworkPolicy
# covers or not as the network plugin implements it (kind's kindnet does
# not): informational. The instance has no token for it in any case.
api=$(k get service kubernetes -o jsonpath='{.spec.clusterIP}')
echo "info: the API server at $api:443 from an instance: $(call_as "$token" stdio reach "{\"address\":\"$api:443\"}")"

gone() { [ -z "$(comm -12 <(echo "$mine") <(pods) | grep . || true)" ]; }
until_ok 150 gone || fail "pods still there after the idle timeout: $(pods | tr '\n' ' ')"
pass "the pods go after the idle timeout"

echo "--- one principal through each replica"
# A port-forward to each replica's pod, past the Service's choice.
ports=()
i=0
for r in $gws; do
	p=$((PORT + 100 + i))
	i=$((i + 1))
	k -n "$NS" port-forward "pod/$r" "$p:8443" >"$work/pf-$r.log" 2>&1 &
	pfs+=($!)
	ports+=("$p")
	for _ in $(seq 30); do
		curl -s --cacert "$work/tls.crt" -o /dev/null "https://127.0.0.1:$p/.well-known/oauth-protected-resource/mcp" && break
		sleep 1
	done
done
n=0
for p in "${ports[@]}"; do
	n=$((n + 1))
	got=$(PORT=$p call_as "$token" stdio echo '{"text":"via each"}')
	[[ "$got" == "echo: via each (call $n)" ]] || fail "call $n, through the replica at port $p: $got"
done
custos_pod() {
	for pod in $(pods); do
		case "$(serves "$pod")" in *agents:custos) echo "$pod" ;; esac
	done
}
[ "$(custos_pod | grep -c .)" = 1 ] || fail "custos's instance pods: $(custos_pod | tr '\n' ' ')"
owner=$(replica_of "$(custos_pod)")
pass "custos's calls through each of the $REPLICAS replicas reach one instance, at $owner"
# The owner wrote their audit records, which name it.
owner_log=$(k -n "$NS" logs "$owner" -c gateway)
grep '"audit":true' <<<"$owner_log" | grep 'agents:custos"' | grep "\"replica\":\"$owner\"" >/dev/null ||
	fail "no audit record of custos names $owner"
pass "the audit records of custos's calls name $owner"

# Another replica lists custos's instance, as $owner's, and stops it there
# (mcp-gateway-admin instances, as the gateway's account: an approver in
# the role data).
admin() { k -n "$NS" exec "$1" -c gateway -- mcp-gateway-admin "${@:2}" --socket /run/mcp-gateway/control.sock; }
other_pod=$(for r in $gws; do [ "$r" != "$owner" ] && echo "$r"; done | head -n1)
listed=$(admin "$other_pod" instances --json) || fail "instances at $other_pod: $listed"
id=$(jq -r --arg o "$owner" '[.[].instances[] | select(.replica == $o and (.sub | endswith("agents:custos")))][0].id // ""' <<<"$listed")
[[ "$id" == "$owner~"* ]] || fail "custos's instance not listed at $other_pod as $owner's: $listed"
pass "$other_pod lists custos's instance on $owner: $id"
out=$(admin "$other_pod" instances stop "$id" --yes) || fail "stopping $id through $other_pod: $out"
no_custos_pod() { [ -z "$(custos_pod)" ]; }
until_ok 60 no_custos_pod || fail "custos's instance pod still there after the stop: $(custos_pod)"
got=$(PORT=${ports[0]} call_as "$token" stdio echo '{"text":"after the stop"}')
[[ "$got" == "echo: after the stop (call 1)" ]] || fail "custos's call after the stop: $got"
[ "$(replica_of "$(custos_pod)")" = "$owner" ] || fail "custos's new instance is not $owner's"
pass "stopped through $other_pod at $owner: custos's next call has a new instance there"

# The replica that serves custos goes: its instance pod is reaped, and
# the next call, through another replica, is served by the one that
# takes custos over, with a new instance.
k -n "$NS" delete pod "$owner" --wait=false >/dev/null
reaped() { [ -z "$(for pod in $(pods); do [ "$(replica_of "$pod")" = "$owner" ] && echo "$pod"; done)" ]; }
until_ok 120 reaped || fail "the instance pods of $owner are still there: $(pods | tr '\n' ' ')"
other_port=
i=0
for r in $gws; do
	[ "$r" != "$owner" ] && other_port=${ports[$i]}
	i=$((i + 1))
done
taken_over() { [[ "$(PORT=$other_port call_as "$token" stdio echo '{"text":"again"}')" == "echo: again (call 1)" ]]; }
until_ok 60 taken_over || fail "custos not served again after $owner went: $(PORT=$other_port call_as "$token" stdio echo '{"text":"again"}')"
[ "$(replica_of "$(custos_pod)")" != "$owner" ] || fail "custos's new instance names $owner"
pass "$owner went: its instance pods were reaped, and another replica serves custos with a new instance"
for p in "${pfs[@]}"; do kill "$p" 2>/dev/null || true; done
pfs=()
# The Service's port-forward may have gone with the pod.
forward

echo "--- a rolling update under calls"
# A caller in the cluster (echo -call, as agents/custos, with a projected
# token for the gateway's audience) calls the stdio server through the
# Service over and over, each call in a session of its own, while the
# Deployment rolls (RollingUpdate: a new pod before an old one drains):
# no call fails.
k -n agents create configmap mcp-gateway-ca --from-file=ca.crt="$work/tls.crt" --dry-run=client -o yaml | apply
apply <<EOF2
apiVersion: v1
kind: Pod
metadata: {name: caller, namespace: agents}
spec:
  serviceAccountName: custos
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 1
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: caller
      image: mcp-echo:test
      args: [-call, "https://mcp-gateway.$NS.svc/mcp/stdio"]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: token, mountPath: /var/run/secrets/tokens, readOnly: true}
        - {name: ca, mountPath: /etc/mcp-gateway-ca, readOnly: true}
  volumes:
    - name: token
      projected:
        sources: [{serviceAccountToken: {audience: mcp-gateway, expirationSeconds: 3600, path: token}}]
    - name: ca
      configMap: {name: mcp-gateway-ca}
EOF2
k -n agents wait pod/caller --for=condition=Ready --timeout=120s >/dev/null
calls() { k -n agents logs caller 2>/dev/null; }
oks() { calls | grep -c '^ok ' || true; }
some_ok() { [ "$(oks)" -ge 5 ]; }
until_ok 60 some_ok || fail "the caller's calls before the update: $(calls | tail -5)"
k -n "$NS" rollout restart deploy/mcp-gateway >/dev/null
k -n "$NS" rollout status deploy/mcp-gateway --timeout=300s >/dev/null
# Until the old replicas are gone too, and some calls after.
# (By name: the chart's pods and the manifests' have different labels.)
old_gone() { [ "$(k -n "$NS" get pods -o name | grep -c '^pod/mcp-gateway-')" = "$REPLICAS" ]; }
until_ok 120 old_gone || fail "old replicas still there: $(k -n "$NS" get pods -o wide)"
n=$(oks)
more_ok() { [ "$(oks)" -ge $((n + 10)) ]; }
until_ok 60 more_ok || fail "the caller's calls after the update: $(calls | tail -5)"
failed=$(calls | grep '^failed ' || true)
total=$(oks)
k -n agents delete pod caller --wait=false >/dev/null
[ -z "$failed" ] || fail "calls failed in the rolling update: $failed"
pass "$total calls through the Service while the $REPLICAS replicas rolled, none failed"
gws=$(replicas | sort)
forward

echo "--- role data changed in the ConfigMap"
k -n "$NS" patch configmap mcp-gateway-rbac --type merge -p '{"data":{"data.yaml":"version: 1\nroles: {}\nbindings: {users: {}, groups: {}}\n"}}' >/dev/null
denied() { [[ "$(call echo bye)" != "echo: "* ]]; }
until_ok 180 denied || fail "still allowed after the role data changed: $(call echo bye)"
pass "role data from the ConfigMap takes effect"

echo "--- the shared store across a restart"
audit_key() { records keys | jq -r '.items[] | select(.metadata.annotations["mcp-gateway.io/name"] == "audit") | .data.record'; }
key=$(audit_key)
clients=$(records clients | jq '.items | length')
before=$(replicas | sort)
k -n "$NS" rollout restart deploy/mcp-gateway >/dev/null
k -n "$NS" rollout status deploy/mcp-gateway --timeout=240s
[ "$(audit_key)" = "$key" ] || fail "another audit key after the restart"
[ "$(records clients | jq '.items | length')" -ge "$clients" ] || fail "client records lost in the restart"
logs=$(k -n "$NS" logs deploy/mcp-gateway -c gateway)
! grep -q "files of state_dir imported" <<<"$logs" || fail "the files imported again after the restart"
pass "a restarted gateway keeps its audit key and the clients seen, and imports nothing again"
# The replicas that stopped gave their Leases up; the new ones hold
# their own.
handed_over() {
	local r
	r=$(replicas | sort)
	[ "$(grep -c . <<<"$r")" = "$REPLICAS" ] && [ -z "$(comm -12 <(echo "$before") <(echo "$r") | grep . || true)" ] || return 1
	for p in $r; do live_pod "$p" || return 1; done
}
until_ok 90 handed_over || fail "replica Leases after the restart: $(replicas | tr '\n' ' ') (before: $(tr '\n' ' ' <<<"$before"))"
pass "the stopped replicas gave their Leases up, the new ones ($(replicas | tr '\n' ' ')) hold their own"

echo "PASS"
