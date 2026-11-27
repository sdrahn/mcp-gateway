# 16. Kubernetes

From 2.0 the gateway also runs in a container and in front of the MCP
servers of a Kubernetes cluster, as the same program with the same
policy, approvals and audit records as on a host
([architecture, section 5.12](../architecture.md#512-containers-and-kubernetes-20),
decision D23). This chapter covers the image, the manifests, agents
that authenticate with the cluster's ServiceAccount tokens, servers in
the cluster, and configuration from ConfigMaps.

*Status: container mode serves servers that speak HTTP, and with the
Kubernetes launcher servers that speak stdio, each instance in a pod of
its own (roadmap step 47); the manifests and the chart set the launcher
up. The console, the management page for operators (chapter 7, "The
console"), and the doctor's checks in the gateway (Operating, below)
complete it (roadmap step 48).*

## What is different from a host

| | On a host | In a cluster |
|---|---|---|
| Setting | `deployment: host` (the default) | `deployment: container` |
| Agents | local (Unix socket) and remote (HTTPS) | remote only: HTTPS with a bearer token |
| Servers | stdio servers in systemd units, servers that speak HTTP | servers that speak HTTP, as Deployments and Services of their own |
| Instances | systemd transient units, SELinux, Landlock | the connector as a child process of the gateway |
| Policy engine | `mcp-opa.service` | OPA in the gateway's pod |
| Configuration | files in `/etc/mcp-gateway` | ConfigMaps and Secrets |
| Audit | journal and kernel audit | the standard error, collected by the cluster's log pipeline |
| Approvers | Cockpit, the command line, the approval page, webhooks, mail | the approval page, `mcp-gateway-admin approvals --gateway`, webhooks, mail |

Chapter 3, [Deployment](03-configuration.md#deployment), lists what
container mode refuses, with the reason.

## The image

`make image` builds it from the same sources as the RPMs on SUSE's Base
Container Image (`registry.suse.com/bci/bci-micro`): the gateway,
`mcp-gateway-admin`, the connector, the sign-in helper,
`mcp-policy-render` and the policy.

```bash
make image IMAGE=registry.example.com/mcp-gateway:2.0.0
podman push registry.example.com/mcp-gateway:2.0.0     # or docker
# Another base, or podman:
make image IMAGE_BASE=registry.opensuse.org/opensuse/bci/bci-micro:latest CONTAINER=podman
```

It runs as uid and gid 10001, never as root, and needs no capability
and no writable root file system. OPA comes from its own image
(`openpolicyagent/opa`, the `-static` variant).

## Deploying with Helm

`deploy/helm/mcp-gateway` is a chart of the same pod. The values hold
`gateway.yaml` (`config`, without what the pod's layout fixes: the
directories, sockets, the listener's address and certificate),
the server definitions (`servers`), the role data (`rbac`), the cluster's
issuer (`clusterIssuer`, on by default), the image, persistence, an
optional Ingress and the resources:

```yaml
# my-values.yaml
image:
  repository: registry.example.com/mcp-gateway
  tag: 2.0.0
config:
  http:
    issuer: https://idp.example.com/realms/mcp
    audience: https://mcp-gateway.example.com/mcp
    scopes: [mcp]
servers:
  tickets:
    name: tickets
    url: http://tickets.mcp-servers.svc:8080/mcp
rbac:
  version: 1
  roles:
    operator:
      permissions:
        - {server: tickets, tool: '*'}
  bindings:
    users:
      "k8s:system:serviceaccount:agents:custos": [operator]
    groups: {}
```

```bash
kubectl create namespace mcp-gateway
kubectl -n mcp-gateway create secret tls mcp-gateway-tls --cert tls.crt --key tls.key
helm -n mcp-gateway upgrade --install mcp-gateway deploy/helm/mcp-gateway -f my-values.yaml
```

`helm upgrade` with changed `servers` or `rbac` updates their
ConfigMaps, which the gateway reloads in place; a changed `config`
rolls the pod (a checksum of `gateway.yaml` in the pod template), as
some of its keys need a restart. The state's volume is kept when the
release is uninstalled.

## Deploying with kubectl

`deploy/kubernetes` holds plain manifests for `kubectl apply -k`: one
Deployment of one replica (sessions, pending approvals and tasks live in
its memory), a Service for the HTTPS listener, a volume for the state,
and three ConfigMaps. The pod has three containers that share two
in-memory volumes, as the three services do on a host: the gateway, OPA,
and `mcp-policy-render`, which renders the role data for OPA. An init
container copies the policy from the gateway's image, so gateway and
policy are always of one version.

```bash
kubectl create namespace mcp-gateway
# The listener's certificate, for the name agents and browsers use.
kubectl -n mcp-gateway create secret tls mcp-gateway-tls --cert tls.crt --key tls.key
# Your image, identity provider and audience: edit
# deploy/kubernetes/kustomization.yaml (images) and configmap.yaml, or
# better an overlay of your own that patches them.
kubectl apply -k deploy/kubernetes
kubectl -n mcp-gateway rollout status deploy/mcp-gateway
```

Expose the Service `mcp-gateway` (port 443) with an Ingress, a Route or
a Gateway API route that passes TLS through or re-encrypts to the
listener. `http.audience` is the URL agents use, ending in `/mcp`.

## Agents in the cluster: ServiceAccount tokens

An agent in a pod authenticates with a projected ServiceAccount token
for the gateway's audience; the gateway checks it against the cluster's
issuer, configured in `http.issuers` (chapter 3, [Remote
access](03-configuration.md#remote-access-https)) next to the
organization's identity provider:

```yaml
http:
  issuer: https://idp.example.com/realms/mcp       # people
  audience: https://mcp-gateway.example.com/mcp
  scopes: [mcp]
  issuers:
    - issuer: https://kubernetes.default.svc.cluster.local   # agents in the cluster
      audience: mcp-gateway
      ca_file: /etc/mcp-gateway/cluster-ca/ca.crt
      jwks_url: https://kubernetes.default.svc.cluster.local/openid/v1/jwks
      token_file: /var/run/secrets/mcp-gateway/token/token
      scopes: []
      subject_prefix: "k8s:"
```

- The issuer is the cluster's `--service-account-issuer`
  (`kubectl get --raw /.well-known/openid-configuration | jq -r .issuer`).
- `ca_file` is the cluster's CA, which signed the API server's
  certificate; the manifests mount the `kube-root-ca.crt` ConfigMap,
  which every namespace has, there.
- The API server gives its key set to ServiceAccounts only (the
  cluster's default binding `system:service-account-issuer-discovery`).
  The gateway's pod has a token of its own for that, a projected volume
  for the API server renewed by the kubelet (`token_file`); the default
  token mount stays off. The token goes to the issuer's own address
  only, so `jwks_url` names the key set there: the discovery document
  names the node's address instead.

- The agent's pod asks for a token with the audience:

  ```yaml
  # in the agent's pod spec
  volumes:
    - name: mcp-token
      projected:
        sources:
          - serviceAccountToken: {audience: mcp-gateway, expirationSeconds: 3600, path: token}
  ```

  and sends `Authorization: Bearer <the file's content>`, read anew for
  each request (the kubelet renews it). The principal is
  `k8s:system:serviceaccount:<namespace>:<name>`; bind roles to that
  name in the role data:

  ```yaml
  bindings:
    users:
      "k8s:system:serviceaccount:agents:custos": [operator]
  ```

People sign in with the organization's identity provider
(`http.issuer`) on the approval page and with `mcp-gateway-admin
--gateway`, as with a host gateway.

## Servers in the cluster

A server runs as a Deployment and a Service of its own and is defined
with its Service's URL:

```yaml
# a file in the mcp-gateway-servers ConfigMap
name: tickets
url: http://tickets.mcp-servers.svc:8080/mcp
```

Plain `http://` is allowed in container mode to a cluster's Service
names, `name.namespace.svc` and `name.namespace.svc.cluster.local`: the
traffic stays on the cluster's network, which NetworkPolicy or a mesh
protects. Every other host needs `https://`; a server whose certificate
a private CA signed names that CA with `ca_file`. Let only the gateway's
pods reach the servers (a NetworkPolicy on the servers' namespace that
admits `app.kubernetes.io/name: mcp-gateway`), so that policy cannot be
bypassed.

## Stdio servers in pods of their own

With `supervisor.mode: kubernetes` (chapter 3) an instance of a server
that speaks stdio is a pod of its own, in a namespace for instances,
created when the instance starts and deleted when it stops, as a unit is
on a host. The server's definition names its image:

```yaml
# a file in the mcp-gateway-servers ConfigMap
name: git
command: [/usr/bin/mcp-server-git, --stdio]
image: registry.example.com/mcp-server-git:1.4
resources:
  limits: {memory: 256Mi, cpu: "1"}
node_selector: {kubernetes.io/arch: amd64}
```

- **The server needs no change:** an init container copies
  `mcp-stdio-bridge` from the gateway's image into the pod, which starts
  the server with the definition's command line and carries its stdin
  and stdout to the gateway over one connection, authenticated with a
  token of the instance's. The image needs nothing of the gateway's.
- **The sandbox, translated:** the pod runs as a uid of its own, never
  root, without privilege escalation, capabilities, a ServiceAccount
  token or other Services' addresses, on a read-only root with an
  empty `/tmp`, under the runtime's default seccomp profile, within a
  memory limit and eight hours; with `supervisor.kubernetes.selinux: on`
  with an MCS level of its own. Its NetworkPolicy lets only the
  gateway's pods reach it, and lets it reach nothing unless the
  definition says `network: true`. Your cluster's network plugin must
  enforce NetworkPolicies. Whether a policy also covers addresses on the
  nodes' host network, the API server's among them, depends on the
  plugin (Calico and Cilium apply it there; kind's kindnet does not); an
  instance has no ServiceAccount token for the API server in any case.
- **Credentials** (`credentials`) are read by the gateway and become the
  instance's Secret, mounted at `$CREDENTIALS_DIRECTORY`; the Secret and
  the NetworkPolicy belong to the pod and go with it.
- **Refused, with the reason** (`mcp-gateway --check`): what a pod
  cannot give, `privileged`, `run_as` other than the default,
  `network_view`, `landlock`, `requires`, `sandbox.*` (also
  `sandbox.capabilities`: Kubernetes gives a container that does not run
  as root no ambient capabilities), and `selinux_type` unless
  `allow_selinux_type`.
- **Lifecycle:** idle timeouts, limits per principal and restarts are
  the gateway's, as on a host. An instance whose pod does not run within
  `start_timeout` fails; one whose image does not pull fails at once,
  with the reason. At start, the gateway deletes the pods an earlier run
  left.

The manifests and the chart set this up: the namespace `mcp-instances`,
held to the restricted Pod Security Standard (the chart's
`kubernetesLauncher.createNamespace`), and `supervisor.mode: kubernetes`
in `gateway.yaml`, with the gateway's image as `bridge_image` (with
`kubectl apply -k`, keep it the image `kustomization.yaml` names; the
chart takes it from `image`). `kubernetesLauncher.enabled: false` in the
chart's values turns the launcher off: stdio servers are refused then,
servers that speak HTTP are served. The gateway's ServiceAccount gets
these rights in the instances' namespace, and nothing else
(`deploy/kubernetes/rbac.yaml`, the chart's `launcher.yaml`):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: mcp-gateway-instances, namespace: mcp-instances}
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [create, get, list, delete, deletecollection]
  - apiGroups: [""]
    resources: [secrets]
    verbs: [create, delete]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies]
    verbs: [create, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: mcp-gateway-instances, namespace: mcp-instances}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: mcp-gateway-instances}
subjects:
  - {kind: ServiceAccount, name: mcp-gateway, namespace: mcp-gateway}
```

## Configuration from ConfigMaps

| ConfigMap | Mounted at | Holds |
|---|---|---|
| `mcp-gateway-config` | `/etc/mcp-gateway/config` | `gateway.yaml` |
| `mcp-gateway-servers` | `/etc/mcp-gateway/servers.d` | one file per server |
| `mcp-gateway-rbac` | `/etc/mcp-gateway/policy/rbac` | `data.yaml`, the role data; empty: the shipped default |

Keep them in Git and apply them with the rest. When the kubelet updates
the mounted files (within a minute or so), the gateway reloads the
server definitions and `gateway.yaml`, and `mcp-policy-render` the role
data, as on a host; a change that does not pass the checks is refused
and the last good one stays in force (`kubectl logs deploy/mcp-gateway
-c gateway`). Keys that need a restart take effect with
`kubectl -n mcp-gateway rollout restart deployment/mcp-gateway`.

## Operating

- Probes: the pod is ready while `GET /readyz` on the metrics port
  (`9464`) answers, which needs the policy engine; alive while
  `GET /healthz` does. The Service's `metrics` port serves `/metrics`
  for Prometheus; the chart adds a ServiceMonitor with
  `serviceMonitor.enabled: true`.

- The doctor: in a container the gateway runs its own checks at the
  start, after each reload and on request, and logs what fails or
  warns: the configuration (a refused change, keys waiting for a
  restart), the policy engine, the listener's certificate, each
  identity provider's key set (as the listener fetches it, with its
  `ca_file` and `token_file`), the approval page's client, the webhooks
  (on request only: their check posts a ping to the receiver), a connection to each server's URL (or its proxy), the state
  volume, and with the Kubernetes launcher the API server's list of the
  instances' pods. The console's Doctor page shows them, as do
  `mcp-gateway-admin doctor --gateway https://mcp-gateway.example.com`
  and `kubectl -n mcp-gateway exec deploy/mcp-gateway -c gateway --
  mcp-gateway-admin doctor --config /etc/mcp-gateway/config/gateway.yaml`
  (as the gateway's own account), for operators the approver rules let
  review the policy (`review_policy`: the `default` rules other than
  `self`).
- Logs and audit records: `kubectl -n mcp-gateway logs deploy/mcp-gateway -c gateway`
  (OPA's decision log: `-c opa`).
- Approvals from another host: `mcp-gateway-admin approvals login
  --gateway https://mcp-gateway.example.com` (chapter 7).
- The console: with the approval page set up, the gateway's management
  page at `https://<listener>/console/`, for operators signed in there
  (chapter 7, "The console"): status and reload errors, servers and
  instances, sessions, tasks, sign-ins, the policy and its what-if, and
  the approvals.
- The console's API: with the approval page set up, the control API on
  the listener below `/console/api/v1/`, for operators signed in there,
  as the approver rules allow them (`remote-user:`, `remote-group:`;
  chapter 7, "The console's API"). Unlike `kubectl exec`, it acts as the
  operator, not as the gateway's account.
- The command line in the pod, as the gateway's account (uid 10001,
  which has no name in the image: the control API takes it as `10001`):
  `kubectl -n mcp-gateway exec deploy/mcp-gateway -c gateway --
  mcp-gateway-admin clients` (the sessions and agents the approver
  rules let it see: `user:10001` names it; the doctor's results it
  always sees).
- State (grants, the audit key, sign-in tokens) is on the volume
  `mcp-gateway-state`; back it up as you would `/var/lib/mcp-gateway`.

`test/kind/run.sh` deploys all of this to a kind cluster and checks it,
with the manifests and with the chart (`DEPLOY=helm`), a stdio server in
pods of their own among it (one per principal, no egress to other pods,
gone after the idle timeout); CI runs both on every change.
