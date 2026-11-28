# 16. Kubernetes

From 2.0 the gateway also runs in a container and in front of the MCP
servers of a Kubernetes cluster, as the same program with the same
policy, approvals and audit records as on a host
([architecture, section 5.12](../architecture.md#512-containers-and-kubernetes-20),
decision D23). This chapter starts with a walkthrough, from an empty
cluster to an agent's first call and an operator's approval, and then
covers the image, the manifests, agents that authenticate with the
cluster's ServiceAccount tokens, servers in the cluster, and
configuration from ConfigMaps. The same containers on
one host, with Podman or Docker, are chapter 17.

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

## Step by step: from an empty cluster to an agent's first call

This walks through a gateway in a cluster with the Helm chart: a server
in the cluster, an agent in a pod that calls it with its ServiceAccount
token, and operators who approve its calls in the console. The sections
after this one explain each part. `test/kind/run.sh` runs the same flow
in CI on every change.

**You need** a cluster whose network plugin enforces NetworkPolicies
(Calico, Cilium; most managed clusters), `kubectl` and `helm`, a
registry for the gateway's image, and a TLS certificate for the name
agents connect to. For people and approvals, add an OpenID Connect
identity provider (chapter 15 sets up Keycloak).

### 1. The image

Push the image to a registry the cluster pulls from (below, "The
image"):

```bash
make image IMAGE=registry.example.com/mcp-gateway:2.0.0 CONTAINER=podman
podman push registry.example.com/mcp-gateway:2.0.0
```

### 2. A server in the cluster

An MCP server that speaks HTTP runs as a Deployment and a Service of
its own, in a namespace for servers. Only the gateway may reach it: the
NetworkPolicy admits the gateway's pods and nothing else, so no agent
can bypass the policy by calling the server directly.

```yaml
# tickets.yaml: kubectl apply -f tickets.yaml
apiVersion: v1
kind: Namespace
metadata: {name: mcp-servers}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: tickets, namespace: mcp-servers}
spec:
  replicas: 1
  selector: {matchLabels: {app: tickets}}
  template:
    metadata: {labels: {app: tickets}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: tickets
          image: registry.example.com/mcp-server-tickets:1.0
          ports: [{name: http, containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: tickets, namespace: mcp-servers}
spec:
  selector: {app: tickets}
  ports: [{name: http, port: 8080, targetPort: http}]
---
# Only the gateway's pods reach the servers.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: only-the-gateway, namespace: mcp-servers}
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: mcp-gateway}}
          podSelector: {matchLabels: {app.kubernetes.io/name: mcp-gateway}}
```

A server that speaks stdio needs no Deployment: the gateway starts each
of its instances as a pod of its own (below, "Stdio servers in pods of
their own").

### 3. The gateway

The values name the image, the server, and the role data that lets the
agent's ServiceAccount use it:

```yaml
# my-values.yaml
image:
  repository: registry.example.com/mcp-gateway
  tag: 2.0.0
config:
  http:
    # The organization's identity provider, for people (step 6).
    issuer: https://login.example.com/realms/mcp
    # The URL agents use: the Ingress's host (step 5), ending in /mcp.
    audience: https://mcp-gateway.example.com/mcp
    scopes: [mcp]
servers:
  tickets:
    name: tickets
    url: http://tickets.mcp-servers.svc:8080/mcp
rbac:
  version: 1
  roles:
    ticket-reader:
      permissions:
        - {server: tickets, tool: 'get_*'}
        - {server: tickets, tool: 'list_*'}
        # Changes need an operator's approval (step 6). A bot cannot
        # open a link: the call waits while operators decide (oob).
        - {server: tickets, tool: 'update_*', require_approval: true, approval_channel: oob}
  bindings:
    users:
      "k8s:system:serviceaccount:agents:triage-bot": [ticket-reader]
    groups: {}
```

```bash
kubectl create namespace mcp-gateway
kubectl -n mcp-gateway create secret tls mcp-gateway-tls --cert tls.crt --key tls.key
helm -n mcp-gateway upgrade --install mcp-gateway deploy/helm/mcp-gateway -f my-values.yaml
kubectl -n mcp-gateway rollout status deploy/mcp-gateway
```

### 4. Check it

The pod is ready once its policy engine answers. The gateway runs its
own checks and logs what fails; ask for them:

```bash
kubectl -n mcp-gateway exec deploy/mcp-gateway -c gateway -- \
    mcp-gateway-admin doctor --config /etc/mcp-gateway/config/gateway.yaml
```

Each failed check says what to change: a server's address that does
not answer (its Service, a NetworkPolicy), an identity provider whose
keys the gateway cannot fetch, a refused configuration.

### 5. An agent in the cluster

The agent's pod asks for a token for the gateway's audience (the
chart's `clusterIssuer.audience`, `mcp-gateway`) and sends it as a
bearer token. Its principal is its ServiceAccount, which the role data
of step 3 binds:

```yaml
# triage-bot.yaml: kubectl apply -f triage-bot.yaml
apiVersion: v1
kind: Namespace
metadata: {name: agents}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: triage-bot, namespace: agents}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: triage-bot, namespace: agents}
spec:
  replicas: 1
  selector: {matchLabels: {app: triage-bot}}
  template:
    metadata: {labels: {app: triage-bot}}
    spec:
      serviceAccountName: triage-bot
      automountServiceAccountToken: false   # the API server's token: not needed
      containers:
        - name: agent
          image: registry.example.com/triage-bot:1.0
          env:
            # The gateway's Service in the cluster; outside, the Ingress.
            - {name: MCP_URL, value: "https://mcp-gateway.mcp-gateway.svc/mcp/tickets"}
            - {name: MCP_TOKEN_FILE, value: /var/run/secrets/mcp/token}
          volumeMounts:
            - {name: mcp-token, mountPath: /var/run/secrets/mcp, readOnly: true}
      volumes:
        - name: mcp-token
          projected:
            sources:
              - serviceAccountToken: {audience: mcp-gateway, expirationSeconds: 3600, path: token}
```

- **The URL**: `/mcp/<server>` for one server, `/mcp` for all the agent
  may use (chapter 5). Inside the cluster the agent reaches the Service
  directly; the certificate must then name
  `mcp-gateway.mcp-gateway.svc` too, or the agent goes through the
  Ingress's name.
- **The token**: the kubelet renews the file before it expires. The
  agent's MCP client sends `Authorization: Bearer <the file's content>`
  and reads the file anew for each request, or at least when the
  gateway answers 401. A client that reads it once fails after an hour.
- **Try it** before the agent exists, with a token of the
  ServiceAccount and the MCP handshake by hand:

  ```bash
  kubectl -n mcp-gateway port-forward svc/mcp-gateway 8443:443 &
  token=$(kubectl -n agents create token triage-bot --audience mcp-gateway --duration 10m)
  curl -s --cacert tls.crt --resolve mcp-gateway.example.com:8443:127.0.0.1 \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"try"}}}' \
      https://mcp-gateway.example.com:8443/mcp/tickets
  ```

  An answer with `serverInfo` means the token was taken. 401 means it
  was not: a token without `--audience mcp-gateway` (the API server's),
  or a cluster issuer the gateway does not know (the doctor says). What
  the agent may then do is the role data's: tools it is not bound to are
  not listed, and their calls are denied with the reason. The audit
  record in the log names the principal and each decision.

**Agents outside the cluster**, and people's agents, connect to the
Ingress with a token of the organization's identity provider
(chapter 5). Expose the gateway's Service with an Ingress that passes
TLS through or re-encrypts to the listener, which serves TLS itself;
the chart's `ingress` values make one:

```yaml
ingress:
  enabled: true
  className: nginx
  host: mcp-gateway.example.com
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
  tls:
    - {hosts: [mcp-gateway.example.com], secretName: mcp-gateway-tls}
```

### 6. Approvals and the console

Calls that need an approval wait until an operator decides. Operators
sign in with the organization's identity provider on the gateway's
approval page and console (chapter 7): register a public client
(OpenID Connect, authorization code with PKCE, the redirect URI
`https://mcp-gateway.example.com/approvals/callback`), name it, and
name the operators in the role data's approver rules:

```yaml
config:
  approvals:
    page:
      client_id: mcp-gateway-console
rbac:
  approvers:
    # The group "ops" of the identity provider's groups claim decides
    # on tickets and may review the policy (the doctor's results).
    tickets: ["remote-group:ops"]
    default: ["remote-group:ops"]
```

- Operators open `https://mcp-gateway.example.com/console/`: the
  gateway's status, servers and instances, sessions, tasks, the doctor,
  and the approvals.
- The agent's waiting call shows on `/approvals/`; approving it lets
  the call run. With webhooks (chapter 7), a chat or ticket system
  hears of it too.
- From a laptop: `mcp-gateway-admin approvals login --gateway
  https://mcp-gateway.example.com`, then `mcp-gateway-admin approvals`.
- A confidential client's secret comes from a Secret that the chart
  mounts (`secrets`, below):

  ```bash
  kubectl -n mcp-gateway create secret generic mcp-gateway-console \
      --from-literal=client-secret='<the identity provider's client secret>'
  ```

  ```yaml
  secrets:
    - name: mcp-gateway-console
  config:
    approvals:
      page:
        client_id: mcp-gateway-console
        client_secret_file: /etc/mcp-gateway/secrets/mcp-gateway-console/client-secret
  ```

### 7. Day to day

- **Changes** go through Git and `helm upgrade`: new servers and role
  data are reloaded in place, and the console and the doctor say
  whether the gateway took them. A change to `config` rolls the pod.
- **Upgrades**: a new `image.tag`, then `helm upgrade`. The one replica
  is replaced (strategy Recreate: the state's volume is read-write
  once), so agents reconnect after a short gap. Grants, sign-ins and
  pending approvals are on the volume and stay: an approval decided
  while its agent was away lets the agent's next identical call through
  (chapter 7, "Pending approvals across disconnects and restarts").
- **Backups**: the state volume, `mcp-gateway-state`, with your
  cluster's volume snapshots (a CSI `VolumeSnapshot`). The image has no
  `tar`, so `kubectl cp` does not work on it. The rest is in Git.
- **Logs and audit**: `kubectl -n mcp-gateway logs deploy/mcp-gateway
  -c gateway` (decisions, approvals, the doctor's failures), `-c opa`
  (OPA's decision log).
- **Monitoring**: the probes and `/metrics` on port 9464; with the
  Prometheus Operator, `serviceMonitor.enabled: true`.

### When something does not work

| You see | Look at |
|---|---|
| The pod is not ready | `kubectl -n mcp-gateway logs deploy/mcp-gateway -c opa`: OPA must start and load the policy; `-c gateway` for a configuration the gateway refuses |
| 401 for an agent | the token's audience (`mcp-gateway` for ServiceAccounts, `http.audience` for the identity provider's) and issuer; the doctor's identity provider checks |
| A tool the agent does not see, or a call denied | the role data's binding of the principal (`k8s:system:serviceaccount:<namespace>:<name>`); the audit record names the decision and its reason |
| A server's calls fail | the doctor's check of the server: its Service's name and port, the servers' NetworkPolicy (it must admit the gateway's pods) |
| A stdio server's instance does not start | `kubectl -n mcp-instances get pods`, `describe pod`: an image that does not pull, the namespace's Pod Security; the definition's limits |
| A change does not take | the console's Gateway page or the doctor's configuration check: the gateway refused it and says why; keys that need a restart roll with `helm upgrade` |
| Approvals do not reach anyone | `approvals.page.client_id`, the redirect URI at the identity provider, and the approver rules (`remote-group:`, `remote-user:`); the doctor's approval page check |

## The image

`make image` builds it from the same sources as the RPMs on SUSE's Base
Container Image of SLES 16 (`registry.suse.com/bci/bci-micro:16.0`): the gateway,
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

**Secrets** for the files `gateway.yaml` and the server definitions
name come from `secrets`: each Secret is mounted read-only into the
gateway's container, readable by its account only (mode 0440, group
10001), at `/etc/mcp-gateway/secrets/<name>/<key>` or at `mountPath`:

```yaml
secrets:
  # approvals.page.client_secret_file, approvals.webhooks[].secret_file,
  # notifications.email.password_file: /etc/mcp-gateway/secrets/mcp-gateway-approvals/<key>
  - name: mcp-gateway-approvals
  # The servers' credentials (credentials: [name] in a definition).
  - name: mcp-gateway-credentials
    mountPath: /etc/mcp-gateway/credentials
```

The gateway reads most of them at start: after changing a Secret,
`kubectl -n mcp-gateway rollout restart deployment/mcp-gateway`.

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

## The state in the Kubernetes API

By default the gateway keeps its state (grants, pending approvals,
notices, reviews, sign-in tokens, the clients seen, the audit key) on
the volume `mcp-gateway-state`, as on a host. With the shared store it
keeps it as Secrets of its own namespace instead, one per record, which
the cluster backs up with the rest of its objects; several replicas
(roadmap step 49) will need it, and one replica can use it already:

```yaml
# my-values.yaml (Helm): a Role for the Secrets, and replication in
# gateway.yaml
replication:
  enabled: true
```

With the manifests, add the component that holds the Role, and the key
to `gateway.yaml` in the `mcp-gateway-config` ConfigMap:

```yaml
# kustomization.yaml of your overlay
resources:
  - ../../deploy/kubernetes
components:
  - ../../deploy/kubernetes/replication
```

```yaml
# gateway.yaml
replication:
  store: kubernetes
  namespace: mcp-gateway
```

At its first start with the store the gateway copies the files of the
volume into it (once: a record `imported` says so), so that it keeps
its grants, approvals, sign-ins and audit key; keep the volume for that
start. Its records are Secrets labelled
`app.kubernetes.io/managed-by=mcp-gateway`, one collection each
(`mcp-gateway.io/collection`: `grants`, `pending`, `notices`, `reviews`,
`tokens`, `clients`, `keys`), and each replica holds a Lease
`mcp-gateway-replica-<pod>` (`mcp-gateway.io/role=replica`), which it
gives up when it stops; the sign-in tokens in them are encrypted
under the `tokens` key, as on the volume. Who may read Secrets in the
gateway's namespace may read the records, approvals' arguments among
them: grant that to no one else, and where the API server encrypts
Secrets at rest (an `EncryptionConfiguration`), they are encrypted in
etcd too. The doctor checks that the gateway reaches them
(`shared-store`). Chapter 3, "Shared store", has the settings.

## Several replicas

On the shared store the gateway can run as several replicas (roadmap
step 49; the console across them, draining and a rolling update come
with stage C). Each principal is served by one replica, which starts
its instances and holds its sessions and tasks; a request that reaches
another replica is forwarded there, over a listener of the replicas'
own with a certificate they all share. Make that certificate once, from
a CA of its own, for the name `mcp-gateway-peer`, for server and client
use:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj /CN=mcp-gateway-peers -keyout peer-ca.key -out peer-ca.crt
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=mcp-gateway-peer -keyout peer.key -out peer.csr
printf 'subjectAltName=DNS:mcp-gateway-peer\nextendedKeyUsage=serverAuth,clientAuth\n' >peer.ext
openssl x509 -req -in peer.csr -CA peer-ca.crt -CAkey peer-ca.key -CAcreateserial -days 365 \
  -extfile peer.ext -out peer.crt
kubectl -n mcp-gateway create secret generic mcp-gateway-peer \
  --from-file=tls.crt=peer.crt --from-file=tls.key=peer.key --from-file=ca.crt=peer-ca.crt
```

```yaml
# my-values.yaml (Helm)
replication:
  enabled: true
  replicas: 3
  peerSecret: mcp-gateway-peer
persistence:
  enabled: false      # the store keeps the state
```

With the manifests, as `test/kind` does: the replication component,
`replicas: 3`, the state volume an `emptyDir`, the Secret mounted at
`/etc/mcp-gateway/peer` and the port `8444` on the gateway's container
(`test/kind/replicas.yaml`), and in `gateway.yaml`:

```yaml
replication:
  store: kubernetes
  namespace: mcp-gateway
  listen: ":8444"
  peer_cert_file: /etc/mcp-gateway/peer/tls.crt
  peer_key_file: /etc/mcp-gateway/peer/tls.key
  peer_ca_file: /etc/mcp-gateway/peer/ca.crt
```

A replica that goes, deleted or lost with its node, gives up its
principals (at once when it stops, else when its Lease runs out): the
next request of each is served by another replica, with new instances;
what lived in its memory (sessions, running tasks, contexts) ends as
in a restart, and its instance pods are deleted. Its pending approvals
are taken over by another replica, and an approval can be decided on
any replica. A sign-in on the approval page or the console is kept by
the replica it was made on, and its cookies name that replica: a
browser's requests reach it whichever replica the Service picks (a
replica that went takes its sign-ins along: sign in again). Each replica's audit records carry `replica`, its name;
the console's status names the replica that serves the page and the
live ones. The console and the control API list every replica's
instances, tasks and clients, each naming its replica, and stop, cancel
or end one on the replica that holds it; the Doctor page and
`doctor --gateway` show every replica's checks (each runs its own). The replicas reach each other on their pod addresses: a
NetworkPolicy in the gateway's namespace must let them reach port
`8444`.

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
  With the shared store it is in the Secrets of the gateway's namespace
  (above), backed up with the cluster's objects.

`test/kind/run.sh` deploys all of this to a kind cluster and checks it,
with the manifests and with the chart (`DEPLOY=helm`), a stdio server in
pods of their own among it (one per principal, no egress to other pods,
gone after the idle timeout), on the shared store (its records, kept
across a restart), with three replicas (one principal's calls through
each reaching one instance; the replica that served it deleted, its
instance pods reaped, another serving it); CI runs both on every
change.
