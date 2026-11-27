# 17. Containers on one host: Podman and Docker

The gateway's image (chapter 16) also runs without a cluster. With
Podman it runs on a single host as the same pod: the gateway, OPA and
the role data renderer, configured from a directory of the host. This
suits a host that should not carry the gateway's packages, such as
SLE Micro, a transactional system, or a host that runs everything in
containers. It also suits trying out the cluster's layout on one
machine.

This chapter sets the pod up step by step, runs it as a systemd service
with Quadlet, and covers changes, upgrades and backups. The files are in
`deploy/podman`.

## Host packages, Podman or Kubernetes

| | Host packages (chapter 2) | Podman (this chapter) | Kubernetes (chapter 16) |
|---|---|---|---|
| Agents | local (Unix socket) and remote (HTTPS) | remote only (HTTPS, bearer tokens) | remote only |
| Servers | stdio and HTTP servers on the host, each instance in a systemd unit with SELinux and Landlock | servers that speak HTTP | servers that speak HTTP; stdio servers in pods of their own |
| Approvers | Cockpit, the command line, the approval page, webhooks, mail | the approval page and the console, `--gateway` on the command line, webhooks, mail | as with Podman |
| Configuration | `/etc/mcp-gateway` | a directory of the host, reloaded as on a host | ConfigMaps |
| Logs and audit | journal and kernel audit | the containers' output (the journal with Quadlet) | the cluster's log pipeline |

The gateway runs in container mode (`deployment: container`) as in a
cluster. Chapter 3, [Deployment](03-configuration.md#deployment), lists
what container mode refuses.

## What you need

- Podman 4.9 or newer (`zypper install podman`); `podman kube play`
  runs the pod.
- The gateway's image: from your registry, or built with
  `make image` (chapter 16, "The image"; `packaging/container`). For a
  SLES 16 host, build on SLE 16's base:

  ```bash
  make image IMAGE=registry.example.com/mcp-gateway:2.0.0 \
      IMAGE_BASE=registry.suse.com/bci/bci-micro:16.0 CONTAINER=podman
  ```

- An identity provider for agents and people (chapter 5, "Remote
  agents"; chapter 15 runs Keycloak with Podman too).
- A TLS certificate for the name agents connect to.

## Step 1: the configuration directory

The pod mounts `/etc/mcp-gateway-pod`, read-only:

| Path | Holds |
|---|---|
| `gateway.yaml` | the configuration |
| `servers.d/` | the server definitions, one file each (chapter 4) |
| `rbac/` | the role data, `data.yaml` (chapter 6); empty: the shipped default |
| `tls/tls.crt`, `tls/tls.key` | the listener's certificate and key |

```bash
mkdir -p /etc/mcp-gateway-pod/{servers.d,rbac,tls}
cp deploy/podman/gateway.yaml /etc/mcp-gateway-pod/
cp mcp-gateway.example.com.crt /etc/mcp-gateway-pod/tls/tls.crt
cp mcp-gateway.example.com.key /etc/mcp-gateway-pod/tls/tls.key
# The gateway runs as uid and gid 10001: let it read the key.
chgrp 10001 /etc/mcp-gateway-pod/tls/tls.key
chmod 0640 /etc/mcp-gateway-pod/tls/tls.key
```

In `gateway.yaml`, set the identity provider (`http.issuer`, or
`http.issuers` for several) and the audience: the URL agents connect
to, whose host the certificate names. The pod fixes the rest (the
directories, the sockets, the listener's address and certificate).

```yaml
http:
  listen: ":8443"
  cert_file: /etc/mcp-gateway/tls/tls.crt
  key_file: /etc/mcp-gateway/tls/tls.key
  issuer: https://login.example.com/realms/mcp
  audience: https://mcp-gateway.example.com:8443/mcp
  scopes: [mcp]
```

On a host with SELinux enforcing (SLES 16, Leap 16, SLE Micro), let
containers read the directory:

```bash
semanage fcontext -a -t container_file_t '/etc/mcp-gateway-pod(/.*)?'
restorecon -R /etc/mcp-gateway-pod
```

## Step 2: start the pod

`deploy/podman/mcp-gateway.yaml` is the pod. Set its image to yours:
the `image` lines of the gateway, the init container and the role data
renderer name the same image. Then start it:

```bash
cp deploy/podman/mcp-gateway.yaml /etc/containers/systemd/mcp-gateway.yaml
sed -i 's|registry.example.com/mcp-gateway:2.0.0|registry.mycorp.example/mcp-gateway:2.0.0|' \
    /etc/containers/systemd/mcp-gateway.yaml     # your image
podman kube play --replace /etc/containers/systemd/mcp-gateway.yaml
```

The pod publishes the HTTPS listener on port 8443 of the host, and the
metrics and probes on port 9464 of the host's loopback only. Its state
(grants, the audit key, sign-in tokens, clients) is in the volume
`mcp-gateway-state`, which Podman creates owned by the gateway's
account. The pod's other volumes go when the pod does.

Check it:

```console
# curl -s 127.0.0.1:9464/readyz
ready
# podman exec mcp-gateway-gateway mcp-gateway-admin doctor --config /etc/mcp-gateway/config/gateway.yaml
OK    configuration: gateway.yaml and the server definitions are in force
OK    policy: OPA decides (deny for an unknown principal)
OK    TLS: certificate for mcp-gateway.example.com, valid until 2027-02-24
OK    identity provider https://login.example.com/realms/mcp: key set with 2 keys
OK    state volume: /var/lib/mcp-gateway is writable
```

The gateway runs these checks itself at the start and after every
change, and logs what fails (chapter 16, "Operating"). Open the
firewall for the listener if agents come from other hosts:
`firewall-cmd --permanent --add-port=8443/tcp && firewall-cmd --reload`.

## Step 3: a systemd service with Quadlet

Quadlet turns a `.kube` file into a systemd service that runs the pod:

```bash
cp deploy/podman/mcp-gateway.kube /etc/containers/systemd/
podman kube down /etc/containers/systemd/mcp-gateway.yaml   # if started by hand
systemctl daemon-reload
systemctl start mcp-gateway.service
systemctl status mcp-gateway.service
```

The unit starts at boot (`WantedBy=multi-user.target`) and restarts the
pod when it fails. Its log is the containers' output:
`journalctl -u mcp-gateway.service`. Stopping the service removes the
pod (`podman kube down`) and keeps the state volume.
`/usr/libexec/podman/quadlet -dryrun` shows the service Quadlet makes.

## Step 4: servers, roles and agents

- **Servers**: a file per server in `/etc/mcp-gateway-pod/servers.d`,
  with `url` (chapter 4). The gateway reloads the directory when it
  changes. In container mode a server is reached over HTTPS; plain
  `http://` is allowed only to a cluster's Service names (`.svc`), and
  stdio servers are refused. `mcp-gateway-admin doctor` (through
  `podman exec`, above) checks that each server's address answers.
- **Roles**: `data.yaml` in `/etc/mcp-gateway-pod/rbac`, as on a host
  (chapter 6). The renderer beside the gateway renders it for OPA when
  it changes.
- **Agents** connect to the audience URL with a token of the identity
  provider (chapter 5). Local agents of the host do so too: the pod has
  no Unix socket for `mcp-connect`.
- **Approvals and the console**: set up the approval page (chapter 7,
  `approvals.page`). It is served at `https://<host>:8443/approvals/`,
  the console at `/console/`, and the command line reaches it with
  `--gateway https://<host>:8443`.

## Changes, upgrades and backups

- **Configuration**: edit the files in `/etc/mcp-gateway-pod`. The
  gateway reloads `gateway.yaml`, the server definitions, the role data
  and the certificate as on a host, and the console's Gateway page and
  the doctor say whether it took them. Keys that need a restart
  (`restart_needed`, chapter 3) take effect with
  `systemctl restart mcp-gateway.service`.
- **Upgrades**: change the image in `mcp-gateway.yaml` to the new
  version and restart the service (or `podman kube play --replace`).
  The state volume stays. Gateway and policy come from the same image
  (the init container copies the policy), so they are always of one
  version.
- **Backups**: the state is the volume:
  `podman volume export mcp-gateway-state > mcp-gateway-state.tar`
  (`podman volume import` restores it into a new volume). With the
  configuration directory, that is everything.
- **The command line in the pod**, as the gateway's account:
  `podman exec mcp-gateway-gateway mcp-gateway-admin clients`. It sees
  what the approver rules let `10001` see; the doctor's results it
  always sees.

## Rootless

The pod also runs as an unprivileged user, with the files in that user's
home and the unit in `~/.config/containers/systemd`:

- Point the pod's `hostPath` volumes at the user's directory, and use
  host ports above 1023 if the default 8443 is taken.
- Let the gateway's account in the user's namespace read the key:
  `podman unshare chgrp 10001 ~/mcp-gateway-pod/tls/tls.key` and
  `podman unshare chmod 0640 ~/mcp-gateway-pod/tls/tls.key`.
- `systemctl --user daemon-reload && systemctl --user start mcp-gateway`,
  and `loginctl enable-linger <user>` so that it runs without a login.

Rootless networking (`pasta` or `slirp4netns`) needs `/dev/net/tun`.

## Docker

`deploy/docker/compose.yaml` runs the same containers with Docker
Compose, from the same configuration directory (step 1):

```bash
cd deploy/docker
MCP_GATEWAY_IMAGE=registry.mycorp.example/mcp-gateway:2.0.0 docker compose up -d
curl -s 127.0.0.1:9464/readyz
docker compose exec gateway mcp-gateway-admin doctor --config /etc/mcp-gateway/config/gateway.yaml
```

Docker creates named volumes owned by root. A first service
(`volumes`) hands them to the gateway's account, uid 10001, and exits.
Another (`policy`) copies the policy from the gateway's image, as the
pod's init container does. Shared volumes join the rest: OPA's socket
(`run`) and the rendered role data (`rendered`). `docker compose down`
keeps the state volume; `down -v` removes it.
