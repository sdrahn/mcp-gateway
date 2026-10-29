# 15. Keycloak for one or more gateways

One Keycloak realm can serve several gateways: the users, their groups
and the clients are kept once, and each gateway validates tokens on its
own, without talking to the others. This chapter runs Keycloak in a
container, sets up the realm for remote agents (chapter 5), the
approval page and the command line on other hosts (chapter 7), and
connects each gateway. A single gateway is the same with one of
everything.

```
                    ┌────────────────────────────┐
                    │          Keycloak          │
                    │ https://idp.example.com    │
                    │        realm: mcp          │
                    └──┬───────────┬──────────┬──┘
          tokens for A │           │ for B    │ for C
                       ▼           ▼          ▼
            ┌────────────────┐ ┌──────────────┐ ┌──────────────┐
            │   Gateway A    │ │  Gateway B   │ │  Gateway C   │
            │ gw-a…:8443/mcp │ │ gw-b…/mcp    │ │ gw-c…/mcp    │
            └────────────────┘ └──────────────┘ └──────────────┘
```

What matters for several gateways:

- **A token is for one gateway.** Each gateway has its own audience
  (its URL) and its own scope: an agent asks for the gateway's scope,
  and Keycloak adds that gateway's audience only. A token for gateway A
  is refused by B and C, so a gateway, its logs or someone who reads a
  token there cannot use it elsewhere. (One token with every gateway's
  audience would be valid at all of them.)
- **Groups are shared.** The token's groups claim names the user's
  Keycloak groups, and every gateway's role data binds roles to them.
- **Clients are shared.** One client for the agents, one for the
  approval pages, one for the command line; each lists every gateway's
  URLs.

The examples use `idp.example.com` for Keycloak and
`gw-a.example.com`, `gw-b.example.com`, `gw-c.example.com` for the
gateways, each listening on port 8443.

## Running Keycloak

### Certificate

Keycloak serves HTTPS with a certificate the gateway hosts trust (a
company CA, Let's Encrypt, or a CA of your own installed on every
gateway host):

```bash
# on the Keycloak host
install -d -m0750 /etc/keycloak/tls
install -m0640 keycloak.crt /etc/keycloak/tls/cert.pem
install -m0640 keycloak.key /etc/keycloak/tls/key.pem
```

Keycloak's image runs it as uid 1000 with group root (0): a key of
mode 0640 owned by `root:root` is readable to it, and to nobody else on
the host.

### A Podman Quadlet

```ini
# /etc/containers/systemd/keycloak.container
[Unit]
Description=Keycloak

[Container]
Image=quay.io/keycloak/keycloak:26.2
ContainerName=keycloak
PublishPort=443:8443
Environment=KC_HOSTNAME=https://idp.example.com
Environment=KC_HTTP_ENABLED=false
Environment=KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/conf/tls/cert.pem
Environment=KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/conf/tls/key.pem
Environment=KC_BOOTSTRAP_ADMIN_USERNAME=admin
Environment=KC_BOOTSTRAP_ADMIN_PASSWORD=<a strong password>
Volume=keycloak-data:/opt/keycloak/data:Z
Volume=/etc/keycloak/tls:/opt/keycloak/conf/tls:ro,Z
Exec=start

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl start keycloak.service
curl -sS https://idp.example.com/realms/master/.well-known/openid-configuration | jq -r .issuer
# https://idp.example.com/realms/master
firewall-cmd --permanent --add-service=https && firewall-cmd --reload
```

- **`KC_HOSTNAME`** is the URL users and gateways reach Keycloak at
  (with the port, if not 443): the issuer of every token is built from
  it, and `http.issuer` on the gateways must be exactly that issuer.
- **The port.** Keycloak listens on 8443 in the container; publish it
  on 443 (or 8080). The gateway reaches HTTP ports (`http_port_t`: 443,
  8443, …) and proxy ports (`http_cache_port_t`: 8080) for Keycloak's
  keys and the approval page, but SELinux labels ports by number, not by
  host: on a gateway host that labels 8443 `mcp_port_t` for its own
  listener, a Keycloak on port 8443 is out of the gateway's reach
  (`mcp-gateway-admin doctor`, `identity provider`, names the denial).
- **No proxy in front?** Then leave `KC_PROXY_HEADERS` unset: with it,
  Keycloak believes `X-Forwarded-*` headers from anyone. Behind a
  reverse proxy, set it as the proxy requires.
- **The database.** Without `KC_DB`, Keycloak keeps everything in the
  `keycloak-data` volume (H2), which is for trials. For production, use
  PostgreSQL (`KC_DB=postgres`, `KC_DB_URL`, `KC_DB_USERNAME`,
  `KC_DB_PASSWORD`).
- **The bootstrap admin** is a temporary account: sign in at
  `https://idp.example.com/admin/`, create a permanent administrator in
  the `master` realm, delete `admin`, and remove the two
  `KC_BOOTSTRAP_ADMIN_*` lines.

## The realm

In the admin console, at `https://idp.example.com/admin/`.

### Realm, groups and users

1. **Realm**: the realm list (top left) → *Create realm*, name `mcp`.
   Its issuer is `https://idp.example.com/realms/mcp`.
2. **Groups**: *Groups* → *Create group*, e.g. `mcp-sysops`,
   `mcp-developers`, `mcp-approvers`. The gateways bind roles to these
   names (below). Use names that no local group on a gateway host has:
   the role data binds groups by name, and the shipped default binds
   `wheel` to `admin`, so a Keycloak group named `wheel` would make its
   members administrators on every gateway.
3. **Users**: *Users* → *Add user*: username, e-mail, *Email verified*
   on, *Create*; *Credentials* → *Set password* (*Temporary* off);
   *Groups* → *Join group*.

With `http.local_user_claim: preferred_username` (chapter 5, "Who a
remote user is"), the Keycloak username of a user who should act as
their local account on a gateway host must be that account's name; on
a host without such an account the user is a remote principal (MCP
servers run as a dynamic user). Tokens naming root or a system account
are refused.

### One client scope per gateway

Each gateway gets an optional client scope that adds its audience to a
token, only when an agent asks for it:

1. *Client scopes* → *Create client scope*: name `mcp-gw-a`, type
   *Optional*, *Include in token scope* on, *Save*.
2. In it, *Mappers* → *Configure a new mapper* → *Audience*: name
   `audience`, *Included Custom Audience*
   `https://gw-a.example.com:8443/mcp` (gateway A's `http.audience`,
   exactly), *Add to access token* on, *Add to ID token* off.

Likewise `mcp-gw-b` with `https://gw-b.example.com:8443/mcp`, and so
on. Each gateway requires its scope (`http.scopes`, below) and names it
in its metadata and in its `401` answer (`WWW-Authenticate: Bearer
resource_metadata=…, scope="mcp-gw-a"`), and agents ask for it when
they sign in.

### The agents' client

The OAuth client agents sign in as (authorization code with PKCE):

1. *Clients* → *Create client*: *OpenID Connect*, client ID
   `mcp-agent`; *Client authentication* off (a public client, for
   agents on users' machines), *Standard flow* on, *Direct access
   grants* off; *Valid redirect URIs* `http://localhost:*` and
   `http://127.0.0.1:*` (the agents' local callbacks); *Save*.
2. *Advanced* → *Proof Key for Code Exchange Code Challenge Method*:
   `S256`.
3. *Client scopes* → *Add client scope*: every gateway's scope
   (`mcp-gw-a`, `mcp-gw-b`, …) as *Optional*.
4. *Client scopes* → `mcp-agent-dedicated` → *Configure a new mapper* →
   *Group Membership*: *Token Claim Name* `groups`, *Full group path*
   off (`mcp-sysops`, not `/mcp-sysops`), *Add to access token* on.

Agents that register themselves instead (dynamic client registration)
need Keycloak's client registration policies to allow it; a registered
client is simpler to keep under control. Tell the agent its client ID,
e.g. Claude Code: `claude mcp add --transport http --client-id
mcp-agent --callback-port 8765 fs https://gw-a.example.com:8443/mcp/fs`
(chapter 5, "Claude Code"). One client per kind of agent, with its own
redirect URIs, works the same way.

### The approval pages' client

One public client for the approval pages of all gateways (chapter 7,
"The gateway's approval page"):

1. *Clients* → *Create client*: client ID `mcp-gateway-approvals`,
   *Client authentication* off, *Standard flow* on, *Direct access
   grants* off.
2. *Valid redirect URIs*, one line per gateway:
   `https://gw-a.example.com:8443/approvals/callback`,
   `https://gw-b.example.com:8443/approvals/callback`, …
3. *Valid post logout redirect URIs*, one line per gateway:
   `https://gw-a.example.com:8443/approvals/signed-out`, … (without
   them, *Sign out* fails with "invalid redirect uri").
4. *Client scopes* → `mcp-gateway-approvals-dedicated` → *Group
   Membership* mapper as for the agents, with **Add to ID token** on:
   the page takes the approver's groups from the ID token.

No audience mapper: the page checks the ID token, which Keycloak issues
for the client itself. *Web origins* stay empty: the browser never
calls Keycloak from the page.

### The command line's client (optional)

For `mcp-gateway-admin approvals --gateway` on other hosts (chapter 7,
"Deciding from another host"), the device flow:

1. *Clients* → *Create client*: client ID
   `mcp-gateway-approvals-cli`, *Client authentication* off, *Standard
   flow* off, *OAuth 2.0 Device Authorization Grant* on.
2. The *Group Membership* mapper with *Add to ID token* on, as for the
   approval pages.

### Token lifetimes

An agent signs in once in the browser and then renews its access token
with the refresh token Keycloak gave it, without asking the user. The
gateway takes each new token as it comes: an HTTP session follows the
tokens of its requests (chapter 5). How long that goes on is Keycloak's
to decide, in *Realm settings*:

| Setting | Default | What it means |
|---|---|---|
| *Tokens* → *Access Token Lifespan* | 5 min | how long an access token lasts; the agent renews it after that |
| *Sessions* → *SSO Session Idle* | 30 min | the refresh token expires after this long without a renewal (the agent closed over lunch) |
| *Sessions* → *SSO Session Max* | 10 h | the refresh token expires after this long, renewed or not |
| *Sessions* → *Offline Session Idle* | 30 days | the same for an offline token (below) |

When the refresh token has expired, the agent has to send its user to
the browser again. Which limit was hit shows in when that happens:

- **About every 5 minutes:** the agent does not renew at all. The
  gateway's journal says `token rejected` with `token is expired` for
  each request with the old token. That is the agent's to fix; a longer
  *Access Token Lifespan* only hides it, and makes a stolen token
  useful for longer.
- **After a break of half an hour or more:** *SSO Session Idle*.
- **Once a day, whatever you do:** *SSO Session Max*.

Two ways to keep agents signed in longer:

- **Longer sessions:** raise *SSO Session Idle* (8 h, say) and *SSO
  Session Max* (7 days). That applies to every client of the realm,
  the approval pages and the command line too. *Clients* → a client →
  *Advanced* → *Client Session Idle* and *Client Session Max* can only
  make it shorter for that client.
- **Offline tokens, for the agents' client:** an offline token is a
  refresh token that does not depend on the sign-in session: it lasts
  *Offline Session Idle* without use and survives a restart of
  Keycloak. Agents ask only for the gateway's scope, so make
  `offline_access` a scope they get without asking: *Clients* →
  `mcp-agent` → *Client scopes*, where `offline_access` is listed as
  *Optional* (every new client gets it so; the *Add client scope*
  dialog does not offer scopes the client has), and set it to
  **Default**. For agents that register themselves, also set
  `offline_access` to *Default* under *Client scopes* (the realm's
  list, *Assigned type*). The users need the realm role
  `offline_access`, which `default-roles-mcp` includes. After the next
  sign-in, *Users* → the user → *Sessions* lists an *Offline* session
  for the client; signing it out there revokes the token.

Do not put `offline_access` in a gateway's `http.scopes`: the gateway
would then refuse every token without it, from every agent. An access
token's lifespan also bounds a single call: one that outlasts it ends
with `token_expired` and its result is withheld (chapter 5); ask for a
task for such calls rather than lengthening the lifespan.

If the realm has no `offline_access` client scope at all (someone
deleted it): *Client scopes* → *Create client scope*, name
`offline_access`, type *Optional*, *Include in token scope* on; in its
*Scope* tab, *Assign role* → the realm role `offline_access` (create it
under *Realm roles* and add it to `default-roles-mcp` if it is gone too).

## Each gateway

The same on every gateway host, with its own name; only `http.audience`
and `http.scopes` differ between gateways.

### Certificate, port, trust

```bash
install -d -m0750 -o root -g mcp-gateway /etc/mcp-gateway/tls
install -m0640 -g mcp-gateway gw-a.crt /etc/mcp-gateway/tls/cert.pem
install -m0640 -g mcp-gateway gw-a.key /etc/mcp-gateway/tls/key.pem
restorecon -R /etc/mcp-gateway/tls
semanage port -a -t mcp_port_t -p tcp 8443 2>/dev/null || semanage port -m -t mcp_port_t -p tcp 8443
firewall-cmd --permanent --add-port=8443/tcp && firewall-cmd --reload
# Keycloak's certificate from a CA of your own:
cp ca.pem /etc/pki/trust/anchors/keycloak-ca.pem && update-ca-certificates
```

### The listener, the approval page and the command line

```console
# mcp-gateway-admin setup http --url https://gw-a.example.com:8443/mcp \
    --issuer https://idp.example.com/realms/mcp \
    --cert /etc/mcp-gateway/tls/cert.pem --key /etc/mcp-gateway/tls/key.pem \
    --local-user-claim preferred_username --scopes mcp-gw-a \
    --client-id mcp-gateway-approvals --device-client-id mcp-gateway-approvals-cli --write
# systemctl restart mcp-gateway.service
```

`setup http` checks Keycloak (its metadata, keys and the approval
page's client with this gateway's redirect URI), the certificate, the
SELinux labels and the firewall before it writes, and says what to fix.
Written by hand instead, as a drop-in (chapter 3, "Drop-ins"):

```yaml
# /etc/mcp-gateway/gateway.d/30-keycloak.yaml
http:
  listen: ":8443"
  cert_file: /etc/mcp-gateway/tls/cert.pem
  key_file: /etc/mcp-gateway/tls/key.pem
  issuer: https://idp.example.com/realms/mcp
  audience: https://gw-a.example.com:8443/mcp
  groups_claim: groups
  local_user_claim: preferred_username
  scopes: [mcp-gw-a]
approvals:
  page:
    client_id: mcp-gateway-approvals
    device_client_id: mcp-gateway-approvals-cli
```

### Role data

Bind the gateway's roles to the Keycloak groups, in a copy of the
shipped default (`cp /usr/share/mcp-gateway/rbac/data.yaml
/etc/mcp-gateway/policy/rbac/data.yaml`, chapter 6), so that its roles
and bindings stay:

```yaml
# /etc/mcp-gateway/policy/rbac/data.yaml (excerpt)
bindings:
  groups:
    dev: [developer]
    wheel: [admin]
    mcp-developers: [developer]
    mcp-sysops: [admin]
  users: {}
approvers:
  default: [self, 'role:admin', 'remote-group:mcp-approvers']
```

A user's roles come from their token's groups and, when they act as a
local account, that account's groups too. Approver rules match a
signed-in approver with a local account as that account (`self`,
`role:`, `group:`, `user:`), one without by `remote-user:` and
`remote-group:` only (chapter 7, "The gateway's approval page"). The
file may be the same on every gateway, or bind other roles per host.

Approving one's own request asks for the password on the command line
and in Cockpit (chapter 7, "Approving your own request: your
password"), not on the approval page, where the sign-in at Keycloak
already authenticated the approver.

### Checking

```console
# mcp-gateway --check && systemctl restart mcp-gateway.service
# mcp-gateway-admin doctor
```

The doctor's `identity provider` fetches Keycloak's metadata and keys,
`approval page` checks the client with this gateway's redirect URI,
`TLS` that the certificate names the host of `http.audience`, and
`firewall` the port.

To see what the gateway makes of a token, get one for a test user from
a client that allows the password grant, kept for tests only: create
`mcp-test` (*Client authentication* off, *Direct access grants* on,
the gateways' scopes as *Optional* and the *Group Membership* mapper as
for the agents), then

```bash
curl -sS https://idp.example.com/realms/mcp/protocol/openid-connect/token \
    -d client_id=mcp-test -d grant_type=password \
    -d username=alice -d password='…' -d 'scope=openid mcp-gw-a' |
    jq -r .access_token >/root/token.jwt
mcp-gateway-admin setup http --token /root/token.jwt   # the principal, groups, scopes; or why it is refused
rm /root/token.jwt
```

and delete `mcp-test` when done: the password grant lets anyone who
has a password get tokens without the browser's sign-in.

## Quick reference

| What | Value |
|---|---|
| issuer (`http.issuer`, every gateway) | `https://idp.example.com/realms/mcp` |
| a gateway's audience (`http.audience`) | `https://<gateway>:8443/mcp` |
| a gateway's scope (`http.scopes`) and client scope | `mcp-<gateway>`, with an *Audience* mapper for its audience |
| approval page | `https://<gateway>:8443/approvals/` |
| redirect URI, post-logout redirect URI | `https://<gateway>:8443/approvals/callback`, `…/approvals/signed-out` |
| protected resource metadata | `https://<gateway>:8443/.well-known/oauth-protected-resource/mcp` |

| Client | Kind | Flow | Mappers |
|---|---|---|---|
| `mcp-agent` | public | authorization code, PKCE (S256) | the gateways' scopes (optional), `offline_access` (default, for offline tokens); Group Membership in the access token |
| `mcp-gateway-approvals` | public | authorization code, PKCE | Group Membership in the ID token |
| `mcp-gateway-approvals-cli` | public | device authorization grant | Group Membership in the ID token |

| Symptom | Cause | Fix |
|---|---|---|
| `401 invalid token` from a gateway | the token lacks the gateway's audience: the agent did not ask for its scope, or the scope has no *Audience* mapper | the client scope with its mapper, added to the agent's client; `setup http --token` shows the token's `aud` |
| `403 insufficient scope` | the token lacks the gateway's scope (`http.scopes`); the gateway's journal names the token's client (`HTTP request refused`, `err`) | add the scope to that client: as *Optional* if the agent asks for it after the `401`, else as *Default*. An agent that registered itself (a client ID that is a UUID) gets the realm's default client scopes: *Client scopes*, the scope's *Assigned type* *Default*, before it registers; *Clients* → the client → *Client scopes* → *Evaluate* shows the access token it gets |
| a user has no tools | the token has no `groups`, or no binding names its groups | the *Group Membership* mapper (access token on); `bindings.groups` in the role data |
| the approval page shows nothing to decide | the ID token has no groups, or the approver rules do not name the approver | the mapper on the approval page's client with *Add to ID token* on; `remote-group:` for approvers without a local account |
| `preferred_username` does not map to the local account | the Keycloak username differs from the account's name, or the account is a system account | the same username on both; tokens never map to root or system accounts |
| the agent asks for a browser sign-in again every few minutes | the agent does not renew its token (the journal: `token rejected`, `token is expired`) | the agent's to fix; see "Token lifetimes" |
| the agent asks for a browser sign-in again after a break, or once a day | the refresh token expired: *SSO Session Idle* (30 min) or *SSO Session Max* (10 h) | longer sessions, or `offline_access` as a *Default* scope of the agents' client ("Token lifetimes") |
| *Sign out* on the page fails: "invalid redirect uri" | the post-logout redirect URI is missing | add `https://<gateway>:8443/approvals/signed-out` to the client |
| `identity provider` fails: connection refused or permission denied | the gateway's SELinux domain may not connect to Keycloak's port, or a firewall | Keycloak on 443 or 8080, or label its port `http_port_t` (not one labeled `mcp_port_t` on the gateway host) |
| `certificate signed by unknown authority` | Keycloak's CA is not trusted on the gateway host | `cp ca.pem /etc/pki/trust/anchors/ && update-ca-certificates` |
