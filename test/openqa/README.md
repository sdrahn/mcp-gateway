# mcp-gateway in openQA

The functional tests of the gateway come as the package
`mcp-gateway-tests`, for openQA and other test systems that test a
product with the packages from its repositories. The CI's VM test runs
the same package the same way (`test/vm/run-vm.sh`).

## What the package holds

| Path | What |
|---|---|
| `/usr/libexec/mcp-gateway/tests/run-tests.sh` | the tests (`test/vm/run-tests.sh` in the source) |
| `/usr/libexec/mcp-gateway/tests/mcpcall` | the test client: one MCP request as the user who runs it |
| `/usr/libexec/mcp-gateway/tests/privsrv` | a test server: a privileged backend, an MCP server over HTTP(S), an OAuth authorization server, an OpenID provider for the gateway's listener |

It requires the gateway's packages (`mcp-gateway`, `-selinux`,
`-fs-server`, `-exec-server`, `-tools`) and what the tests run: `audit`,
`policycoreutils`, `selinux-tools`, `selinux-policy-devel`, `make`,
`rpm-build`, `jq`, `curl`, `polkit`, `util-linux`. On SLES these come
from the Basesystem and Development Tools modules.

## Running them

As root, on a system with SELinux enforcing that is there for testing:

```bash
zypper -n in mcp-gateway-tests
/usr/libexec/mcp-gateway/tests/run-tests.sh --disposable --results /var/tmp/mcp-gateway-tests
```

- **They change the system for good:** users `alice`, `bob`, `carol`,
  `dora` and `erin`, the role data, `gateway.yaml` and drop-ins, a test
  SELinux module and package, booleans, and the gateway's state; and
  they end by removing the gateway's packages, this one included (the
  last section, "Uninstall"). Without `--disposable` they refuse to
  start (exit status 2). Run them on a snapshot or a throwaway VM, and
  only once per system.
- **Results:** every check prints `PASS:`, `FAIL:` or `SKIP:` on
  standard output, in sections (`=== Calls`). With `--results DIR`,
  `results.tap` (TAP) and `results.xml` (JUnit, a test suite per
  section) are written there. Exit status 0 when nothing failed, 1
  otherwise.
- **The server setups** (systemd, firewalld, zypp, snapper,
  suseconnect, podman) are tested when all their packages are installed
  (`mcp-gateway-profile-*` and `systemd-mcp`, `firewalld-mcp`,
  `mcp-server-zypp`, `mcp-server-snapper`, `mcp-server-suseconnect`,
  `podman-mcp-server`), and skipped otherwise (one `SKIP`). They install
  `firewalld`, `snapper`, `btrfsprogs` and `podman` from the repositories
  if missing.
- **The update test** needs the packages as files (`--rpms DIR`, as in
  CI); without it, it is skipped and the program is replaced in place
  instead, which tests the same restart notice.
- **Time:** a few minutes (under five in CI with 2 CPUs and 4 GB of
  memory, the setups included); installing their packages from slow
  repositories adds to it. A timeout of 30 minutes leaves room.

## An openQA test module

For [os-autoinst-distri-opensuse](https://github.com/os-autoinst/os-autoinst-distri-opensuse),
as `tests/console/mcp_gateway.pm`: [mcp_gateway.pm](mcp_gateway.pm). It
installs the package, runs the tests, hands the JUnit results to openQA
(`parse_extra_log`), so that each check is a result of its own, and
uploads the output and the gateway's journal. Schedule it after the
system is installed and registered, with the repository that has the
gateway's packages; the setups need theirs as well.

## Tests to add

What the tests cover now: the domains, users and MCS pairs of the
gateway, OPA and the instances; calls and refusals by policy, with
argument constraints; the obligations under the real OPA and the shipped
policy (redaction, pseudonymization and the session's vault,
re-identification, the size limit, the rate limit, full audit); role
data in YAML (`data.yaml` in force over `data.json`, rendered for OPA to
`/run/mcp-opa/rbac` by `mcp-policy-render.service`, which the gateway's
account cannot write; a change in force within seconds, YAML that does
not parse keeping the role data in force, a subdirectory rendered along,
the doctor naming the ignored file); the limits per principal, lowered with `mcp-gateway-admin config set` (a
session, an instance and a task refused, room again once a session ends
or an instance is idle, an idle HTTP session making room, the refusals
counted and audited); failing closed and recovering (OPA stopped
denies every call, a killed instance replaced, one that keeps dying
backed off, a killed gateway started again by systemd with its
grants and pending approvals); signed policy bundles (a change previewed
with what-if, OPA in bundle mode with a key made by `mcp-policy-bundle`,
unsigned role data without effect, a tampered bundle and one signed with
another key refused, everything denied until a valid one is back);
uninstalling (a setup package's server and polkit rule gone; all
packages removed without stopping anything first: the services stopped
and disabled, no instance left, the SELinux modules unloaded once the
modules and ports built on their types are gone, configuration and
state kept); a remote principal without a local account (servers
working in the home not offered to it, others are); users from a
directory (389 Directory Server and SSSD: users and groups not in
/etc/passwd, the socket's group a directory group, roles bound to it,
approvals by a directory group); e-mail approvals (a local postfix,
approvers by group, members listed and by primary group, no mail
without `mcpgw_can_send_mail`); approvals through the control API;
files written through the file server and what SELinux keeps from it;
polkit; credentials; a privileged backend and its own SELinux module; the six
server setups with their real servers (systemd changes a unit after an
approval, `inspect`, `profile`); servers over HTTP, over HTTPS through a
proxy, and with a sign-in per user (OAuth); the gateway's own HTTPS
listener for remote agents (set up with `mcp-gateway-admin setup
http`, tokens refused for a missing token, expiry, audience, an unknown
key or a missing scope, the principal acting as its local account, a
scope ceiling with step-up, an agent of MCP 2026-07-28 without a
session, a renewed certificate taken without a restart); live reloads of server
definitions, `gateway.yaml` and drop-ins, `mcp-gateway-admin config`;
an update without restart; clients and tasks from the command line;
metrics; the self-check; the kernel audit records; and no SELinux
denials. The Go tests in CI cover the protocol, the policy logic and
the clients (`e2e/`, `test/clients`) without SELinux.

Proposed additions, the most valuable first, each an openQA test module
of its own (what openQA does well and CI cannot):

1. **Reboot:** after the tests' setup, reboot and check that the
   gateway and OPA come up, `/run/mcp-gateway` and its sockets are back
   with their groups and labels, the doctor is clean, and grants made
   before the reboot still apply.
2. **Transactional systems** (SL Micro, openSUSE MicroOS): install
   with `transactional-update pkg install` and reboot, then the tests;
   `/usr` read-only, `/etc` as an overlay, the SELinux relabel after
   the snapshot, and the documented "read-only file system" message for
   the commands that would write `/usr`.
3. **Upgrade and migration:** install the previous release from the
   product's maintenance repository, set it up (drop-ins, grants,
   sign-in tokens), update to the new one with `zypper up`, and run the
   tests against the kept state: restart notice, configuration kept,
   deprecation warnings, `test/compat` on the product. And a service
   pack migration (SLES 16.0 to 16.1) with the gateway installed.
4. **Cockpit in a browser:** log in to Cockpit (`https://host:9090`),
   open "MCP Gateway", approve a pending call that `mcpcall` waits on,
   end a client, cancel a task, reload the configuration, with needles
   for the tabs. Kit's page (cockpit-kit) the same way, against this
   gateway.
5. **Desktop approvals:** `mcp-gateway-desktop` in a GNOME session: the
   notification appears, "Approve" lets the waiting call through.
6. **FIPS mode** (SLES with `fips=1` and the FIPS crypto policy): the
   HTTPS listener and the connector's TLS, the AES-GCM token store of
   sign-ins, and the OAuth helper still work, with only FIPS-approved
   algorithms.
7. **Other architectures:** aarch64, ppc64le and s390x. The packages
   build there, but the tests have run on x86_64 only; MCS pairs,
   Landlock ABIs and the audit records differ by kernel and
   architecture.
8. **Longer runs:** many sessions and instances for an hour (memory,
   file descriptors, journal volume), and `logrotate` of the audit log.
