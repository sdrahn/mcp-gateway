# The container image on SUSE systems

`Containerfile` builds the gateway's container image (2.0, container
mode; user guide, chapters 16 and 17) on a SUSE Linux Base Container
Image (BCI). The image holds:

- the gateway and `mcp-gateway-admin`;
- the connector, the sign-in helper, `mcp-policy-render` and
  `mcp-stdio-bridge` (in `/usr/libexec/mcp-gateway`);
- the policy (`/usr/share/mcp-gateway/policy`) and the shipped role data.

It builds from the same sources as the RPMs (`packaging/suse`), but not
from the RPMs: `make image` builds the binaries, stages them with
`make install-container`, and copies the staged tree onto the base. It
runs as uid and gid 10001, never as root. OPA comes from its own image
(`openpolicyagent/opa`, the `-static` variant).

## Building on SLES, Leap or Tumbleweed

You need Go (the version in `go.mod`), `make` and Podman (or Docker).
Building needs no root.

```bash
zypper install go make podman git
git clone https://github.com/sdrahn/mcp-gateway && cd mcp-gateway
make image CONTAINER=podman IMAGE=registry.example.com/mcp-gateway:2.0.0
```

| Variable | Default | Meaning |
|---|---|---|
| `IMAGE` | `mcp-gateway:$(VERSION)` | the image's name and tag |
| `IMAGE_BASE` | `registry.suse.com/bci/bci-micro:15.7` | the base image |
| `CONTAINER` | `docker` | `podman` or `docker` |
| `VERSION` | `git describe --tags --always --dirty` | the version in the binaries and the image's label |

`make image` stages into `build/image` and builds from there. The build
reads nothing else from the checkout.

### The base image

The image needs the GNU C library (the binaries link it, all but
`mcp-stdio-bridge`, which runs in other images) and `cp` (the init
container copies the policy with it). BCI-Micro has both, with bash and
coreutils, and no package manager. These bases are tested:

| Base | For | Note |
|---|---|---|
| `registry.suse.com/bci/bci-micro:15.7` | SLE 15 SP7 | the default; the CI's kind jobs build on it |
| `registry.suse.com/bci/bci-micro:16.0` | SLES 16 | `IMAGE_BASE=registry.suse.com/bci/bci-micro:16.0` |
| `registry.opensuse.org/opensuse/bci/bci-micro:latest` | openSUSE Tumbleweed | rolling: rebuild often |

The other BCI variants (BCI-Base with zypper, BCI-Minimal with rpm,
BCI-BusyBox, BCI-Nano without a shell or coreutils, and the FIPS
variants such as `bci-micro-fips`) are described in SUSE's Container
Guide, section 4:
<https://documentation.suse.com/container/all/html/Container-guide/index.html>.
BCI-Nano has no C library and no `cp`: the image does not run on it.

### Verifying the base

SUSE signs its BCI images with Sigstore Cosign and Podman's signatures.
The public key is installed as
`/usr/share/pki/containers/suse-container-key.pem`. To have Podman
refuse unsigned or wrongly signed images from `registry.suse.com`, set
up `/etc/containers/registries.d/` and `/etc/containers/policy.json` as
the Container Guide's section 17 says.

## What the image is

| | |
|---|---|
| Entry point | `/usr/bin/mcp-gateway`, command `--config /etc/mcp-gateway/config/gateway.yaml` |
| User | `10001:10001` |
| Ports | `8443` (HTTPS listener), `9464` (metrics and probes, as configured) |
| Writable | nothing in the image: the state volume, `/run/mcp-gateway`, `/run/mcp-opa` and `/tmp` are volumes |
| Labels | `org.opencontainers.image.title`, `.description`, `.source`, `.licenses`, `.version` |

The image inherits the base's labels, the `com.suse.*` ones among them.
They describe the base, not the gateway.

## Publishing

Tag the release's version, and the minor version for those who follow
fixes, then push:

```bash
make image CONTAINER=podman IMAGE=registry.example.com/mcp-gateway:2.0.0 \
    IMAGE_BASE=registry.suse.com/bci/bci-micro:16.0
podman tag registry.example.com/mcp-gateway:2.0.0 registry.example.com/mcp-gateway:2.0
podman push registry.example.com/mcp-gateway:2.0.0
podman push registry.example.com/mcp-gateway:2.0
```

The manifests, the chart, the Podman pod and the Compose file name the
image in one place each (user guide, chapters 16 and 17).

SUSE's BCI images "are covered by a permissive EULA that allows you to
redistribute custom container images based on a SUSE Linux Base
Container Image" (Container Guide, section 3.1). They "do not require a
subscription to run and distribute them" (section 3.2).

## Keeping it current

The image is as current as its base. Rebuild it when SUSE updates the
base (security fixes), not only for a new gateway release:
`podman pull` the base and run `make image` again with the same
`VERSION`.

## Not covered here: OBS

The Open Build Service builds the RPMs (`packaging/suse`). Building this
image in OBS as well needs a project set up for container builds and a
Dockerfile that installs the gateway from the project's RPMs. Neither is
part of this directory yet.
