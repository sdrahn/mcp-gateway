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
| `IMAGE_BASE` | `registry.suse.com/bci/bci-micro:16.0` | the base image |
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
| `registry.suse.com/bci/bci-micro:16.0` | SLES 16 | the default; the CI's kind jobs build on it |
| `registry.suse.com/bci/bci-micro:15.7` | SLE 15 SP7 | `IMAGE_BASE=registry.suse.com/bci/bci-micro:15.7` |
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
make image CONTAINER=podman IMAGE=registry.example.com/mcp-gateway:2.0.0
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

## Building in OBS

The Open Build Service builds the RPMs (`packaging/suse`), and can build
the image from them too: the subpackage `mcp-gateway-container` holds
exactly what `make install-container` stages, without services, accounts
or dependencies. `obs/Dockerfile` installs it into BCI-Micro. Steps, for
a project such as `home:sdrahn:testing`, whose repository
`openSUSE_Tumbleweed` builds the RPMs:

1. **The package `mcp-gateway`** from this checkout's spec (the
   `container` subpackage and the stdio bridge are new in 2.0): copy
   `packaging/suse/{mcp-gateway.spec,_service,mcp-gateway-rpmlintrc}`
   into the OBS package and run `osc service manualrun`
   (`packaging/suse/README.md`). To keep a released version published,
   build this one in a subproject, such as `home:sdrahn:testing:main`.

2. **A repository for the image** in the project's meta
   (`osc meta prj -e home:sdrahn:testing`): the RPMs, and the base
   images from `openSUSE:Containers:Tumbleweed`:

   ```xml
   <repository name="containerfile">
     <path project="home:sdrahn:testing" repository="openSUSE_Tumbleweed"/>
     <path project="openSUSE:Containers:Tumbleweed" repository="containers"/>
     <arch>x86_64</arch>
     <arch>aarch64</arch>
   </repository>
   ```

   The RPM packages build in it no more (`<disable
   repository="containerfile"/>` in each package's build flags), and
   the image's package builds there only (`<disable
   repository="openSUSE_Tumbleweed"/>`).

3. **The project config** (`osc meta prjconf -e home:sdrahn:testing`):
   Dockerfile builds with Podman in that repository:

   ```
   %if "%_repository" == "containerfile"
   Type: docker
   BuildEngine: podman
   %endif
   ```

4. **The package `mcp-gateway-container`** with `obs/Dockerfile` and
   `obs/_service`:

   ```bash
   osc mkpac mcp-gateway-container && cd mcp-gateway-container
   cp <checkout>/packaging/container/obs/{Dockerfile,_service} .
   osc add Dockerfile _service && osc commit
   ```

   - The Dockerfile names the images of the repository's path:
     `opensuse/bci/bci-micro` and `opensuse/tumbleweed`, Tumbleweed's
     image with zypper; Tumbleweed has no `bci-base`. If a build does
     not find them, list what the path offers:
     `osc ls -b openSUSE:Containers:Tumbleweed containers x86_64 | grep -E 'bci|tumbleweed'`.
   - It tags `sdrahn/mcp-gateway` as `latest`, `%PKG_VERSION%` and
     `%PKG_VERSION%-%RELEASE%`, and names the built file after
     `%PKG_VERSION%` (`#!BuildVersion`), e.g.
     `sdrahn-mcp-gateway-2.0.0.x86_64-4.1.tar`. `_service` fills these
     in at build time: `replace_using_package_version` puts the version
     of `mcp-gateway-container` into `%PKG_VERSION%`, and
     `kiwi_metainfo_helper` replaces `%RELEASE%` (OBS's build counter),
     `%BUILDTIME%` and `%DISTURL%`. obs-build itself replaces none of
     them; without `kiwi_metainfo_helper`, podman refuses the tag
     `…-%RELEASE%` ("invalid reference format").
   - Its labels carry the image's own prefix as well,
     `org.opensuse.mcp-gateway.*` (`docker_label_helper`), so they do
     not read as BCI-Micro's. `org.opensuse.reference` names where
     `home:sdrahn:testing` publishes the image: in another project,
     change it to that project's path (below).
   - container-build-checks warns four times in a home project, which
     is not fatal there: three times that the tags are outside the
     namespaces openSUSE's container projects allow (`opensuse/*`,
     `bci/*` and a few more), and once that `org.opensuse.reference`
     names no tag. The check strips only the registry's host from the
     reference, and a home project publishes below its project and
     repository, so the rest never equals a tag.
   - The image is the one `make image` builds: uid 10001, port 8443,
     the same entry point. Its RPM database names the package, so
     scanners see the gateway's version.

OBS publishes images at
`registry.opensuse.org/<project, ":" as "/">/<repository>/<image>:<tag>`,
here
`registry.opensuse.org/home/sdrahn/testing/containerfile/sdrahn/mcp-gateway:<tag>`.
OBS signs what it publishes. Images built in an openSUSE project are
openSUSE's, not SUSE's supported BCI-based images.

The installation from the package is tested here with a local stand-in
for the project's repository: the same Dockerfile, its `FROM` lines by
registry name, a repository of an `mcp-gateway-container` built from
`make install-container`'s files. One package is installed (BCI-Micro's
RPM database already holds what it needs), and the image runs as the
gateway's pod (`deploy/podman`).

### Using the published image

- **Helm**: `image.repository:
  registry.opensuse.org/home/sdrahn/testing/containerfile/sdrahn/mcp-gateway`
  and a fixed `image.tag` (a version, not `latest`). The chart names the
  same image as the Kubernetes launcher's `bridge_image`.
- **kubectl**: in `deploy/kubernetes/kustomization.yaml`, set the
  `images` entry's `newName` and `newTag` to it, and the same image as
  `supervisor.kubernetes.bridge_image` in `configmap.yaml`: the launcher
  copies the stdio bridge from that image into each stdio server's pod,
  so it has to be the gateway's own.
- **Podman and Compose**: the `image` lines of `deploy/podman` and
  `MCP_GATEWAY_IMAGE` (user guide, chapter 17).
