# The gateway's container image built in the Open Build Service from the
# project's RPMs (mcp-gateway-container; packaging/container/README.md,
# "Building in OBS"). The same image as packaging/container/Containerfile
# builds from a checkout: uid 10001, port 8443, the same entry point.
#
#!BuildTag: sdrahn/mcp-gateway:latest
#!BuildTag: sdrahn/mcp-gateway:%PKG_VERSION%
#!BuildTag: sdrahn/mcp-gateway:%PKG_VERSION%-%RELEASE%
#!UseOBSRepositories

FROM opensuse/bci/bci-micro:latest AS micro

# BCI-Micro has no package manager: zypper of Tumbleweed's image installs
# the package into a copy of it (--installroot uses that image's
# repositories, which OBS points at the project's). Tumbleweed has no
# bci-base; opensuse/tumbleweed is its image with zypper.
FROM opensuse/tumbleweed:latest AS build
COPY --from=micro / /target
RUN zypper -n --installroot /target install --no-recommends mcp-gateway-container && \
    zypper -n --installroot /target clean --all && \
    rm -rf /target/var/cache/zypp /target/var/log/zypp*

FROM micro
COPY --from=build /target /

LABEL org.opencontainers.image.title="mcp-gateway" \
      org.opencontainers.image.description="Policy-enforcing gateway for MCP servers, in container mode" \
      org.opencontainers.image.source="https://github.com/sdrahn/mcp-gateway" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="%PKG_VERSION%"

# An account of its own, never root; the manifests set the same ids
# (runAsUser, fsGroup).
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/bin/mcp-gateway"]
CMD ["--config", "/etc/mcp-gateway/config/gateway.yaml"]
