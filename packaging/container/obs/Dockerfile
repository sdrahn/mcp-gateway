# The gateway's container image built in the Open Build Service from the
# project's RPMs (mcp-gateway-container; packaging/container/README.md,
# "Building in OBS"). The same image as packaging/container/Containerfile
# builds from a checkout: uid 10001, port 8443, the same entry point.
#
#!BuildTag: sdrahn/mcp-gateway:latest
#!BuildTag: sdrahn/mcp-gateway:%PKG_VERSION%
#!BuildTag: sdrahn/mcp-gateway:%PKG_VERSION%-%RELEASE%
#!BuildVersion: %PKG_VERSION%
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

# The labels between labelprefix and endlabelprefix are repeated with
# the image's own prefix (docker_label_helper), as derived images'
# labels are on openSUSE (https://en.opensuse.org/Building_derived_containers);
# without them, the base's org.opensuse.bci.micro.* labels describe
# this image. org.opensuse.reference names where this project publishes
# the image: change it for another project (README, "Building in OBS").
# labelprefix=org.opensuse.mcp-gateway
LABEL org.opencontainers.image.title="mcp-gateway"
LABEL org.opencontainers.image.description="Policy-enforcing gateway for MCP servers, in container mode"
LABEL org.opencontainers.image.version="%PKG_VERSION%"
LABEL org.opencontainers.image.source="https://github.com/sdrahn/mcp-gateway"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.created="%BUILDTIME%"
LABEL org.opensuse.reference="registry.opensuse.org/home/sdrahn/testing/containerfile/sdrahn/mcp-gateway:%PKG_VERSION%-%RELEASE%"
LABEL org.openbuildservice.disturl="%DISTURL%"
# endlabelprefix

# An account of its own, never root; the manifests set the same ids
# (runAsUser, fsGroup).
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/bin/mcp-gateway"]
CMD ["--config", "/etc/mcp-gateway/config/gateway.yaml"]
