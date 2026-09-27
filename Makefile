VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
GO      ?= go
OPA     ?= opa
# Distribution builds: PIE, reproducible paths. GOFLAGS (e.g. -mod=vendor)
# is passed through from the environment.
BUILDMODE ?= pie
LDFLAGS   := -X github.com/sdrahn/mcp-gateway/internal/version.Version=$(VERSION)
GOBUILD    = $(GO) build -trimpath -buildmode=$(BUILDMODE)

SELINUX_DEVEL ?= /usr/share/selinux/devel/Makefile
SELINUXTYPE   ?= targeted

# Installation directories (override from the package build, e.g. the spec
# passes %{_libexecdir}, %{_distconfdir}, %{_unitdir}, ...).
PREFIX      ?= /usr
BINDIR      ?= $(PREFIX)/bin
LIBEXECDIR  ?= $(PREFIX)/libexec
DATADIR     ?= $(PREFIX)/share
SYSCONFDIR  ?= /etc
# Where the default gateway.yaml goes: /usr/etc on openSUSE (UsrEtc),
# $(SYSCONFDIR) elsewhere.
DISTCONFDIR ?= $(SYSCONFDIR)
UNITDIR     ?= $(PREFIX)/lib/systemd/system
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d
POLKITDIR   ?= $(DATADIR)/polkit-1/rules.d
COCKPITDIR  ?= $(DATADIR)/cockpit/mcp-gateway
SELINUXDIR  ?= $(DATADIR)/selinux/packages/$(SELINUXTYPE)
DESTDIR     ?=

BINARIES := bin/mcp-gateway bin/mcp-connect bin/mcp-fs-demo

.PHONY: all build test vet lint fmt-check policy-check policy-test selinux check \
	install install-gateway install-selinux install-cockpit install-demo clean

all: build

build: $(BINARIES)

bin/mcp-fs-demo: FORCE
	$(GOBUILD) -o $@ ./examples/mcp-fs-demo

bin/%: FORCE
	$(GOBUILD) -ldflags '$(LDFLAGS)' -o $@ ./cmd/$*

FORCE:

# e2e/ runs when opa is on PATH (or $$OPA is set), and is skipped otherwise.
test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(OPA) fmt --fail --list policy

policy-check:
	$(OPA) check --strict policy

policy-test:
	$(OPA) test policy -v

selinux: selinux/mcp_gateway.pp

selinux/mcp_gateway.pp: selinux/mcp_gateway.te selinux/mcp_gateway.if selinux/mcp_gateway.fc
	$(MAKE) -C selinux -f $(SELINUX_DEVEL) mcp_gateway.pp

# Everything CI runs, except lint and the SELinux build.
check: fmt-check vet test policy-check policy-test

# Everything but the SELinux module, the Cockpit page and the demo server,
# which distributions ship as subpackages.
install: install-gateway

install-gateway:
	install -Dm0755 bin/mcp-gateway $(DESTDIR)$(BINDIR)/mcp-gateway
	install -Dm0755 bin/mcp-connect $(DESTDIR)$(BINDIR)/mcp-connect
	install -Dm0644 config/gateway.yaml $(DESTDIR)$(DISTCONFDIR)/mcp-gateway/gateway.yaml
	install -d $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/servers.d
	install -d -m0700 $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/credentials
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp
	install -m0644 $(filter-out %_test.rego,$(wildcard policy/mcp/*.rego)) $(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp/
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/policy/system
	install -m0644 $(filter-out %_test.rego,$(wildcard policy/system/*.rego)) $(DESTDIR)$(DATADIR)/mcp-gateway/policy/system/
	install -Dm0644 policy/rbac/data.json $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/policy/rbac/data.json
	install -Dm0644 systemd/mcp-gateway.service $(DESTDIR)$(UNITDIR)/mcp-gateway.service
	install -Dm0644 systemd/mcp-opa.service $(DESTDIR)$(UNITDIR)/mcp-opa.service
	install -Dm0644 packaging/sysusers.d/mcp-gateway.conf $(DESTDIR)$(SYSUSERSDIR)/mcp-gateway.conf
	install -Dm0644 packaging/polkit/50-mcp-gateway.rules $(DESTDIR)$(POLKITDIR)/50-mcp-gateway.rules

install-selinux: selinux/mcp_gateway.pp
	install -d $(DESTDIR)$(SELINUXDIR)
	bzip2 -9 -c selinux/mcp_gateway.pp >$(DESTDIR)$(SELINUXDIR)/mcp_gateway.pp.bz2
	chmod 0644 $(DESTDIR)$(SELINUXDIR)/mcp_gateway.pp.bz2

install-cockpit:
	install -d $(DESTDIR)$(COCKPITDIR)
	install -m0644 cockpit/mcp-gateway/* $(DESTDIR)$(COCKPITDIR)/

install-demo:
	install -Dm0755 bin/mcp-fs-demo $(DESTDIR)$(LIBEXECDIR)/mcp-servers/mcp-fs-demo
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d
	sed 's|@LIBEXECDIR@|$(LIBEXECDIR)|g' packaging/demo/fs-demo.yaml.in \
		>$(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/fs-demo.yaml
	chmod 0644 $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/fs-demo.yaml

clean:
	rm -rf bin selinux/tmp selinux/*.pp
