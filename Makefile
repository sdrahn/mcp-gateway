VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
GO      ?= go
OPA     ?= opa
# Distribution builds: PIE, reproducible paths. GOFLAGS (e.g. -mod=vendor)
# is passed through from the environment.
BUILDMODE ?= pie
GOBUILD    = $(GO) build -trimpath -buildmode=$(BUILDMODE)

SELINUX_DEVEL ?= /usr/share/selinux/devel/Makefile
SELINUXTYPE   ?= targeted

# Installation directories (override from the package build, e.g. the spec
# passes %{_libexecdir}, %{_distconfdir}, %{_unitdir}, ...).
PREFIX      ?= /usr
BINDIR      ?= $(PREFIX)/bin
SBINDIR     ?= $(PREFIX)/sbin
LIBEXECDIR  ?= $(PREFIX)/libexec
DATADIR     ?= $(PREFIX)/share
SYSCONFDIR  ?= /etc
# Where the default gateway.yaml goes: /usr/etc on openSUSE (UsrEtc),
# $(SYSCONFDIR) elsewhere.
DISTCONFDIR ?= $(SYSCONFDIR)
UNITDIR     ?= $(PREFIX)/lib/systemd/system
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d
POLKITDIR   ?= $(DATADIR)/polkit-1/rules.d
COCKPITDIR  ?= $(DATADIR)/cockpit/mcp-gateway
SELINUXDIR  ?= $(DATADIR)/selinux/packages/$(SELINUXTYPE)
# mcp_gateway.if, for modules of dedicated backend domains.
SELINUXINCDIR ?= $(DATADIR)/selinux/devel/include/services
DESTDIR     ?=

# mcp-gateway-admin finds mcp-gateway-tools in $(LIBEXECDIR)/mcp-gateway.
LDFLAGS := -X github.com/sdrahn/mcp-gateway/internal/version.Version=$(VERSION) \
	-X github.com/sdrahn/mcp-gateway/internal/version.LibexecDir=$(LIBEXECDIR)

BINARIES := bin/mcp-gateway bin/mcp-gateway-admin bin/mcp-gateway-tools bin/mcp-connect bin/mcp-gateway-notify bin/mcp-server-fs bin/mcp-server-exec

# Server setups (profiles/<name>, SELinux module selinux/mcp_<name>.te),
# packaged as mcp-gateway-profile-<name>.
PROFILES := systemd firewalld zypp suseconnect snapper

.PHONY: all build test vet lint fmt-check policy-check policy-test selinux check \
	install install-gateway install-tools install-selinux install-cockpit install-desktop install-fs-server install-demo install-exec-server \
	install-profiles clean

all: build

build: $(BINARIES)

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

selinux: selinux/mcp_gateway.pp $(PROFILES:%=selinux/mcp_%.pp)

selinux/mcp_gateway.pp: selinux/mcp_gateway.te selinux/mcp_gateway.if selinux/mcp_gateway.fc
	$(MAKE) -C selinux -f $(SELINUX_DEVEL) mcp_gateway.pp

# The setups' modules build on mcp_gateway.if, found next to them.
selinux/mcp_%.pp: selinux/mcp_%.te selinux/mcp_%.fc selinux/mcp_gateway.if
	$(MAKE) -C selinux -f $(SELINUX_DEVEL) mcp_$*.pp

# Everything CI runs, except lint and the SELinux build.
check: fmt-check vet test policy-check policy-test

# Everything but the SELinux module, the Cockpit page and the demo server,
# which distributions ship as subpackages.
install: install-gateway

install-gateway:
	install -Dm0755 bin/mcp-gateway $(DESTDIR)$(BINDIR)/mcp-gateway
	install -Dm0755 bin/mcp-gateway-admin $(DESTDIR)$(BINDIR)/mcp-gateway-admin
	install -Dm0755 bin/mcp-connect $(DESTDIR)$(BINDIR)/mcp-connect
	install -Dm0755 tools/mcp-policy-bundle $(DESTDIR)$(SBINDIR)/mcp-policy-bundle
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/opa
	install -m0644 packaging/opa/* $(DESTDIR)$(DATADIR)/mcp-gateway/opa/
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/mcs
	install -m0644 packaging/mcs/* $(DESTDIR)$(DATADIR)/mcp-gateway/mcs/
	install -Dm0644 config/gateway.yaml $(DESTDIR)$(DISTCONFDIR)/mcp-gateway/gateway.yaml
	install -d $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/servers.d
	install -d -m0700 $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/credentials
	install -d $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/bundle
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp
	install -m0644 $(filter-out %_test.rego,$(wildcard policy/mcp/*.rego)) $(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp/
	install -Dm0644 internal/policydata/rbac.schema.json $(DESTDIR)$(DATADIR)/mcp-gateway/schema/rbac.schema.json
	install -Dm0644 policy/mcp/rbac/data.json $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/policy/rbac/data.json
	install -Dm0644 systemd/mcp-gateway.service $(DESTDIR)$(UNITDIR)/mcp-gateway.service
	install -Dm0644 systemd/mcp-opa.service $(DESTDIR)$(UNITDIR)/mcp-opa.service
	install -Dm0644 packaging/sysusers.d/mcp-gateway.conf $(DESTDIR)$(SYSUSERSDIR)/mcp-gateway.conf
	install -Dm0644 packaging/tmpfiles.d/mcp-gateway.conf $(DESTDIR)$(TMPFILESDIR)/mcp-gateway.conf
	install -Dm0644 packaging/polkit/50-mcp-gateway.rules $(DESTDIR)$(POLKITDIR)/50-mcp-gateway.rules
	# The documentation, for the gateway-docs server: not as %doc, which
	# installations without documentation (rpm excludedocs) leave out.
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/docs/user-guide
	install -m0644 docs/user-guide/*.md $(DESTDIR)$(DATADIR)/mcp-gateway/docs/user-guide/
	install -m0644 docs/README.md docs/architecture.md CHANGELOG.md $(DESTDIR)$(DATADIR)/mcp-gateway/docs/
	# The gateway's diagnostics as the server gateway-admin, with its role.
	sed 's|@BINDIR@|$(BINDIR)|g' packaging/admin/gateway-admin.yaml.in \
		>$(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/gateway-admin.yaml
	chmod 0644 $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/gateway-admin.yaml
	install -Dm0644 packaging/admin/gateway-admin-roles.json \
		$(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp/profiles/gateway-admin/data.json

# The onboarding commands (mcp-gateway-admin inspect, profile, review).
install-tools:
	install -Dm0755 bin/mcp-gateway-tools $(DESTDIR)$(LIBEXECDIR)/mcp-gateway/mcp-gateway-tools

install-selinux: selinux
	install -d $(DESTDIR)$(SELINUXDIR)
	for m in gateway $(PROFILES); do \
		bzip2 -9 -c selinux/mcp_$$m.pp >$(DESTDIR)$(SELINUXDIR)/mcp_$$m.pp.bz2 && \
		chmod 0644 $(DESTDIR)$(SELINUXDIR)/mcp_$$m.pp.bz2 || exit 1; \
	done
	install -Dm0644 selinux/mcp_gateway.if $(DESTDIR)$(SELINUXINCDIR)/mcp_gateway.if

# Server setups: definition (active once installed), shipped roles, polkit
# rule and service account where the setup has them.
install-profiles:
	for p in $(PROFILES); do \
		install -Dm0644 profiles/$$p/$$p.yaml $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/$$p.yaml && \
		install -Dm0644 profiles/$$p/roles.json $(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp/profiles/$$p/data.json && \
		{ [ ! -f profiles/$$p/polkit.rules ] || \
		  install -Dm0644 profiles/$$p/polkit.rules $(DESTDIR)$(POLKITDIR)/60-mcp-gateway-$$p.rules; } && \
		{ [ ! -f profiles/$$p/sysusers.conf ] || \
		  install -Dm0644 profiles/$$p/sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/mcp-gateway-profile-$$p.conf; } || exit 1; \
	done
	install -Dm0644 profiles/zypp/zypp-privileged.yaml $(DESTDIR)$(DATADIR)/mcp-gateway/profiles/zypp-privileged.yaml
	install -Dm0644 profiles/snapper/snapper-privileged.yaml $(DESTDIR)$(DATADIR)/mcp-gateway/profiles/snapper-privileged.yaml

install-cockpit:
	install -d $(DESTDIR)$(COCKPITDIR)
	install -m0644 cockpit/mcp-gateway/* $(DESTDIR)$(COCKPITDIR)/

# Desktop notification agent, started with graphical sessions (XDG
# autostart); it exits for users without access to the control socket.
install-desktop:
	install -Dm0755 bin/mcp-gateway-notify $(DESTDIR)$(BINDIR)/mcp-gateway-notify
	install -Dm0644 packaging/desktop/mcp-gateway-notify.desktop $(DESTDIR)$(SYSCONFDIR)/xdg/autostart/mcp-gateway-notify.desktop

# The file server, as the server "fs".
install-fs-server:
	install -Dm0755 bin/mcp-server-fs $(DESTDIR)$(LIBEXECDIR)/mcp-servers/mcp-server-fs
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d
	sed 's|@LIBEXECDIR@|$(LIBEXECDIR)|g' packaging/fs-server/fs.yaml.in \
		>$(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/fs-demo.yaml
	chmod 0644 $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/fs-demo.yaml
	# The gateway's documentation as the server gateway-docs, with its role.
	sed -e 's|@LIBEXECDIR@|$(LIBEXECDIR)|g' -e 's|@DATADIR@|$(DATADIR)|g' packaging/fs-server/gateway-docs.yaml.in \
		>$(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/gateway-docs.yaml
	chmod 0644 $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/gateway-docs.yaml
	install -Dm0644 packaging/fs-server/gateway-docs-roles.json \
		$(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp/profiles/gateway-docs/data.json

install-demo: install-fs-server

# The command server, as the server "exec": no commands until the
# administrator puts them into /etc/mcp-gateway/exec.d (examples in
# $(DATADIR)/mcp-gateway/exec).
install-exec-server:
	install -Dm0755 bin/mcp-server-exec $(DESTDIR)$(LIBEXECDIR)/mcp-servers/mcp-server-exec
	install -d $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d
	sed -e 's|@LIBEXECDIR@|$(LIBEXECDIR)|g' -e 's|@DATADIR@|$(DATADIR)|g' packaging/exec-server/exec.yaml.in \
		>$(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/exec.yaml
	chmod 0644 $(DESTDIR)$(DATADIR)/mcp-gateway/servers.d/exec.yaml
	install -Dm0644 packaging/exec-server/examples.yaml $(DESTDIR)$(DATADIR)/mcp-gateway/exec/examples.yaml
	install -d $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/exec.d
	install -Dm0644 packaging/exec-server/exec-roles.json \
		$(DESTDIR)$(DATADIR)/mcp-gateway/policy/mcp/profiles/exec/data.json

clean:
	rm -rf bin selinux/tmp selinux/*.pp $(PROFILES:%=selinux/mcp_%.if)
