VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
GO      ?= go
OPA     ?= opa
LDFLAGS := -X github.com/sdrahn/mcp-gateway/internal/version.Version=$(VERSION)

SELINUX_DEVEL ?= /usr/share/selinux/devel/Makefile

PREFIX     ?= /usr
SYSCONFDIR ?= /etc
UNITDIR    ?= $(PREFIX)/lib/systemd/system
DESTDIR    ?=

BINARIES := bin/mcp-gateway bin/mcp-connect

.PHONY: all build test vet lint fmt-check policy-check policy-test selinux check install clean

all: build

build: $(BINARIES)

bin/%: FORCE
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/$*

FORCE:

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

selinux:
	$(MAKE) -C selinux -f $(SELINUX_DEVEL) mcp_gateway.pp

# Everything CI runs, except lint and the SELinux build.
check: fmt-check vet test policy-check policy-test

install: build
	install -Dm0755 bin/mcp-gateway $(DESTDIR)$(PREFIX)/bin/mcp-gateway
	install -Dm0755 bin/mcp-connect $(DESTDIR)$(PREFIX)/bin/mcp-connect
	install -Dm0644 config/gateway.yaml $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/gateway.yaml
	install -d $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/servers.d
	install -d $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/policy
	cp -r policy/. $(DESTDIR)$(SYSCONFDIR)/mcp-gateway/policy/
	install -Dm0644 systemd/mcp-gateway.service $(DESTDIR)$(UNITDIR)/mcp-gateway.service
	install -Dm0644 systemd/mcp-opa.service $(DESTDIR)$(UNITDIR)/mcp-opa.service
	install -Dm0644 packaging/sysusers.d/mcp-gateway.conf $(DESTDIR)$(PREFIX)/lib/sysusers.d/mcp-gateway.conf
	install -Dm0644 packaging/polkit/50-mcp-gateway.rules $(DESTDIR)$(PREFIX)/share/polkit-1/rules.d/50-mcp-gateway.rules

clean:
	rm -rf bin selinux/tmp selinux/*.pp
