#
# spec file for package mcp-gateway
#
# Built on the Open Build Service for openSUSE Tumbleweed, Leap and SLES;
# see packaging/suse/README.md. Sources: the tarball and vendor.tar.gz
# (Go modules, OBS builds are offline) come from the _service file.
#

%define selinuxtype targeted
%define modulename mcp_gateway
# /usr/etc (UsrEtc) where the distribution has it, else /etc.
%{!?_distconfdir: %global _distconfdir %{_sysconfdir}}

Name:           mcp-gateway
Version:        0.1.0
Release:        0
Summary:        Policy-enforcing gateway for local MCP servers
# FIXME: the repository has no LICENSE file yet; set the actual license
# and add a %%license line to %%files.
License:        MIT
Group:          Productivity/Networking/Security
URL:            https://github.com/sdrahn/mcp-gateway
Source0:        %{name}-%{version}.tar.gz
Source1:        vendor.tar.gz
Source99:       %{name}-rpmlintrc
BuildRequires:  bzip2
BuildRequires:  gcc
BuildRequires:  golang(API) >= 1.24
BuildRequires:  make
BuildRequires:  selinux-policy-devel
BuildRequires:  sysuser-tools
BuildRequires:  systemd-rpm-macros
Requires:       opa
Requires:       polkit
Requires:       (%{name}-selinux if selinux-policy-%{selinuxtype})
Suggests:       %{name}-cockpit
%sysusers_requires
%{?systemd_ordering}

%description
mcp-gateway makes MCP (Model Context Protocol) servers that only speak
stdio available to local clients (unix socket) and remote clients (MCP
Streamable HTTP with OAuth bearer tokens). Every request is decided by
OPA policy (RBAC, argument constraints), sensitive calls can require a
human approval, and each MCP server instance runs as a confined systemd
transient unit in its own SELinux domain.

%package selinux
Summary:        SELinux policy module for mcp-gateway
Group:          System/Management
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
%{?selinux_requires}

%description selinux
SELinux domains for mcp-gateway, its OPA policy engine and the MCP
servers it starts, including the rule that MCP servers can never reach
the gateway's or OPA's sockets.

%package cockpit
Summary:        Cockpit page for mcp-gateway approvals
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Requires:       cockpit-bridge

%description cockpit
A Cockpit page to decide on pending mcp-gateway approvals and to list and
revoke grants, as the logged-in user.

%package demo-server
Summary:        Demo filesystem MCP server for mcp-gateway
Group:          Development/Tools/Other
Requires:       %{name} = %{version}

%description demo-server
A minimal stdio MCP server offering file tools, resources and a prompt
on the connecting user's home directory, registered with mcp-gateway as
server "fs". For trying out and testing the gateway.

%prep
%autosetup -p1 -a1

%build
export GOFLAGS="-mod=vendor"
%make_build build VERSION=%{version}
make selinux
%sysusers_generate_pre packaging/sysusers.d/mcp-gateway.conf %{name} %{name}.conf

%install
%make_install install install-selinux install-cockpit install-demo \
    PREFIX=%{_prefix} BINDIR=%{_bindir} LIBEXECDIR=%{_libexecdir} \
    DATADIR=%{_datadir} SYSCONFDIR=%{_sysconfdir} DISTCONFDIR=%{_distconfdir} \
    UNITDIR=%{_unitdir} SYSUSERSDIR=%{_sysusersdir} \
    SELINUXDIR=%{_datadir}/selinux/packages/%{selinuxtype}

%check
export GOFLAGS="-mod=vendor"
go test ./internal/...

%pre -f %{name}.pre
%service_add_pre mcp-gateway.service mcp-opa.service

%post
%service_add_post mcp-gateway.service mcp-opa.service

%preun
%service_del_preun mcp-gateway.service mcp-opa.service

%postun
%service_del_postun mcp-gateway.service mcp-opa.service

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files
%doc README.md docs/architecture.md
%{_bindir}/mcp-gateway
%{_bindir}/mcp-connect
%dir %{_sysconfdir}/mcp-gateway
%dir %{_sysconfdir}/mcp-gateway/servers.d
%dir %{_sysconfdir}/mcp-gateway/policy
%dir %{_sysconfdir}/mcp-gateway/policy/rbac
%config(noreplace) %{_sysconfdir}/mcp-gateway/policy/rbac/data.json
%if "%{_distconfdir}" == "%{_sysconfdir}"
%config(noreplace) %{_sysconfdir}/mcp-gateway/gateway.yaml
%else
%dir %{_distconfdir}/mcp-gateway
%{_distconfdir}/mcp-gateway/gateway.yaml
%endif
%dir %{_datadir}/mcp-gateway
%dir %{_datadir}/mcp-gateway/servers.d
%{_datadir}/mcp-gateway/policy
%{_unitdir}/mcp-gateway.service
%{_unitdir}/mcp-opa.service
%{_sysusersdir}/%{name}.conf
%{_datadir}/polkit-1/rules.d/50-mcp-gateway.rules

%files selinux
%dir %{_datadir}/selinux/packages/%{selinuxtype}
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%files cockpit
%dir %{_datadir}/cockpit
%{_datadir}/cockpit/mcp-gateway

%files demo-server
%dir %{_libexecdir}/mcp-servers
%{_libexecdir}/mcp-servers/mcp-fs-demo
%{_datadir}/mcp-gateway/servers.d/fs-demo.yaml

%changelog
