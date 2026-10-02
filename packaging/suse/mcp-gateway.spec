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
Version:        0.5.0
Release:        0
Summary:        Policy-enforcing gateway for local MCP servers
# MIT for mcp-gateway; the others for the vendored Go modules linked in.
License:        MIT AND Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause
Group:          Productivity/Networking/Security
URL:            https://github.com/sdrahn/mcp-gateway
Source0:        %{name}-%{version}.tar.gz
Source1:        vendor.tar.gz
Source99:       %{name}-rpmlintrc
BuildRequires:  bzip2
BuildRequires:  gcc
BuildRequires:  golang(API) >= 1.24
BuildRequires:  make
BuildRequires:  pkgconfig(systemd)
# Owns /usr/share/polkit-1/rules.d, where the rules file goes (the build
# root of SLES 16.0 has no other owner; the file list check needs one).
BuildRequires:  polkit
BuildRequires:  selinux-policy-devel
BuildRequires:  sysuser-tools
BuildRequires:  systemd-rpm-macros
Requires:       opa
Requires:       polkit
# mcp-policy-bundle -G creates signing keys with openssl.
Recommends:     openssl
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
License:        MIT
Group:          System/Management
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
# %%selinux_requires asks for the build's selinux-policy version and
# release, so a build against a rebuild or maintenance update of the same
# policy version cannot be installed on a host without that update. The
# module needs the policy version only: drop the release.
%{?_selinux_policy_version:%global _selinux_policy_version %(echo '%{_selinux_policy_version}' | cut -d- -f1)}
%{?selinux_requires}

%description selinux
SELinux domains for mcp-gateway, its OPA policy engine and the MCP
servers it starts, including the rule that MCP servers can never reach
the gateway's or OPA's sockets.

%package cockpit
Summary:        Cockpit page for mcp-gateway
License:        MIT
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Requires:       cockpit-bridge

%description cockpit
A Cockpit page for mcp-gateway, as the logged-in user: decide on pending
approvals and revoke grants, see MCP servers and stop their instances,
edit role bindings and view the audit records.

%package desktop
Summary:        Desktop notifications for mcp-gateway approvals
Group:          System/Management
Requires:       %{name} = %{version}
Requires:       xdg-utils

%description desktop
Shows a desktop notification in graphical sessions for every mcp-gateway
approval the logged-in user may decide on, with an action opening the
approval page. Started with the session (XDG autostart); does nothing for
users without access to the gateway.

%package demo-server
Summary:        Demo filesystem MCP server for mcp-gateway
Group:          Development/Tools/Other
Requires:       %{name} = %{version}

%description demo-server
A minimal stdio MCP server offering file tools, resources and a prompt
on the connecting user's home directory, registered with mcp-gateway as
server "fs". For trying out and testing the gateway.

%package profile-systemd
Summary:        systemd-mcp behind mcp-gateway
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Recommends:     systemd-mcp
# systemd-mcp offers get_man_page (in the roles) only if man is installed.
Recommends:     man
%sysusers_requires

%description profile-systemd
Sets up systemd-mcp (https://github.com/openSUSE/systemd-mcp) behind
mcp-gateway: the server definition, the account mcp-sysmgmt (a member
of systemd-journal), a polkit rule letting that account manage units,
and the roles systemd-reader and systemd-operator to bind users to.
Changes to units need an approval.

%package profile-firewalld
Summary:        firewalld-mcp behind mcp-gateway
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Recommends:     firewalld-mcp
%sysusers_requires

%description profile-firewalld
Sets up firewalld-mcp (https://github.com/janvhs/firewalld-mcp) behind
mcp-gateway: the server definition, the account mcp-sysmgmt, a polkit
rule letting it read the firewall configuration, and the role
firewalld-reader.

%package profile-zypp
Summary:        mcp-server-zypp behind mcp-gateway
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Recommends:     mcp-server-zypp
%sysusers_requires

%description profile-zypp
Sets up mcp-server-zypp (https://github.com/openSUSE/mcp-server-zypp)
behind mcp-gateway: searching packages, dependencies and updates and
planning installations as the account mcp-sysmgmt, in the sandbox (role
zypp-reader). A definition as a privileged server, which can install and
remove packages with approval (role zypp-installer), is included for
the administrator to enable.

%package profile-snapper
Summary:        mcp-server-snapper behind mcp-gateway
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Recommends:     mcp-server-snapper
%sysusers_requires

%description profile-snapper
Sets up mcp-server-snapper (https://github.com/aschnell/mcp-server-snapper)
behind mcp-gateway: listing snapper configs and snapshots and creating
and deleting snapshots as the account mcp-snapper, in the sandbox (roles
snapper-reader and snapper-operator). snapperd allows the account only
the configs whose ALLOW_USERS name it. A definition as a privileged
server, which can also change configs and roll back, is included for the
administrator to enable.

%package profile-suseconnect
Summary:        suseconnect-mcp behind mcp-gateway
Group:          System/Management
BuildArch:      noarch
Requires:       %{name} = %{version}
Recommends:     mcp-server-suseconnect

%description profile-suseconnect
Sets up suseconnect-mcp (package mcp-server-suseconnect) behind
mcp-gateway: the server definition (root, in the sandbox, with network
access and write access to the system credentials) and the roles
suseconnect-reader and suseconnect-admin. Changes to the registration
need an approval.

%prep
%autosetup -p1 -a1

%build
export GOFLAGS="-mod=vendor"
%make_build build VERSION=%{version}
make selinux
%sysusers_generate_pre packaging/sysusers.d/mcp-gateway.conf %{name} %{name}.conf
%sysusers_generate_pre profiles/systemd/sysusers.conf %{name}-profile-systemd %{name}-profile-systemd.conf
%sysusers_generate_pre profiles/firewalld/sysusers.conf %{name}-profile-firewalld %{name}-profile-firewalld.conf
%sysusers_generate_pre profiles/zypp/sysusers.conf %{name}-profile-zypp %{name}-profile-zypp.conf
%sysusers_generate_pre profiles/snapper/sysusers.conf %{name}-profile-snapper %{name}-profile-snapper.conf

%install
%make_install install install-selinux install-cockpit install-desktop install-demo install-profiles \
    PREFIX=%{_prefix} BINDIR=%{_bindir} SBINDIR=%{_sbindir} LIBEXECDIR=%{_libexecdir} \
    DATADIR=%{_datadir} SYSCONFDIR=%{_sysconfdir} DISTCONFDIR=%{_distconfdir} \
    UNITDIR=%{_unitdir} SYSUSERSDIR=%{_sysusersdir} TMPFILESDIR=%{_tmpfilesdir} \
    SELINUXDIR=%{_datadir}/selinux/packages/%{selinuxtype}

%check
export GOFLAGS="-mod=vendor"
go test ./internal/... ./profiles/...

%pre -f %{name}.pre
%service_add_pre mcp-gateway.service mcp-opa.service

%post
%tmpfiles_create %{_tmpfilesdir}/%{name}.conf
%service_add_post mcp-gateway.service mcp-opa.service

%preun
%service_del_preun mcp-gateway.service mcp-opa.service

%postun
# The gateway is not restarted on update: an update made through a
# privileged MCP server (package installation) would wait for itself. It
# logs, and the Cockpit page shows, that a restart is pending.
%service_del_postun_without_restart mcp-gateway.service
%service_del_postun mcp-opa.service

%pre profile-systemd -f %{name}-profile-systemd.pre

%pre profile-firewalld -f %{name}-profile-firewalld.pre

%pre profile-zypp -f %{name}-profile-zypp.pre

%pre profile-snapper -f %{name}-profile-snapper.pre

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
# One line: the macro takes no continued arguments. The setup modules
# (mcp-gateway-profile-*) come with this package.
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2 %{_datadir}/selinux/packages/%{selinuxtype}/mcp_systemd.pp.bz2 %{_datadir}/selinux/packages/%{selinuxtype}/mcp_firewalld.pp.bz2 %{_datadir}/selinux/packages/%{selinuxtype}/mcp_zypp.pp.bz2 %{_datadir}/selinux/packages/%{selinuxtype}/mcp_suseconnect.pp.bz2 %{_datadir}/selinux/packages/%{selinuxtype}/mcp_snapper.pp.bz2

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} mcp_systemd mcp_firewalld mcp_zypp mcp_suseconnect mcp_snapper %{modulename}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files
%license LICENSE
%doc README.md docs/architecture.md
%{_bindir}/mcp-gateway
%{_bindir}/mcp-connect
%{_sbindir}/mcp-policy-bundle
%dir %{_sysconfdir}/mcp-gateway
%dir %{_sysconfdir}/mcp-gateway/servers.d
%dir %attr(0700,root,root) %{_sysconfdir}/mcp-gateway/credentials
%dir %{_sysconfdir}/mcp-gateway/bundle
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
%dir %{_datadir}/mcp-gateway/policy
%dir %{_datadir}/mcp-gateway/policy/mcp
%{_datadir}/mcp-gateway/policy/mcp/*.rego
%dir %{_datadir}/mcp-gateway/policy/mcp/profiles
%{_datadir}/mcp-gateway/opa
%{_datadir}/mcp-gateway/mcs
%{_datadir}/mcp-gateway/schema
%{_unitdir}/mcp-gateway.service
%{_unitdir}/mcp-opa.service
%{_sysusersdir}/%{name}.conf
%{_tmpfilesdir}/%{name}.conf
%{_datadir}/polkit-1/rules.d/50-mcp-gateway.rules

%files selinux
%dir %{_datadir}/selinux/packages/%{selinuxtype}
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/packages/%{selinuxtype}/mcp_systemd.pp.bz2
%{_datadir}/selinux/packages/%{selinuxtype}/mcp_firewalld.pp.bz2
%{_datadir}/selinux/packages/%{selinuxtype}/mcp_zypp.pp.bz2
%{_datadir}/selinux/packages/%{selinuxtype}/mcp_suseconnect.pp.bz2
%{_datadir}/selinux/packages/%{selinuxtype}/mcp_snapper.pp.bz2
%{_datadir}/selinux/devel/include/services/%{modulename}.if

%files cockpit
%dir %{_datadir}/cockpit
%{_datadir}/cockpit/mcp-gateway

%files desktop
%{_bindir}/mcp-gateway-notify
%config %{_sysconfdir}/xdg/autostart/mcp-gateway-notify.desktop

%files demo-server
%dir %{_libexecdir}/mcp-servers
%{_libexecdir}/mcp-servers/mcp-fs-demo
%{_datadir}/mcp-gateway/servers.d/fs-demo.yaml

%files profile-systemd
%{_datadir}/mcp-gateway/servers.d/systemd.yaml
%{_datadir}/mcp-gateway/policy/mcp/profiles/systemd
%{_datadir}/polkit-1/rules.d/60-mcp-gateway-systemd.rules
%{_sysusersdir}/%{name}-profile-systemd.conf

%files profile-firewalld
%{_datadir}/mcp-gateway/servers.d/firewalld.yaml
%{_datadir}/mcp-gateway/policy/mcp/profiles/firewalld
%{_datadir}/polkit-1/rules.d/60-mcp-gateway-firewalld.rules
%{_sysusersdir}/%{name}-profile-firewalld.conf

%files profile-zypp
%{_datadir}/mcp-gateway/servers.d/zypp.yaml
%{_datadir}/mcp-gateway/policy/mcp/profiles/zypp
%{_sysusersdir}/%{name}-profile-zypp.conf
%dir %{_datadir}/mcp-gateway/profiles
%{_datadir}/mcp-gateway/profiles/zypp-privileged.yaml

%files profile-snapper
%{_datadir}/mcp-gateway/servers.d/snapper.yaml
%{_datadir}/mcp-gateway/policy/mcp/profiles/snapper
%{_sysusersdir}/%{name}-profile-snapper.conf
%dir %{_datadir}/mcp-gateway/profiles
%{_datadir}/mcp-gateway/profiles/snapper-privileged.yaml

%files profile-suseconnect
%{_datadir}/mcp-gateway/servers.d/suseconnect.yaml
%{_datadir}/mcp-gateway/policy/mcp/profiles/suseconnect

%changelog
