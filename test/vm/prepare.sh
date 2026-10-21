#!/bin/bash
# Prepares the CI VM for the functional tests (run-vm.sh runs it as root):
# the tests' dependencies, OPA, and the packages built from this tree,
# mcp-gateway-tests among them. On a product system (openQA), the
# packages come from its repositories instead, and the tests start from
# there (/usr/libexec/mcp-gateway/tests/run-tests.sh).
#
# Usage: prepare.sh <dir>, with <dir>/rpms (the packages) and <dir>/opa
# (OPA, used if the distribution has no opa package).
set -euo pipefail
dir=$1
die() {
	echo "FATAL: $*"
	exit 1
}

# zypper's output only when it fails: which package or repository.
zypper -n --gpg-auto-import-keys ref >/tmp/zypper.log 2>&1 ||
	{ tail -n 30 /tmp/zypper.log; die "refreshing the repositories failed"; }
# What mcp-gateway-tests requires, and the policy development files.
deps="audit policycoreutils selinux-tools polkit rpm-build jq curl make"
# shellcheck disable=SC2086 # deps is a list of package names
if ! zypper -n in --no-recommends $deps selinux-policy-targeted selinux-policy-devel >/tmp/zypper.log 2>&1; then
	# The image's selinux-policy can be newer than any selinux-policy-devel
	# in the repositories (Leap 16.0 on 2026-10-16: git412 installed,
	# devel only at git405, which requires its own policy): the policy at
	# the devel package's version, then, so that both match.
	v=$(zypper -n --no-refresh info selinux-policy-devel | sed -n 's/^Version *: *//p' | head -n 1)
	[ -n "$v" ] || { tail -n 30 /tmp/zypper.log; die "installing dependencies failed"; }
	had=$(rpm -q --qf '%{version}-%{release}' selinux-policy 2>/dev/null || echo none)
	# shellcheck disable=SC2086
	zypper -n in --no-recommends --oldpackage $deps "selinux-policy=$v" "selinux-policy-targeted=$v" \
		"selinux-policy-devel=$v" >/tmp/zypper.log 2>&1 ||
		{ tail -n 30 /tmp/zypper.log; die "installing dependencies failed"; }
	echo "  selinux-policy $v, the devel package's version (the image had $had)"
fi
if zypper -n in --no-recommends opa >/dev/null 2>&1; then
	echo "  opa: distribution package"
else
	install -m 0755 "$dir/opa" /usr/bin/opa
	restorecon /usr/bin/opa
	echo "  opa: release binary ($(opa version | head -1))"
fi
rpm -Uvh --nodeps "$dir"/rpms/mcp-gateway-[0-9]*.rpm "$dir"/rpms/mcp-gateway-selinux-*.rpm \
	"$dir"/rpms/mcp-gateway-fs-server-*.rpm "$dir"/rpms/mcp-gateway-exec-server-*.rpm \
	"$dir"/rpms/mcp-gateway-tools-*.rpm "$dir"/rpms/mcp-gateway-tests-*.rpm ||
	die "installing the packages failed"
