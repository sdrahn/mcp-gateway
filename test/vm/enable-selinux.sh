#!/bin/bash
# Installs and enables SELinux (targeted, enforcing) on an openSUSE system
# that does not have it yet, as openSUSE documents it: the policy, the
# kernel command line, and a relabel on the next boot. Runs as root; the
# caller reboots.
set -euo pipefail
zypper -n --gpg-auto-import-keys ref >/dev/null
zypper -n in --no-recommends selinux-policy-targeted policycoreutils selinux-autorelabel \
	container-selinux >/dev/null 2>&1 ||
	zypper -n in --no-recommends selinux-policy-targeted policycoreutils selinux-autorelabel >/dev/null
sed -i 's/^SELINUX=.*/SELINUX=enforcing/; s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config
grep -q '^SELINUX=' /etc/selinux/config || echo 'SELINUX=enforcing' >>/etc/selinux/config
if [ -f /etc/default/grub ]; then
	sed -i -E 's/\b(security|selinux|enforcing)=[^ "]*//g' /etc/default/grub
	sed -i -E 's/^(GRUB_CMDLINE_LINUX_DEFAULT=")/\1security=selinux selinux=1 /' /etc/default/grub
	if command -v update-bootloader >/dev/null; then
		update-bootloader --refresh
	else
		grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
fi
touch /.autorelabel
