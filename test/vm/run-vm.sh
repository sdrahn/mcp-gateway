#!/bin/bash
# Boots an openSUSE cloud image with QEMU/KVM, installs the packages built
# from this tree and runs test/vm/run-tests.sh in it as root.
#
# Usage: test/vm/run-vm.sh <rpm dir> <mcpcall binary> <opa binary>
#
# Environment:
#   IMAGE_URL  cloud image (default: openSUSE Tumbleweed Minimal-VM, Cloud)
#   WORK       working directory (default: a new temporary directory); the
#              serial console log and test output are left there
#
# If SELinux is not enforcing in the image, it is installed and enabled
# first (with a relabelling reboot). Needs qemu-system-x86_64, qemu-img,
# cloud-localds (cloud-image-utils), ssh and /dev/kvm.
set -euo pipefail

[ $# = 3 ] || {
	echo "usage: $0 <rpm dir> <mcpcall binary> <opa binary>" >&2
	exit 2
}
rpms=$(realpath "$1")
mcpcall=$(realpath "$2")
opa=$(realpath "$3")
here=$(cd "$(dirname "$0")" && pwd)
image_url=${IMAGE_URL:-https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2}
work=${WORK:-$(mktemp -d)}
mkdir -p "$work"
port=2222
log() { echo "[$(date +%T)] $*"; }

[ -w /dev/kvm ] || {
	echo "/dev/kvm is not available or not writable" >&2
	exit 1
}

log "work directory: $work"
if [ ! -f "$work/base.qcow2" ]; then
	log "downloading $image_url"
	curl -fsSL --retry 3 -o "$work/base.qcow2" "$image_url"
fi
qemu-img create -q -f qcow2 -b "$work/base.qcow2" -F qcow2 "$work/disk.qcow2" 20G

ssh-keygen -q -t ed25519 -N '' -f "$work/key" <<<y >/dev/null
cat >"$work/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
growpart:
  mode: auto
  devices: ["/"]
EOF
printf 'instance-id: mcpgw-vmtest\nlocal-hostname: mcpgw-vmtest\n' >"$work/meta-data"
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"

ssh_opts=(-i "$work/key" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5 -o ServerAliveInterval=15)
vm() { ssh "${ssh_opts[@]}" root@127.0.0.1 "$@"; }

log "booting the VM"
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 4096 \
	-drive file="$work/disk.qcow2",if=virtio \
	-drive file="$work/seed.img",if=virtio,format=raw \
	-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$port-:22 \
	-display none -serial file:"$work/console.log" \
	-pidfile "$work/qemu.pid" -daemonize
trap 'kill "$(cat "$work/qemu.pid" 2>/dev/null)" 2>/dev/null || true' EXIT

wait_ssh() {
	local i
	for i in $(seq 120); do
		if vm true 2>/dev/null; then
			log "ssh is up"
			return
		fi
		sleep 5
	done
	echo "the VM did not come up; console:" >&2
	tail -50 "$work/console.log" >&2
	exit 1
}
wait_ssh
vm 'cloud-init status --wait >/dev/null 2>&1 || true'

if [ "$(vm 'getenforce 2>/dev/null || echo Missing')" != Enforcing ]; then
	log "enabling SELinux (state: $(vm 'getenforce 2>/dev/null || echo missing'))"
	vm bash -s <"$here/enable-selinux.sh"
	vm 'systemctl reboot' || true
	sleep 20
	wait_ssh
	# The first boot may relabel and reboot once more.
	for _ in $(seq 30); do
		[ "$(vm 'getenforce 2>/dev/null' || true)" = Enforcing ] && break
		sleep 10
		wait_ssh
	done
fi

log "copying the test payload"
vm 'rm -rf /root/vmtest && mkdir -p /root/vmtest/rpms'
scp -q -i "$work/key" -P "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	"$here/run-tests.sh" "$mcpcall" "$opa" root@127.0.0.1:/root/vmtest/
scp -q -i "$work/key" -P "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	"$rpms"/*.rpm root@127.0.0.1:/root/vmtest/rpms/

log "running the tests"
set +e
vm 'bash /root/vmtest/run-tests.sh' 2>&1 | tee "$work/test.log"
status=${PIPESTATUS[0]}
set -e
log "tests exited with $status"
exit "$status"
