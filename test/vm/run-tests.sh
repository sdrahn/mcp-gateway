#!/bin/bash
# Property tests of the installed gateway on a real openSUSE system with
# SELinux enforcing: domains, MCS pairs, polkit, credentials, kernel audit
# and no SELinux denials. Runs inside the VM as root (test/vm/run-vm.sh
# copies it there), with, next to it:
#   rpms/     mcp-gateway, mcp-gateway-selinux and mcp-gateway-demo-server
#   mcpcall   the test client (test/vm/mcpcall)
#   opa       OPA binary, used if the distribution has no opa package
# Every check prints PASS or FAIL; the script exits 1 if any failed.
set -u
dir=$(cd "$(dirname "$0")" && pwd)
failed=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failed=1; }
check() { # check <description> <command...>
	local desc=$1
	shift
	if "$@"; then pass "$desc"; else fail "$desc"; fi
}
section() { printf '\n=== %s\n' "$*"; }
die() {
	echo "FATAL: $*"
	exit 1
}

# --- helpers ---------------------------------------------------------------

label() { ps -o label= -p "$1" 2>/dev/null | tr -d ' '; }     # context of a process
proc_user() { ps -o user= -p "$1" 2>/dev/null | tr -d ' '; }  # owner of a process
file_label() { stat -c %C "$1" 2>/dev/null; }                  # context of a file
has_type() { [[ $1 == *":$2:"* ]]; }                           # has_type <context> <type>
proc_has_type() { has_type "$(label "$1")" "$2"; }             # proc_has_type <pid> <type>
file_has_type() { has_type "$(file_label "$1")" "$2"; }        # file_has_type <path> <type>
categories() { sed -n 's/.*:s0:\(c[0-9]*,c[0-9]*\)$/\1/p' <<<"$1"; } # "c801,c942"
in_range() { # in_range <cA,cB> <low> <high>
	local c
	[ -n "$1" ] || return 1
	for c in ${1//,/ }; do
		c=${c#c}
		[ "$c" -ge "$2" ] && [ "$c" -le "$3" ] || return 1
	done
}

# call <user> <mcpcall args...>: a request as <user>; sets $out and $rc
# (0 success, 1 request error, 2 tool error).
call() {
	local user=$1
	shift
	out=$(runuser -u "$user" -- /usr/local/bin/mcpcall --server fs "$@" 2>&1)
	rc=$?
	echo "  [$user] rc=$rc ${out:0:300}"
}
tool() { call "$1" --method tools/call --params "{\"name\":\"$2\",\"arguments\":$3}"; }
succeeded_with() { [ "$rc" = 0 ] && grep -qF -- "$1" <<<"$out"; }
# A refusal by the gateway, not a failure to reach it.
failed_without() { [ "$rc" != 0 ] && ! grep -qF -- "$1" <<<"$out" && ! grep -qE "dial unix|backend unavailable" <<<"$out"; }
tool_error_with() { [ "$rc" = 2 ] && grep -qF -- "$1" <<<"$out"; }

# instance_pid <user>: main PID of the running fs instance of <user>.
instance_pid() {
	local unit pid
	for unit in $(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-fs-*' | awk '{print $1}'); do
		pid=$(systemctl show -p MainPID --value "$unit")
		if [ "$pid" != 0 ] && [ "$(proc_user "$pid")" = "$1" ]; then
			echo "$pid"
			return
		fi
	done
}

as_gateway_user_fails() { ! runuser -u mcp-gateway -- "$@" >/dev/null 2>&1; }
# audit_since <types>: raw kernel audit records of <types> since the
# packages were installed ($since, epoch seconds). ausearch -ts takes
# locale-formatted dates; filtering on the record timestamps avoids that.
# --input-logs: without a terminal, ausearch would read stdin instead.
audit_since() {
	local line ts
	ausearch --input-logs -m "$1" -ts yesterday --raw 2>/dev/null | while IFS= read -r line; do
		ts=${line#*msg=audit(}
		ts=${ts%%.*}
		[[ $ts =~ ^[0-9]+$ ]] && [ "$ts" -ge "$since" ] && printf '%s\n' "$line"
	done
}
audited() { audit_since TRUSTED_APP | grep -q "op=$1"; }
audit_log_works() { audit_since SERVICE_START | grep -q 'unit=mcp-gateway'; }
journal_has_audit() { journalctl -u mcp-gateway.service -o cat | grep -qF '"audit":true'; }
no_mcp_denials() { ! grep -E 'mcpgw_|mcpopa_|mcpsrv_|mcp_port_t' <<<"$avc" | grep -q .; }

# --- tests -------------------------------------------------------------------

section "System"
grep PRETTY_NAME /etc/os-release
uname -r
check "SELinux is enforcing" test "$(getenforce)" = Enforcing
sestatus | grep -E 'policy name|mode'

section "Install"
zypper -n --gpg-auto-import-keys ref >/dev/null
zypper -n in --no-recommends audit policycoreutils selinux-policy-targeted polkit >/dev/null ||
	die "installing dependencies failed"
systemctl enable --now auditd
if zypper -n in --no-recommends opa >/dev/null 2>&1; then
	echo "  opa: distribution package"
else
	install -m 0755 "$dir/opa" /usr/bin/opa
	restorecon /usr/bin/opa
	echo "  opa: release binary ($(opa version | head -1))"
fi
install -m 0755 "$dir/mcpcall" /usr/local/bin/mcpcall
since=$(date +%s)
rpm -Uvh --nodeps "$dir"/rpms/mcp-gateway-[0-9]*.rpm "$dir"/rpms/mcp-gateway-selinux-*.rpm \
	"$dir"/rpms/mcp-gateway-demo-server-*.rpm || die "installing the packages failed"
check "SELinux module mcp_gateway is loaded" bash -c 'semodule -l | grep -qx mcp_gateway'
# Labels as the packages leave them (no restorecon): a wrong label here is
# a packaging bug.
for f in /usr/bin/mcp-gateway:mcpgw_exec_t /usr/libexec/mcp-servers/mcp-fs-demo:mcpsrv_fs_exec_t \
	/etc/mcp-gateway/credentials:mcpgw_cred_t /usr/etc/mcp-gateway/gateway.yaml:mcpgw_etc_t; do
	echo "  $(file_label "${f%%:*}") ${f%%:*}"
	check "${f%%:*} is labeled ${f##*:}" file_has_type "${f%%:*}" "${f##*:}"
done

section "Users and policy"
for u in alice bob; do
	useradd -m "$u"
	usermod -aG mcp-users "$u"
	runuser -u "$u" -- sh -c "umask 077; echo '$u secret' > /home/$u/secret.txt"
done
cat >/etc/mcp-gateway/policy/rbac/data.json <<'EOF'
{
  "roles": {"tester": {"permissions": [
    {"server": "fs", "tool": "read_*"},
    {"server": "fs", "tool": "list_*"},
    {"server": "fs", "tool": "write_file", "args": {"path": "^${home}/"}},
    {"server": "fs", "tool": "delete_*", "effect": "deny"}
  ]}},
  "bindings": {"users": {"alice": ["tester"], "bob": ["tester"]}, "groups": {}},
  "approvers": {"default": ["self"]}
}
EOF

section "Start"
systemctl enable --now mcp-gateway.service
for _ in $(seq 60); do
	[ -S /run/mcp-gateway/mcp.sock ] && break
	sleep 1
done
check "gateway socket is up" test -S /run/mcp-gateway/mcp.sock
gw_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
opa_pid=$(systemctl show -p MainPID --value mcp-opa.service)
echo "  gateway: $(label "$gw_pid")"
echo "  opa:     $(label "$opa_pid")"
check "gateway runs in mcpgw_t" proc_has_type "$gw_pid" mcpgw_t
check "OPA runs in mcpopa_t" proc_has_type "$opa_pid" mcpopa_t
check "gateway runs as mcp-gateway" test "$(proc_user "$gw_pid")" = mcp-gateway
ls -ldZ /run/mcp-gateway | sed 's/^/  /'
ls -lZ /run/mcp-gateway/ | sed 's/^/  /'
check "/run/mcp-gateway is labeled mcpgw_runtime_t" file_has_type /run/mcp-gateway mcpgw_runtime_t
check "mcp.sock belongs to group mcp-users" test "$(stat -c %G /run/mcp-gateway/mcp.sock)" = mcp-users
# Restarting OPA (e.g. for a new policy bundle) must leave the gateway's
# sockets alone.
systemctl restart mcp-opa.service
sleep 2
check "OPA is running after a restart" systemctl is-active --quiet mcp-opa.service
check "mcp.sock keeps its group across an OPA restart" test "$(stat -c %G /run/mcp-gateway/mcp.sock)" = mcp-users

section "Calls"
tool alice read_file '{"path":"/home/alice/secret.txt"}'
check "alice reads her own file" succeeded_with "alice secret"
tool bob read_file '{"path":"/home/bob/secret.txt"}'
check "bob reads his own file" succeeded_with "bob secret"
tool alice read_file '{"path":"/home/bob/secret.txt"}'
check "alice cannot read bob's file" failed_without "bob secret"
tool alice delete_file '{"path":"/home/alice/secret.txt"}'
check "delete is denied by policy" tool_error_with "denied by policy"
check "the file was not deleted" test -f /home/alice/secret.txt

section "Instances"
systemctl list-units --type=service --plain --no-legend 'mcp-*' | awk '{print "  " $1, $4}'
a_pid=$(instance_pid alice)
b_pid=$(instance_pid bob)
check "alice's instance runs as alice" test -n "$a_pid"
check "bob's instance runs as bob" test -n "$b_pid"
a_ctx=$(label "${a_pid:-1}")
b_ctx=$(label "${b_pid:-1}")
echo "  alice: $a_ctx"
echo "  bob:   $b_ctx"
a_cats=$(categories "$a_ctx")
b_cats=$(categories "$b_ctx")
check "alice's instance runs in mcpsrv_fs_t" has_type "$a_ctx" mcpsrv_fs_t
check "bob's instance runs in mcpsrv_fs_t" has_type "$b_ctx" mcpsrv_fs_t
check "the instances have different category pairs" test -n "$a_cats" -a -n "$b_cats" -a "$a_cats" != "$b_cats"
check "alice's pair is in c768.c1023" in_range "$a_cats" 768 1023
check "bob's pair is in c768.c1023" in_range "$b_cats" 768 1023
if [ -n "$a_pid" ]; then
	grep -E '^(NoNewPrivs|CapEff|Seccomp):' "/proc/$a_pid/status" | sed 's/^/  /'
	check "the instance has no capabilities" grep -q '^CapEff:[[:space:]]*0000000000000000' "/proc/$a_pid/status"
	check "the instance has no_new_privs" grep -q '^NoNewPrivs:[[:space:]]*1' "/proc/$a_pid/status"
fi

section "Files written through the gateway"
tool alice write_file '{"path":"/home/alice/note.txt","content":"written by the agent"}'
check "alice writes a file in her home" test "$rc" = 0
echo "  $(file_label /home/alice/note.txt) /home/alice/note.txt"
check "the file belongs to alice" test "$(stat -c %U /home/alice/note.txt 2>/dev/null)" = alice
check "the file is user home content" file_has_type /home/alice/note.txt user_home_t
check "the file carries no instance categories" test "$(categories "$(file_label /home/alice/note.txt)")" = ""
# A later instance of the same user has another pair; it must still read
# what the previous one wrote.
[ -n "$a_pid" ] && systemctl stop "$(ps -o unit= -p "$a_pid" | tr -d ' ')"
for _ in $(seq 15); do
	tool alice read_file '{"path":"/home/alice/note.txt"}'
	[ "$rc" = 0 ] && break
	sleep 2
done
check "a new instance of alice reads the file" succeeded_with "written by the agent"
new_pid=$(instance_pid alice)
echo "  new instance: $(label "${new_pid:-1}")"

section "polkit"
check "the gateway user may start mcp-* units" \
	runuser -u mcp-gateway -- systemd-run --quiet --wait --unit=mcp-vmtest-probe.service /bin/true
check "the gateway user may not start other units" \
	as_gateway_user_fails systemd-run --quiet --wait --unit=vmtest-probe.service /bin/true

section "Credentials"
echo s3cr3t | install -m 0600 /dev/stdin /etc/mcp-gateway/credentials/probe
echo "  $(file_label /etc/mcp-gateway/credentials/probe) /etc/mcp-gateway/credentials/probe"
check "credentials are labeled mcpgw_cred_t" file_has_type /etc/mcp-gateway/credentials/probe mcpgw_cred_t
check "the gateway user cannot read credentials" as_gateway_user_fails cat /etc/mcp-gateway/credentials/probe

section "Kernel audit"
echo "  auditd: $(systemctl is-active auditd); records since the install: $(audit_since ALL | wc -l)"
audit_since SERVICE_START | grep -o 'unit=mcp-[a-z-]*' | sort | uniq -c | sed 's/^/  /'
audit_since TRUSTED_APP |
	grep -o 'op=mcp-[a-z-]*' | sort | uniq -c | sed 's/^/  /'
check "the audit log has the gateway's service start" audit_log_works
check "the gateway start is audited" audited mcp-gateway-start
check "the denial is audited" audited mcp-decision
check "decisions are in the journal" journal_has_audit

section "SELinux denials"
avc=$(audit_since AVC,USER_AVC,SELINUX_ERR)
# One line per distinct denial (pids, inodes and /proc names removed).
grep -E 'avc:|type=SELINUX_ERR' <<<"$avc" |
	sed -E 's/^.*(avc: |type=SELINUX_ERR)/\1/; s/ (pid|ino)=[0-9]+//g; s/ name="[0-9]+"//' |
	sort | uniq -c | sort -rn | sed 's/^/  /' | head -60
check "no denials involving the gateway, OPA or MCP servers" no_mcp_denials

section "Logs"
journalctl -u mcp-gateway.service -u mcp-opa.service --no-pager -o short-precise | tail -60
journalctl -u 'mcp-fs-*' --no-pager -o short-precise 2>/dev/null | tail -20

section "Result"
if [ "$failed" = 0 ]; then echo "all checks passed"; else echo "some checks FAILED"; fi
exit "$failed"
