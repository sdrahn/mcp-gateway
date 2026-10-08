#!/bin/bash
# Property tests of the installed gateway on a real openSUSE system with
# SELinux enforcing: domains, MCS pairs, polkit, credentials, kernel audit
# and no SELinux denials. Runs inside the VM as root (test/vm/run-vm.sh
# copies it there), with, next to it:
#   rpms/     mcp-gateway and its subpackages (selinux, fs-server, exec-server,
#             tools, the profiles)
#   mcpcall   the test client (test/vm/mcpcall)
#   opa       OPA binary, used if the distribution has no opa package
#   privsrv   test server for privileged backends (test/vm/privsrv)
#   servers/  the servers of the setup packages (test/vm/build-servers.sh), optional
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
eventually() { # eventually <seconds> <command...>: retry until it succeeds
	local deadline=$((SECONDS + $1))
	shift
	until "$@"; do
		[ "$SECONDS" -ge "$deadline" ] && return 1
		sleep 0.2
	done
}
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
# The kernel replaces the last byte of a user record with a NUL; the
# record must still end with the complete result.
denial_res_complete() { audit_since TRUSTED_APP | grep 'op=mcp-decision' | grep -q "res=failed'"; }
audit_log_works() { audit_since SERVICE_START | grep -q 'unit=mcp-gateway'; }
journal_has_audit() { journalctl -u mcp-gateway.service -o cat | grep -qF '"audit":true'; }
# outside_dontaudit_off: the records (stdin) outside the profiling run,
# which turns dontaudit rules off for the whole system: accesses the
# policy keeps silent (such as the gateway's MCS scan of /proc) are logged
# while it runs.
dontaudit_off_from=0 dontaudit_off_to=0
outside_dontaudit_off() {
	local line ts
	while IFS= read -r line; do
		ts=${line#*msg=audit(}
		ts=${ts%%.*}
		[[ $ts =~ ^[0-9]+$ ]] && [ "$ts" -ge "$dontaudit_off_from" ] && [ "$ts" -le "$dontaudit_off_to" ] && continue
		printf '%s\n' "$line"
	done
}
# Denials in a permissive domain (permissive=1) are those mcp-gateway
# profile records on purpose.
no_mcp_denials() {
	! outside_dontaudit_off <<<"$avc" | grep -E 'mcpgw_|mcpopa_|mcpsrv_|mcp_port_t' | grep -v 'permissive=1' | grep -q .
}
not_loaded() { ! semodule -l | awk '{print $1}' | grep -qx "$1"; }
# ptool <user> <tool> <args>: a call to the privileged test server.
ptool() {
	out=$(runuser -u "$1" -- /usr/local/bin/mcpcall --server privtest --method tools/call \
		--params "{\"name\":\"$2\",\"arguments\":$3}" 2>&1)
	rc=$?
	echo "  [$1] rc=$rc ${out:0:300}"
}
# control <user> <method> <path> [body]: the control API as <user>.
control() {
	runuser -u "$1" -- curl -s --unix-socket /run/mcp-gateway/control.sock -X "$2" \
		${4:+--data-binary "$4"} "http://gw$3"
}
# ptool_approved <user> <tool> <args>: ptool, with <user> approving the
# call (once) through the control API while it waits.
ptool_approved() {
	local id res=/root/privtest/call.out
	ptool "$@" >"$res" &
	local pid=$!
	for _ in $(seq 30); do
		id=$(control "$1" GET /v1/approvals | jq -r '.[0].id // empty')
		[ -n "$id" ] && break
		sleep 1
	done
	echo "  approval: ${id:-none}"
	[ -n "$id" ] && control "$1" POST "/v1/approvals/$id" '{"decision":"approve","scope":"once"}' >/dev/null
	wait "$pid"
	cat "$res"
	out=$(cat "$res")
	rc=0
	grep -q 'rc=0 ' "$res" || rc=1
}
wait_socket() {
	for _ in $(seq 60); do
		[ -S /run/mcp-gateway/mcp.sock ] && return
		sleep 1
	done
}
journal_since_start_has() {
	journalctl -u mcp-gateway.service -o cat --since "@$since" | grep -qF -- "$1"
}
has_capabilities() { ! grep -q '^CapEff:[[:space:]]*0000000000000000' "/proc/$1/status"; }
not_installed() { ! rpm -q "$1" >/dev/null 2>&1; }
# auditd writes the records asynchronously: wait for them a little.
privileged_audited() {
	for _ in $(seq 10); do
		audit_since TRUSTED_APP | grep 'op=mcp-decision' | grep 'privileged=yes' | grep -q 'res=success' && return
		sleep 1
	done
	return 1
}
# stool <user> <server> <tool> <args>: a tool call to a server; sets $out
# and $rc as call does.
stool() {
	out=$(runuser -u "$1" -- /usr/local/bin/mcpcall --server "$2" --method tools/call \
		--params "{\"name\":\"$3\",\"arguments\":$4}" 2>&1)
	rc=$?
	echo "  [$1 $2/$3] rc=$rc ${out:0:300}"
}
# stool_approved <user> <server> <tool> <args>: stool, approved (once) by
# <user> through the control API while it waits.
stool_approved() {
	local id res=/root/vmtest/stool.out
	stool "$@" >"$res" &
	local pid=$!
	for _ in $(seq 30); do
		id=$(control "$1" GET /v1/approvals | jq -r '.[0].id // empty')
		[ -n "$id" ] && break
		sleep 1
	done
	echo "  approval: ${id:-none}"
	[ -n "$id" ] && control "$1" POST "/v1/approvals/$id" '{"decision":"approve","scope":"once"}' >/dev/null
	wait "$pid"
	cat "$res"
	out=$(cat "$res")
	rc=0
	grep -q ' rc=0 ' "$res" || rc=1
}
# reached_server: the last call got an answer from the server (a result or
# a tool error), not a refusal or an unavailable backend.
reached_server() { [ "$rc" != 1 ]; }

# --- tests -------------------------------------------------------------------

section "System"
grep PRETTY_NAME /etc/os-release
uname -r
# Landlock (roadmap step 30): the LSMs, and the ABI once mcp-landlock is
# installed (section Start).
echo "LSMs: $(cat /sys/kernel/security/lsm)"
check "SELinux is enforcing" test "$(getenforce)" = Enforcing
sestatus | grep -E 'policy name|mode'

section "Install"
zypper -n --gpg-auto-import-keys ref >/dev/null
zypper -n in --no-recommends audit policycoreutils selinux-tools selinux-policy-targeted selinux-policy-devel polkit \
	rpm-build jq >/dev/null ||
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
install -D -m 0755 "$dir/privsrv" /usr/libexec/mcpgw-privtest
since=$(date +%s)
rpm -Uvh --nodeps "$dir"/rpms/mcp-gateway-[0-9]*.rpm "$dir"/rpms/mcp-gateway-selinux-*.rpm \
	"$dir"/rpms/mcp-gateway-fs-server-*.rpm "$dir"/rpms/mcp-gateway-exec-server-*.rpm \
	"$dir"/rpms/mcp-gateway-tools-*.rpm || die "installing the packages failed"
check "SELinux module mcp_gateway is loaded" bash -c 'semodule -l | grep -qx mcp_gateway'
# Labels as the packages leave them (no restorecon): a wrong label here is
# a packaging bug.
for f in /usr/bin/mcp-gateway:mcpgw_exec_t /usr/bin/mcp-gateway-admin:mcpsrv_admin_exec_t \
	/usr/libexec/mcp-servers/mcp-server-fs:mcpsrv_fs_exec_t \
	/usr/libexec/mcp-servers/mcp-server-exec:mcpsrv_exec_exec_t \
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
  ]},
  "commands": {"permissions": [{"server": "exec", "tool": "*"}]}},
  "bindings": {"users": {"alice": ["tester", "gateway-docs-reader", "gateway-admin", "commands"], "bob": ["tester"]}, "groups": {}},
  "approvers": {"default": ["self"]}
}
EOF

# The command server: the shipped examples and commands for the test.
install -m 0644 /usr/share/mcp-gateway/exec/examples.yaml /etc/mcp-gateway/exec.d/examples.yaml
cat >/etc/mcp-gateway/exec.d/vmtest.yaml <<'CMDS'
version: 1
commands:
  echo_word: {argv: [/usr/bin/echo, "{word}"], args: {word: {pattern: "[a-z]+"}}, read_only: true}
  user_name: {argv: [/usr/bin/id, -un], read_only: true}
  slow: {argv: [/usr/bin/sleep, "30"], timeout: 1s}
CMDS
restorecon -R /etc/mcp-gateway/exec.d
check "mcp-server-exec --check accepts the commands" /usr/libexec/mcp-servers/mcp-server-exec --check

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
# Type=notify: systemctl start returned once the gateway said it is
# ready; the status line and the watchdog pings follow at once.
check "systemd saw the gateway ready (Type=notify)" systemctl is-active --quiet mcp-gateway.service
status_text=$(systemctl show -p StatusText --value mcp-gateway.service)
echo "  status: $status_text"
check "the status line counts sessions and instances" grep -q 'sessions, .* server instances' <<<"$status_text"
echo "  watchdog: $(systemctl show -p WatchdogUSec --value mcp-gateway.service), last ping $(systemctl show -p WatchdogTimestamp --value mcp-gateway.service)"
check "the gateway pings the watchdog" test "$(systemctl show -p WatchdogTimestampMonotonic --value mcp-gateway.service)" -gt 0

section "Calls"
tool alice read_file '{"path":"/home/alice/secret.txt"}'
check "alice reads her own file" succeeded_with "alice secret"
tool bob read_file '{"path":"/home/bob/secret.txt"}'
check "bob reads his own file" succeeded_with "bob secret"
tool alice read_file '{"path":"/home/bob/secret.txt"}'
check "alice cannot read bob's file" failed_without "bob secret"
# Landlock (step 30): a file in bob's home that alice's account may read
# (world-readable) is still out of her fs instance's reach.
chmod 755 /home/bob
runuser -u bob -- sh -c "echo 'bob public' > /home/bob/public.txt; chmod 644 /home/bob/public.txt"
echo "  $(/usr/libexec/mcp-gateway/mcp-landlock -version)"
check "landlock: the kernel has Landlock" bash -c '/usr/libexec/mcp-gateway/mcp-landlock -version | grep -qE "ABI [1-9]"'
check "landlock: alice's account can read bob's public file" runuser -u alice -- cat /home/bob/public.txt
tool alice read_file '{"path":"/home/bob/public.txt"}'
check "landlock: alice's fs instance cannot read bob's public file" failed_without "bob public"
check "landlock: the fs instance started through mcp-landlock" \
	bash -c 'journalctl -q --no-pager -u "mcp-fs-*" | grep -q "mcp-landlock: Landlock ABI"'
# The fs server refuses bob's file as outside its --root before the
# kernel is asked. The launcher with the fs ruleset shows the kernel
# itself refusing it, where DAC and SELinux (alice's own domain) allow it.
ll_rules='{"write":["/home/alice"]}'
check "landlock: alice's own file, under the fs ruleset" \
	runuser -u alice -- /usr/libexec/mcp-gateway/mcp-landlock -rules "$ll_rules" -- cat /home/alice/secret.txt
check "landlock: ... and the kernel refuses bob's public file" \
	bash -c "runuser -u alice -- /usr/libexec/mcp-gateway/mcp-landlock -rules '$ll_rules' -- cat /home/bob/public.txt 2>&1 | grep -q 'public.txt: Permission denied'"
tool alice delete_file '{"path":"/home/alice/secret.txt"}'
check "delete is denied by policy" tool_error_with "denied by policy"
check "the file was not deleted" test -f /home/alice/secret.txt
# The file server logs a line to stderr at start: it belongs in the
# instance's journal, not on the MCP connection.
check "a server's stderr goes to the journal" \
	bash -c "journalctl -u 'mcp-fs-*' -o cat | grep -q 'mcp-server-fs: serving'"
# The file server under SELinux and the sandbox: the last lines of a file,
# and a symbolic link out of the home directory refused by the server
# (the policy sees only the path).
printf 'one\ntwo\nthree\n' >/home/alice/lines.txt && chown alice: /home/alice/lines.txt && restorecon /home/alice/lines.txt
tool alice read_text_file '{"path":"/home/alice/lines.txt","tail":1}'
check "read_text_file with tail" succeeded_with '"text":"three\n"'
ln -sfn /etc /home/alice/etclink && restorecon /home/alice/etclink
tool alice read_text_file '{"path":"/home/alice/etclink/os-release"}'
check "a symbolic link out of the home directory is refused" tool_error_with "outside the allowed directories"
rm -f /home/alice/etclink /home/alice/lines.txt
# A read-only file system (as / and /usr on a transactional system), here
# a read-only bind mount in the home directory: the server says why the
# write fails and that transactional-update changes such a system. The
# running instance has its own mount namespace, into which the bind mount
# propagates but not its remount read-only: a new instance sees it.
mkdir -p /home/alice/rodir && chown alice: /home/alice/rodir && restorecon /home/alice/rodir &&
	mount --bind /home/alice/rodir /home/alice/rodir && mount -o remount,bind,ro /home/alice/rodir
ro_pid=$(instance_pid alice)
[ -n "$ro_pid" ] && systemctl stop "$(ps -o unit= -p "$ro_pid" | tr -d ' ')"
for _ in $(seq 15); do
	tool alice write_file '{"path":"/home/alice/rodir/x","content":"x"}'
	[ "$rc" = 0 ] || tool_error_with "read-only" && break
	sleep 2
done
check "a write on a read-only file system says so" tool_error_with "read-only file system (on a transactional system"
umount /home/alice/rodir; rmdir /home/alice/rodir
# The gateway's documentation as a server: read-only, for alice (role
# gateway-docs-reader), not for bob.
stool alice gateway-docs search_files '{"path":"/usr/share/mcp-gateway/docs","pattern":"*operations*"}'
check "gateway-docs: search_files finds the operations chapter" succeeded_with "10-operations.md"
stool alice gateway-docs read_text_file '{"path":"user-guide/10-operations.md","head":1}'
check "gateway-docs: read_text_file" succeeded_with "# 10. Operations"
stool alice gateway-docs read_text_file '{"path":"README.md","head":1}'
check "gateway-docs: the index is installed" succeeded_with "# mcp-gateway documentation"
stool alice gateway-docs write_file '{"path":"x","content":"x"}'
check "gateway-docs: no tool that writes" bash -c '[ "$1" = 1 ] && grep -q "unknown tool" <<<"$2"' _ "$rc" "$out"
stool bob gateway-docs read_text_file '{"path":"user-guide/10-operations.md","head":1}'
check "gateway-docs: not for bob, who holds no role for it" failed_without "# 10. Operations"
# The gateway diagnostics as a server: root without capabilities in
# mcpsrv_admin_t, for alice (role gateway-admin: doctor and check_config
# freely, the rest with approval), not for bob.
stool alice gateway-admin doctor '{}'
check "gateway-admin: doctor" succeeded_with "configuration: "
check "gateway-admin: doctor does not ask OPA" succeeded_with "servers cannot reach OPA"
check "gateway-admin: doctor asks systemd" succeeded_with "mcp-gateway.service: active"
check "gateway-admin: doctor reads the audit log" bash -c '! grep -q "reading the audit log" <<<"$1"' _ "$out"
# matchpathcon is in /usr/sbin, which the server's PATH lacks: the doctor
# finds it there and compares the programs' labels with the policy's.
check "gateway-admin: doctor gets the policy's labels" bash -c '! grep -q "the policy.s label for" <<<"$1" && grep -q "labeled as the policy says" <<<"$1"' _ "$out"
stool alice gateway-admin check_config '{}'
check "gateway-admin: check_config" succeeded_with "role data: /etc/mcp-gateway/policy/rbac/data.json valid"
stool_approved alice gateway-admin explain_decision '{"user":"bob","server":"fs","name":"delete_file"}'
check "gateway-admin: explain_decision" succeeded_with "bob tools.call fs/delete_file: deny"
stool_approved alice gateway-admin show_config '{"file":"/etc/mcp-gateway/policy/rbac/data.json"}'
check "gateway-admin: show_config" succeeded_with "tester"
stool_approved alice gateway-admin recent_audit '{"user":"alice","server":"gateway-docs"}'
check "gateway-admin: recent_audit" succeeded_with "name=search_files"
stool_approved alice gateway-admin selinux_denials '{"since":"1h"}'
check "gateway-admin: selinux_denials" test "$rc" = 0
adm_pid=""
for unit in $(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-gateway-admin-*' | awk '{print $1}'); do
	pid=$(systemctl show -p MainPID --value "$unit")
	[ "$(proc_user "$pid")" = root ] && adm_pid=$pid
done
check "gateway-admin: an instance runs as root" test -n "$adm_pid"
if [ -n "$adm_pid" ]; then
	echo "  $(label "$adm_pid")"
	check "gateway-admin: in mcpsrv_admin_t" has_type "$(label "$adm_pid")" mcpsrv_admin_t
	check "gateway-admin: without capabilities" grep -q '^CapEff:[[:space:]]*0000000000000000' "/proc/$adm_pid/status"
fi
stool bob gateway-admin doctor '{}'
check "gateway-admin: not for bob, who holds no role for it" failed_without "configuration: "
# Allowed commands: the shipped examples under SELinux, as the calling
# user, no shell, patterns, the timeout; not for bob.
stool alice exec system_info '{}'
check "exec: system_info" succeeded_with "Linux"
stool alice exec os_release '{}'
check "exec: os_release" succeeded_with "openSUSE"
stool alice exec uptime '{}'
check "exec: uptime" succeeded_with "load average"
stool alice exec memory '{}'
check "exec: memory" succeeded_with "Mem:"
stool alice exec disk_usage '{}'
check "exec: disk_usage" succeeded_with "Filesystem"
stool alice exec package_version '{"package":"mcp-gateway"}'
check "exec: package_version" succeeded_with "mcp-gateway-0"
stool alice exec user_name '{}'
check "exec: commands run as the calling user" succeeded_with "alice"
stool alice exec echo_word '{"word":"a; id"}'
check "exec: a value outside its pattern is refused" tool_error_with "does not match"
stool alice exec echo_word '{"word":"-n"}'
check "exec: a value starting with - is refused" tool_error_with "must not start"
stool alice exec slow '{}'
check "exec: a command is ended after its timeout" tool_error_with "ended after the timeout"
exec_pid=""
for unit in $(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-exec-*' | awk '{print $1}'); do
	pid=$(systemctl show -p MainPID --value "$unit")
	[ "$(proc_user "$pid")" = alice ] && exec_pid=$pid
done
check "exec: alice's instance runs as alice" test -n "$exec_pid"
[ -n "$exec_pid" ] && check "exec: in mcpsrv_exec_t" has_type "$(label "$exec_pid")" mcpsrv_exec_t
stool bob exec system_info '{}'
check "exec: not for bob, who holds no role for it" failed_without "Linux"
check "no server output reached the gateway as invalid messages" \
	bash -c "! journalctl -u mcp-gateway.service -o cat | grep -q 'invalid message from backend'"

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
# A server reads its secret from $CREDENTIALS_DIRECTORY, in its domain
# (mcpsrv_generic_t), and sees neither other units' credentials nor their
# transient unit files.
jq '.roles.tester.permissions += [{"server": "credtest", "tool": "*"}]' \
	/etc/mcp-gateway/policy/rbac/data.json >/root/cred-data.json &&
	cat /root/cred-data.json >/etc/mcp-gateway/policy/rbac/data.json
cat >/etc/mcp-gateway/servers.d/credtest.yaml <<'END'
name: credtest
command: ["/usr/libexec/mcpgw-privtest"]
credentials: [probe]
END
restorecon /etc/mcp-gateway/servers.d/credtest.yaml
ctool() {
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server credtest --method tools/call \
		--params "{\"name\":\"$1\",\"arguments\":$2}" 2>&1)
	rc=$?
	echo "  [$1] rc=$rc ${out:0:300}"
}
cred_read() { ctool read_credential '{"name":"probe"}' >/dev/null && succeeded_with "credential: s3cr3t"; }
check "a server reads its secret from \$CREDENTIALS_DIRECTORY" eventually 40 cred_read
echo "  rc=$rc ${out:0:300}"
ctool list_credentials '{}'
cred_only_own() { succeeded_with "units: mcp-credtest-" && ! grep -qE 'units: .* ' <<<"$out"; }
check "it sees only its own unit's credentials" cred_only_own
transient=$(ls /run/systemd/transient/mcp-*.service 2>/dev/null | head -1)
ctool read_file "{\"path\":\"${transient:-/run/systemd/transient/none}\"}"
check "it cannot read transient unit files" test "$rc" != 0 -o -z "$transient"
rm -f /etc/mcp-gateway/servers.d/credtest.yaml

section "Privileged server"
# A server that installs packages, as mcp-server-zypp does: its own
# domain, rpm in rpm_t (mcp_gateway_backend_rpm), no sandbox, approval
# for every call not allowed by exact name.
mkdir -p /root/privtest
cat >/root/privtest/mcp_privtest.te <<'END'
policy_module(mcp_privtest, 1.0)

mcp_gateway_backend_template(privtest)
mcp_gateway_backend_rpm(privtest)

# Test only: "hold" writes its marker file below /run.
gen_require(`
	type var_run_t;
')
allow mcpsrv_privtest_t var_run_t:dir rw_dir_perms;
allow mcpsrv_privtest_t var_run_t:file manage_file_perms;
END
printf '/usr/libexec/mcpgw-privtest\t--\tgen_context(system_u:object_r:mcpsrv_privtest_exec_t,s0)\n' \
	>/root/privtest/mcp_privtest.fc
make -s -C /root/privtest -f /usr/share/selinux/devel/Makefile mcp_privtest.pp >/root/privtest/build.log 2>&1 ||
	sed 's/^/  /' /root/privtest/build.log
check "a backend module builds with the installed interface" test -f /root/privtest/mcp_privtest.pp
semodule -i /root/privtest/mcp_privtest.pp && restorecon /usr/libexec/mcpgw-privtest
echo "  $(file_label /usr/libexec/mcpgw-privtest) /usr/libexec/mcpgw-privtest"
check "the test server is labeled mcpsrv_privtest_exec_t" file_has_type /usr/libexec/mcpgw-privtest mcpsrv_privtest_exec_t
cat >/root/privtest/mcpgw-vmtest.spec <<'END'
Name: mcpgw-vmtest
Version: 1
Release: 1
Summary: VM test package of mcp-gateway
License: MIT
BuildArch: noarch
%description
Installed and removed through a privileged MCP server.
%install
mkdir -p %{buildroot}/usr/share/mcpgw-vmtest
echo hello >%{buildroot}/usr/share/mcpgw-vmtest/hello.txt
%files
/usr/share/mcpgw-vmtest
END
rpmbuild -bb --quiet --define "_rpmdir /srv/mcpgw-vmtest" /root/privtest/mcpgw-vmtest.spec >/dev/null 2>&1
test_rpm=/srv/mcpgw-vmtest/noarch/mcpgw-vmtest-1-1.noarch.rpm
check "the test package was built" test -f "$test_rpm"
cat >/etc/mcp-gateway/servers.d/privtest.yaml <<'END'
name: privtest
command: ["/usr/libexec/mcpgw-privtest"]
run_as: root
selinux_type: mcpsrv_privtest_t
privileged: true
END
# "hold" by exact name (allowed), everything else through the wildcard
# (asks, since the server is privileged).
jq '.roles.tester.permissions += [{"server": "privtest", "tool": "hold"}, {"server": "privtest", "tool": "*"}]' \
	/etc/mcp-gateway/policy/rbac/data.json >/root/privtest/data.json &&
	cat /root/privtest/data.json >/etc/mcp-gateway/policy/rbac/data.json
check "the gateway accepts the privileged server" /usr/bin/mcp-gateway --check --policy-data=
systemctl restart mcp-gateway.service
wait_socket
check "the start log warns about the privileged server" journal_since_start_has 'privileged server'

ptool alice hold '{"seconds":"0","marker":"/run/mcpgw-vmtest-hold0"}'
check "a tool named exactly runs without approval" succeeded_with "held"
p_unit=$(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-privtest-*' | awk 'NR==1{print $1}')
p_pid=$(systemctl show -p MainPID --value "${p_unit:-none}" 2>/dev/null)
p_ctx=$(label "${p_pid:-1}")
echo "  ${p_unit:-no unit}: $p_ctx"
check "the privileged instance runs as root" test "$(proc_user "${p_pid:-1}")" = root
check "the privileged instance runs in mcpsrv_privtest_t" has_type "$p_ctx" mcpsrv_privtest_t
check "the privileged instance has no category pair" test "${p_ctx##*:}" = s0
if [ -n "$p_pid" ] && [ "$p_pid" != 0 ]; then
	grep -E '^(NoNewPrivs|CapEff):' "/proc/$p_pid/status" | sed 's/^/  /'
	check "the privileged instance has capabilities" has_capabilities "$p_pid"
	check "the privileged instance has no no_new_privs" grep -q '^NoNewPrivs:[[:space:]]*0' "/proc/$p_pid/status"
fi

ptool_approved alice install_rpm "{\"path\":\"$test_rpm\"}"
check "the install call succeeded after an approval" succeeded_with "install_rpm done"
check "the package is installed" rpm -q mcpgw-vmtest
echo "  $(file_label /usr/share/mcpgw-vmtest/hello.txt) /usr/share/mcpgw-vmtest/hello.txt"
check "installed files have their normal label" file_has_type /usr/share/mcpgw-vmtest/hello.txt usr_t
check "installed files carry no categories" test "$(categories "$(file_label /usr/share/mcpgw-vmtest/hello.txt)")" = ""
check "the privileged call is in the kernel audit log" privileged_audited
ptool_approved alice remove_rpm '{"name":"mcpgw-vmtest"}'
check "the remove call succeeded after an approval" succeeded_with "remove_rpm done"
check "the package is removed" not_installed mcpgw-vmtest

# Stopping the gateway waits for a running call to a privileged server.
rm -f /run/mcpgw-vmtest-held
ptool alice hold '{"seconds":"15","marker":"/run/mcpgw-vmtest-held"}' >/dev/null &
sleep 3
t0=$(date +%s)
systemctl stop mcp-gateway.service
t1=$(date +%s)
wait
echo "  stopping took $((t1 - t0)) s"
check "the call finished before the instance stopped" test -f /run/mcpgw-vmtest-held
check "stopping waited for the call" test $((t1 - t0)) -ge 8
check "the gateway logged that it waited" journal_since_start_has 'waiting for privileged calls'
systemctl start mcp-gateway.service
wait_socket

section "Server setups"
# The setup packages with the real servers, built from upstream
# (test/vm/build-servers.sh): each server reads through the gateway, and
# systemd changes a unit after an approval, all with SELinux enforcing.
if [ -d "$dir/servers" ]; then
	cp -a "$dir/servers/." /
	# CI artifacts do not keep file modes.
	chmod 0755 /usr/bin/systemd-mcp /usr/bin/firewalld-mcp /usr/bin/mcp-server-zypp \
		/usr/bin/suseconnect-mcp /usr/libexec/mcp-server-zypp/zypp-mcp-tool /usr/bin/mcp-server-snapper
	restorecon -R /usr/bin/systemd-mcp /usr/bin/firewalld-mcp /usr/bin/mcp-server-zypp \
		/usr/bin/suseconnect-mcp /usr/libexec/mcp-server-zypp /usr/bin/mcp-server-snapper
	rpm -Uvh --nodeps "$dir"/rpms/mcp-gateway-profile-*.rpm >/dev/null || die "installing the setup packages failed"
	zypper -n in --no-recommends firewalld man >/dev/null && systemctl enable --now firewalld >/dev/null 2>&1
	zypper -n in --no-recommends snapper btrfsprogs >/dev/null
	# A snapper config of its own on a small btrfs, whatever the root file
	# system: snapperd allows it to mcp-snapper (ALLOW_USERS). Created
	# without snapperd (its domain may not write /etc/sysconfig/snapper on
	# every policy), which is then restarted to read it.
	truncate -s 512M /root/vmtest/snapper.img
	mkfs.btrfs -q /root/vmtest/snapper.img && mkdir -p /mnt/vmtest && mount -o loop /root/vmtest/snapper.img /mnt/vmtest &&
		snapper --no-dbus -c vmtest create-config /mnt/vmtest &&
		snapper --no-dbus -c vmtest set-config ALLOW_USERS=mcp-snapper ||
		echo "  setting up the snapper config failed"
	systemctl stop snapperd.service 2>/dev/null
	snapper list-configs 2>&1 | sed 's/^/  /'
	for f in /usr/bin/systemd-mcp:mcpsrv_systemd_exec_t /usr/bin/firewalld-mcp:mcpsrv_firewalld_exec_t \
		/usr/bin/mcp-server-zypp:mcpsrv_zypp_exec_t /usr/libexec/mcp-server-zypp/zypp-mcp-tool:rpm_exec_t \
		/usr/bin/suseconnect-mcp:mcpsrv_suseconnect_exec_t /usr/bin/mcp-server-snapper:mcpsrv_snapper_exec_t; do
		echo "  $(file_label "${f%%:*}") ${f%%:*}"
		check "${f%%:*} is labeled ${f##*:}" file_has_type "${f%%:*}" "${f##*:}"
	done
	# The package mcp-server-systemd installs the program under both names;
	# as hard links they share one label, which a relabel of either name
	# must keep.
	ln -f /usr/bin/systemd-mcp /usr/bin/mcp-server-systemd &&
		restorecon -F /usr/bin/mcp-server-systemd /usr/bin/systemd-mcp
	check "/usr/bin/mcp-server-systemd, a second name, keeps mcpsrv_systemd_exec_t" file_has_type /usr/bin/mcp-server-systemd mcpsrv_systemd_exec_t
	rm -f /usr/bin/mcp-server-systemd
	# suseconnect-mcp caches profile ids in /run/suseconnect (created by
	# the server where the policy transitions it; relabeled otherwise).
	mkdir -p /run/suseconnect && restorecon -F /run/suseconnect
	check "/run/suseconnect is labeled mcpsrv_suseconnect_runtime_t" file_has_type /run/suseconnect mcpsrv_suseconnect_runtime_t
	rmdir /run/suseconnect 2>/dev/null
	check "the setups created mcp-sysmgmt in systemd-journal" bash -c 'id -nG mcp-sysmgmt | grep -qw systemd-journal'
	# systemd-mcp 0.3.4 checks every read as com.suse.gatekeeper.readlog
	# (auth_admin in its policy): the setup's rule allows it. polkitd reads
	# the action file, copied with the servers above, when it starts.
	restorecon /usr/share/polkit-1/actions/com.suse.gatekeeper.policy
	systemctl try-restart polkit.service
	ls -lZ /usr/share/polkit-1/actions/com.suse.gatekeeper.policy | sed 's/^/  /'
	readlog_allowed() {
		runuser -u mcp-sysmgmt -- sh -c 'pkcheck --action-id com.suse.gatekeeper.readlog --process $$'
	}
	check "polkit allows mcp-sysmgmt reads of systemd-mcp 0.3.4 (com.suse.gatekeeper.readlog)" readlog_allowed
	check "the snapper setup created mcp-snapper" id mcp-snapper
	cat >/etc/systemd/system/mcpgw-vmtest.service <<'END'
[Unit]
Description=mcp-gateway VM test unit
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
END
	systemctl daemon-reload
	jq '.bindings.users.alice += ["systemd-operator", "firewalld-reader", "zypp-reader", "suseconnect-reader", "snapper-operator"]' \
		/etc/mcp-gateway/policy/rbac/data.json >/root/vmtest/data.json &&
		cat /root/vmtest/data.json >/etc/mcp-gateway/policy/rbac/data.json
	check "the role data binds the shipped roles" mcp-gateway --check-policy-data
	# Each server, started as for shared discovery, has every tool its
	# shipped roles name (mcp-gateway-admin inspect, roadmap step 11). zypp
	# offers the tools of zypp-installer only as root: its roles are
	# checked against the privileged definition, in a configuration of
	# its own.
	mkdir -p /root/vmtest/servers.d
	ln -sf /usr/share/mcp-gateway/profiles/zypp-privileged.yaml /root/vmtest/servers.d/zypp.yaml
	printf 'servers_dir: /root/vmtest/servers.d\n' >/root/vmtest/inspect-gateway.yaml
	for s in systemd firewalld zypp suseconnect snapper; do
		conf=()
		[ "$s" = zypp ] && conf=(-config /root/vmtest/inspect-gateway.yaml)
		mcp-gateway-admin inspect "${conf[@]}" -server "$s" -timeout 60s \
			-roles "/usr/share/mcp-gateway/policy/mcp/profiles/$s/data.json" >"/root/vmtest/inspect-$s.txt" 2>&1
		rc=$?
		sed -n '1p;/^Tools/,$p' "/root/vmtest/inspect-$s.txt" | sed "s/^/  [$s] /"
		check "inspect: the $s roles name only tools the server has" test "$rc" = 0
	done
	# systemd-mcp's list_log times are plain strings in its schema: inspect
	# flags them, and the shipped definition's note covers them.
	check "inspect: list_log's times are flagged, and noted" \
		grep -qF "list_log: times without a format: from, to (has a note)" /root/vmtest/inspect-systemd.txt
	check "inspect: the systemd tool notes name its tools" \
		bash -c '! grep -q "Tool notes for tools the server does not offer" /root/vmtest/inspect-systemd.txt'
	systemctl restart mcp-gateway.service
	wait_socket

	stool alice systemd list_log '{"unit":["mcp-gateway.service"],"exact_unit":true,"count":50,"pattern":"configuration valid"}'
	check "systemd: list_log reads the system journal" succeeded_with "configuration valid"
	# The definition's tool note: in the description, and the format it
	# names is the one list_log takes.
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server systemd --method tools/list --params '{}' 2>&1)
	rc=$?
	check "systemd: list_log's description has the tool note" succeeded_with "Administrator's note: from and to are RFC 3339 times"
	stool alice systemd list_log "{\"from\":\"$(date -Is -d '-1 hour')\",\"count\":5}"
	check "systemd: list_log takes from as the note says" test "$rc" = 0
	mcp-gateway-admin doctor --server systemd >/root/vmtest/doctor-systemd.txt 2>&1
	check "doctor: the systemd tool notes name its tools" bash -c '! grep -q "tool_notes name tools" /root/vmtest/doctor-systemd.txt'
	stool_approved alice systemd change_unit_state '{"name":"mcpgw-vmtest.service","action":"start","timeout":30}'
	check "systemd: change_unit_state after an approval" test "$rc" = 0
	# systemd-mcp reports the start job finished; the unit's state may
	# follow a moment later.
	check "systemd: the unit was started" eventually 10 systemctl is-active --quiet mcpgw-vmtest.service
	# Listed once started (an inactive unit nothing refers to is unloaded).
	stool alice systemd list_loaded_units '{"state":"active","patterns":["mcpgw-vmtest*"]}'
	check "systemd: list_loaded_units" succeeded_with "mcpgw-vmtest.service"

	stool alice firewalld get_default_zone '{}'
	check "firewalld: get_default_zone" test "$rc" = 0
	# The permanent configuration: polkit's FirewallD1.config.info.
	stool alice firewalld get_services_for_zone '{"zone":"public"}'
	check "firewalld: get_services_for_zone" test "$rc" = 0
	stool alice firewalld get_service_info '{"service":"ssh"}'
	check "firewalld: get_service_info" test "$rc" = 0

	stool alice zypp search_packages '{"pattern":"bash"}'
	check "zypp: search_packages" succeeded_with "bash"

	# Without a registration it may report an error, but from the server.
	stool alice suseconnect RegistrationStatus '{}'
	check "suseconnect: RegistrationStatus answers" reached_server

	# snapper in the sandbox, as mcp-snapper: what snapperd allows the
	# account through ALLOW_USERS. Changing a config is root's.
	mcp-gateway-admin doctor --server snapper --no-start 2>&1 | grep -E '^[a-z]+ +snapper' | sed 's/^/  /'
	check "doctor: snapperd allows mcp-snapper the vmtest config" \
		sh -c 'mcp-gateway-admin doctor --server snapper --no-start 2>&1 | grep -qE "^OK +snapper snapper: .*vmtest"'
	# The same through the gateway-admin server (mcpsrv_admin_t), which
	# reads the configs' ALLOW_USERS under the policy.
	stool alice gateway-admin doctor '{}'
	check "gateway-admin: doctor reads snapper's configs" bash -c 'grep -q "snapperd allows mcp-snapper the configs" <<<"$1" && ! grep -q "reading snapper.s configs" <<<"$1"' _ "$out"
	stool alice snapper list_configs '{}'
	check "snapper: list_configs" succeeded_with "vmtest"
	# The server's input schemas require every argument.
	stool alice snapper create_snapshot '{"config":"vmtest","type":"single","pre_number":0,"description":"vmtest","cleanup_algorithm":"","userdata":{}}'
	check "snapper: create_snapshot (no approval)" test "$rc" = 0
	snap=$(jq -r '.structuredContent.result // empty' <<<"$out" 2>/dev/null)
	stool alice snapper list_snapshots '{"config":"vmtest"}'
	check "snapper: list_snapshots shows it" succeeded_with '"description":"vmtest"'
	stool_approved alice snapper delete_snapshots "{\"config\":\"vmtest\",\"numbers\":[${snap:-0}]}"
	check "snapper: delete_snapshots after an approval" test "$rc" = 0
	check "snapper: the snapshot is gone" sh -c "! snapper --csvout -c vmtest list --columns number | grep -qx '${snap:-x}'"
	stool_approved alice snapper set_config '{"config":"vmtest","values":{"NUMBER_LIMIT":"7"}}'
	# stool_approved keeps the tool error in $out (rc=2); snapperd's
	# refusal reaches the server only as org.freedesktop.DBus.Error.Failed.
	check "snapper: set_config is refused in the sandbox (snapperd: root only)" \
		bash -c 'grep -q " rc=2 " <<<"$1" && grep -q "SetConfig.*D-Bus call failed" <<<"$1"' _ "$out"
	check "snapper: ... and the config is unchanged" bash -c '! grep -q "^NUMBER_LIMIT=\"7\"" /etc/snapper/configs/vmtest'

	# The privileged definition (root, no sandbox): set_config, and
	# rollback where the root file system is set up for it.
	ln -sf /usr/share/mcp-gateway/profiles/snapper-privileged.yaml /etc/mcp-gateway/servers.d/snapper.yaml
	systemctl restart mcp-gateway.service
	wait_socket
	stool_approved alice snapper set_config '{"config":"vmtest","values":{"NUMBER_LIMIT":"7"}}'
	check "snapper (privileged): set_config after an approval" test "$rc" = 0
	check "snapper (privileged): the config changed" grep -q '^NUMBER_LIMIT="7"' /etc/snapper/configs/vmtest
	if snapper -c root get-config >/dev/null 2>&1 && [ "$(stat -f -c %T /)" = btrfs ]; then
		before=$(btrfs subvolume get-default / 2>&1)
		stool_approved alice snapper rollback '{"config":"root","number":null,"description":"vmtest rollback","cleanup_algorithm":"","userdata":{}}'
		check "snapper (privileged): rollback after an approval" test "$rc" = 0
		after=$(btrfs subvolume get-default / 2>&1)
		echo "  default subvolume before: $before"
		echo "  default subvolume after:  $after"
		check "snapper (privileged): rollback set a new default subvolume" test "$before" != "$after"
	else
		echo "  the root file system has no snapper config on btrfs: rollback not tested"
	fi
	rm -f /etc/mcp-gateway/servers.d/snapper.yaml
	systemctl restart mcp-gateway.service
	wait_socket

	for s in systemd firewalld zypp suseconnect snapper; do
		journalctl -u "mcp-$s-*" --no-pager -o cat 2>/dev/null | tail -5 | sed "s/^/  [$s] /"
	done

	section "Profiling a new server"
	# Roadmap step 11, stage 2: firewalld-mcp under another name and path,
	# as a server nobody has written a module for. mcp-gateway-admin profile
	# drafts its domain from a permissive run; with the drafted module
	# and definition it runs enforcing without denials.
	install -m 0755 /usr/bin/firewalld-mcp /usr/libexec/mcpgw-fwprof
	restorecon /usr/libexec/mcpgw-fwprof
	cat >/etc/mcp-gateway/servers.d/fwprof.yaml <<'END'
name: fwprof
command: ["/usr/libexec/mcpgw-fwprof"]
run_as: mcp-sysmgmt
END
	prof=/root/vmtest/fwprof
	dontaudit_off_from=$(date +%s)
	mcp-gateway-admin profile -server fwprof -out "$prof" >"$prof.txt" 2>&1
	rc=$?
	dontaudit_off_to=$(date +%s)
	sed 's/^/  /' "$prof.txt" | head -70
	check "profile: the run completed" test "$rc" = 0
	check "profile: get_default_zone answered" grep -q '^  ok     get_default_zone' "$prof.txt"
	check "profile: the drafted module builds" test -f "$prof/mcp_fwprof.pp"
	check "profile: the temporary module is removed" not_loaded mcpprof_fwprof
	sed 's/^/  | /' "$prof/mcp_fwprof.te" | head -60
	semodule -i "$prof/mcp_fwprof.pp" && restorecon -F /usr/libexec/mcpgw-fwprof
	echo "  $(file_label /usr/libexec/mcpgw-fwprof) /usr/libexec/mcpgw-fwprof"
	check "profile: the program has the new domain's label" file_has_type /usr/libexec/mcpgw-fwprof mcpsrv_fwprof_exec_t
	cp "$prof/fwprof.yaml" /etc/mcp-gateway/servers.d/fwprof.yaml
	check "profile: the drafted definition is valid" mcp-gateway --check --policy-data=
	mcp-gateway-admin profile -server fwprof -verify >"$prof-verify.txt" 2>&1
	rc=$?
	sed 's/^/  /' "$prof-verify.txt" | head -40
	check "profile: with the drafted module the server runs enforcing without denials" test "$rc" = 0
	[ "$rc" = 0 ] || journalctl -u 'mcp-fwprof-*' --no-pager -o cat 2>/dev/null | tail -15 | sed 's/^/  [fwprof] /'
else
	echo "  no servers given (test/vm/run-vm.sh <...> <servers dir>); skipped"
fi

section "MCP server over HTTP"
# A server defined with url: each instance is mcp-http-connector in
# mcpsrv_http_t, which reaches only the server's address and sends the
# credential as a header. The server: privsrv -http on an HTTP port.
/usr/libexec/mcpgw-privtest -http 127.0.0.1:8008 &
http_pid=$!
echo vmtest-token | install -m 0600 /dev/stdin /etc/mcp-gateway/credentials/httptoken
jq '.roles.tester.permissions += [{"server": "httpecho", "tool": "whoami"}]' \
	/etc/mcp-gateway/policy/rbac/data.json >/root/http-data.json &&
	cat /root/http-data.json >/etc/mcp-gateway/policy/rbac/data.json
cat >/etc/mcp-gateway/servers.d/httpecho.yaml <<'END'
name: httpecho
url: http://127.0.0.1:8008/mcp
credentials: [httptoken]
headers:
  Authorization: "Bearer ${CREDENTIAL:httptoken}"
END
restorecon /etc/mcp-gateway/servers.d/httpecho.yaml /etc/mcp-gateway/credentials/httptoken
check "the gateway accepts a definition with url" /usr/bin/mcp-gateway --check --policy-data=
http_call() {
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server httpecho --method tools/call \
		--params '{"name":"whoami","arguments":{}}' 2>&1)
	rc=$?
}
http_works() { http_call && grep -qF "authorization: Bearer vmtest-token" <<<"$out"; }
check "a call reaches the server over HTTP, with the credential as a header" eventually 40 http_works
echo "  rc=$rc ${out:0:300}"
h_unit=$(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-httpecho-*' | awk 'NR==1{print $1}')
h_pid=$(systemctl show -p MainPID --value "${h_unit:-none}" 2>/dev/null)
h_ctx=$(label "${h_pid:-1}")
echo "  ${h_unit:-no unit}: $h_ctx"
systemctl show -p IPAddressAllow -p IPAddressDeny "${h_unit:-none}" 2>/dev/null | sed 's/^/  /'
check "the instance runs in mcpsrv_http_t" has_type "$h_ctx" mcpsrv_http_t
check "the instance may reach the server's address" sh -c "systemctl show -p IPAddressAllow --value '${h_unit:-none}' | grep -q 127.0.0.1"
check "the instance may reach no other address" sh -c "systemctl show -p IPAddressDeny --value '${h_unit:-none}' | grep -qE 'any|0\.0\.0\.0/0'"
http_secret_hidden() { ! tr '\0' ' ' <"/proc/${h_pid:-1}/cmdline" | grep -q vmtest-token; }
check "the credential is not on the instance's command line" http_secret_hidden
rm -f /etc/mcp-gateway/servers.d/httpecho.yaml /etc/mcp-gateway/credentials/httptoken
kill "$http_pid" 2>/dev/null
wait "$http_pid" 2>/dev/null

section "MCP server over HTTPS through a proxy"
# proxy: the connector tunnels through the proxy (CONNECT, on a proxy
# port, 3128) with the proxy credential, verifies the server's
# certificate, and the instance may reach the proxy's address only. The
# proxy (127.0.0.2) resolves the server's name (mcp.vmtest, 127.0.0.3);
# the gateway never does.
grep -q 'mcp\.vmtest' /etc/hosts || echo '127.0.0.3 mcp.vmtest' >>/etc/hosts
/usr/libexec/mcpgw-privtest -https 127.0.0.3:8443 /root/vmtest-server.pem &
https_pid=$!
/usr/libexec/mcpgw-privtest -proxy 127.0.0.2:3128 2>/root/vmtest-proxy.log &
proxy_pid=$!
eventually 10 test -s /root/vmtest-server.pem
install -m 0644 /root/vmtest-server.pem /etc/pki/trust/anchors/mcp-vmtest.pem && update-ca-certificates
echo vmtest-token | install -m 0600 /dev/stdin /etc/mcp-gateway/credentials/httptoken
printf %s vmtest:proxypass | base64 | install -m 0600 /dev/stdin /etc/mcp-gateway/credentials/proxyauth
jq '.roles.tester.permissions += [{"server": "httpsproxied", "tool": "whoami"}]' \
	/etc/mcp-gateway/policy/rbac/data.json >/root/http-data.json &&
	cat /root/http-data.json >/etc/mcp-gateway/policy/rbac/data.json
cat >/etc/mcp-gateway/servers.d/httpsproxied.yaml <<'END'
name: httpsproxied
url: https://mcp.vmtest:8443/mcp
proxy: http://127.0.0.2:3128
credentials: [httptoken, proxyauth]
headers:
  Authorization: "Bearer ${CREDENTIAL:httptoken}"
proxy_headers:
  Proxy-Authorization: "Basic ${CREDENTIAL:proxyauth}"
END
restorecon /etc/mcp-gateway/servers.d/httpsproxied.yaml /etc/mcp-gateway/credentials/httptoken /etc/mcp-gateway/credentials/proxyauth
proxy_call() {
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server httpsproxied --method tools/call \
		--params '{"name":"whoami","arguments":{}}' 2>&1)
	rc=$?
}
proxy_works() { proxy_call && grep -qF "authorization: Bearer vmtest-token; proxy-authorization: (none)" <<<"$out"; }
check "a call reaches the server through the proxy, over TLS" eventually 40 proxy_works
echo "  rc=$rc ${out:0:300}"
check "the connector tunnelled through the proxy" grep -qF "CONNECT mcp.vmtest:8443" /root/vmtest-proxy.log
p_unit=$(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-httpsproxied-*' | awk 'NR==1{print $1}')
p_allow=$(systemctl show -p IPAddressAllow --value "${p_unit:-none}" 2>/dev/null)
echo "  ${p_unit:-no unit}: IPAddressAllow=$p_allow"
check "the instance may reach the proxy's address" grep -qF 127.0.0.2 <<<"$p_allow"
proxy_only() { ! grep -qF 127.0.0.3 <<<"$p_allow"; }
check "the instance may not reach the server's address" proxy_only
p_pid=$(systemctl show -p MainPID --value "${p_unit:-none}" 2>/dev/null)
proxy_secret_hidden() { ! tr '\0' ' ' <"/proc/${p_pid:-1}/cmdline" | grep -qE 'vmtest-token|proxypass|dm10ZXN0'; }
check "the proxy credential is not on the instance's command line" proxy_secret_hidden
rm -f /etc/mcp-gateway/servers.d/httpsproxied.yaml /etc/mcp-gateway/credentials/httptoken \
	/etc/mcp-gateway/credentials/proxyauth /etc/pki/trust/anchors/mcp-vmtest.pem
update-ca-certificates
kill "$https_pid" "$proxy_pid" 2>/dev/null
wait "$https_pid" "$proxy_pid" 2>/dev/null

section "Signing in to a server for each user"
# A server with sign_in (OAuth with PKCE): alice signs in at its
# authorization server (the fake signs in the account its login parameter
# names at once) and is sent back to the gateway's callback on its HTTP
# listener; the gateway keeps the tokens, encrypted, the instance gets the
# access token as a credential, and every request to the authorization
# server is made by mcp-oauth-helper in its own domain.
zypper -n in --no-recommends policycoreutils-python-utils >/dev/null 2>&1 || true
if command -v semanage >/dev/null && command -v openssl >/dev/null; then
	si_since=$(date +%s)
	semanage port -a -t mcp_port_t -p tcp 9443 2>/dev/null || semanage port -m -t mcp_port_t -p tcp 9443
	grep -q 'auth\.vmtest' /etc/hosts || echo '127.0.0.4 auth.vmtest' >>/etc/hosts
	/usr/libexec/mcpgw-privtest -oauth 127.0.0.4:443 /root/vmtest-auth.pem &
	oauth_pid=$!
	eventually 10 test -s /root/vmtest-auth.pem
	install -m 0644 /root/vmtest-auth.pem /etc/pki/trust/anchors/mcp-vmtest-auth.pem && update-ca-certificates
	install -d -m 0750 -g mcp-gateway /etc/mcp-gateway/tls
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=gw.vmtest \
		-addext subjectAltName=DNS:gw.vmtest -keyout /etc/mcp-gateway/tls/key.pem -out /etc/mcp-gateway/tls/cert.pem 2>/dev/null
	chgrp mcp-gateway /etc/mcp-gateway/tls/key.pem && chmod 0640 /etc/mcp-gateway/tls/key.pem
	{
		cat /usr/etc/mcp-gateway/gateway.yaml
		printf 'http:\n  listen: 127.0.0.1:9443\n  cert_file: /etc/mcp-gateway/tls/cert.pem\n  key_file: /etc/mcp-gateway/tls/key.pem\n'
		printf '  issuer: https://idp.vmtest\n  audience: https://gw.vmtest:9443/mcp\n'
	} >/etc/mcp-gateway/gateway.yaml
	jq '.roles.tester.permissions += [{"server": "tickets", "tool": "whoami"}]' \
		/etc/mcp-gateway/policy/rbac/data.json >/root/si-data.json &&
		cat /root/si-data.json >/etc/mcp-gateway/policy/rbac/data.json
	cat >/etc/mcp-gateway/servers.d/tickets.yaml <<'END'
name: tickets
url: https://auth.vmtest/mcp
sign_in: {}
END
	restorecon -R /etc/mcp-gateway/tls /etc/mcp-gateway/gateway.yaml /etc/mcp-gateway/servers.d/tickets.yaml
	check "the gateway accepts a definition with sign_in" /usr/bin/mcp-gateway --check --policy-data=
	systemctl restart mcp-gateway.service
	tickets() { runuser -u alice -- /usr/local/bin/mcpcall --server tickets --method "$1" --params "$2" 2>&1; }
	si_offers() { out=$(tickets tools/list '{}') && grep -q '"sign_in"' <<<"$out" && ! grep -q '"whoami"' <<<"$out"; }
	check "before signing in, the server offers only sign_in" eventually 30 si_offers
	echo "  ${out:0:300}"

	# mcpcall has no URL elicitation: the call answers at once with a link
	# to the gateway, which the agent would show.
	tickets tools/call '{"name":"whoami","arguments":{}}' >/root/si-call.out
	start=$(grep -o 'https://gw\.vmtest:9443/oauth/start/[A-Za-z0-9_-]*' /root/si-call.out | head -1)
	check "the call answers at once with a sign-in link to the gateway" test -n "$start"
	echo "  $(head -c 300 /root/si-call.out)"
	si_link() { link=$(control alice GET /v1/sign-ins | jq -r '.pending[0].url // empty') && [ -n "$link" ]; }
	check "the sign-in is shown to alice (control API)" si_link
	si_not_bob() { [ "$(control bob GET /v1/sign-ins | jq '.pending | length')" = 0 ]; }
	check "the link is not shown to bob" si_not_bob
	# alice opens the link: the gateway sends her browser on to the
	# authorization server, which sends it back to the gateway's callback.
	auth=$(curl -s --noproxy '*' -o /dev/null -w '%{redirect_url}' --cacert /etc/mcp-gateway/tls/cert.pem \
		--resolve gw.vmtest:9443:127.0.0.1 "$start")
	check "the link leads to the authorization server" test "$auth" = "$link"
	back=$(curl -s --noproxy '*' -o /dev/null -w '%{redirect_url}' "$auth&login=alice")
	echo "  callback: ${back%%\?*}"
	cb=$(curl -s --noproxy '*' -o /root/si-callback.html -w '%{http_code}' --cacert /etc/mcp-gateway/tls/cert.pem \
		--resolve gw.vmtest:9443:127.0.0.1 "$back")
	si_callback() { [ "$cb" = 200 ] && grep -q 'signed in to tickets for alice' /root/si-callback.html; }
	check "the callback signs alice in, and says so" si_callback
	tickets tools/call '{"name":"whoami","arguments":{}}' >/root/si-call.out
	check "the next call works, as alice's account at the server" grep -qF "signed in as alice" /root/si-call.out
	echo "  $(head -c 300 /root/si-call.out)"
	si_audit() { journalctl -u mcp-gateway.service -o cat --since "@$si_since" | grep -F "\"event\":\"$1\"" | grep -qF "$2"; }
	check "the sign-in is audited" si_audit mcp-sign-in '"step":"completed"'
	si_helpers() { journalctl --since "@$si_since" -o short | grep -q 'mcp-tickets-sign-in-'; }
	check "the sign-in's requests ran in helper units" si_helpers
	ls -Z /var/lib/mcp-gateway/tokens/ | sed 's/^/  /'
	check "the tokens are kept in mcpgw_token_t" sh -c "ls -Z /var/lib/mcp-gateway/tokens/tokens.json | grep -q mcpgw_token_t"
	check "the token store holds no token in the clear" sh -c "! grep -qE 'access_token|refresh_token' /var/lib/mcp-gateway/tokens/tokens.json"
	si_unit=$(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-tickets-*' | awk '$1 !~ /sign-in/ {print $1; exit}')
	si_pid=$(systemctl show -p MainPID --value "${si_unit:-none}" 2>/dev/null)
	si_ctx=$(label "${si_pid:-1}")
	echo "  ${si_unit:-no unit}: $si_ctx; $(systemctl show -p IPAddressAllow -p RuntimeMaxUSec "${si_unit:-none}" 2>/dev/null | tr '\n' ' ')"
	check "the instance runs in mcpsrv_http_t" has_type "$si_ctx" mcpsrv_http_t
	check "the instance may reach the server's address only" sh -c "systemctl show -p IPAddressAllow --value '${si_unit:-none}' | grep -q 127.0.0.4"
	si_runtime() { systemctl show -p RuntimeMaxUSec --value "${si_unit:-none}" | grep -q '^8h$'; }
	check "the instance does not end with its token (it asks for a new one)" si_runtime
	si_no_token_file() { [ -z "$(ls -A /run/mcp-gateway/credentials 2>/dev/null)" ]; }
	check "the token file is gone once the unit started" si_no_token_file
	si_cmdline() { ! tr '\0' ' ' <"/proc/${si_pid:-1}/cmdline" | grep -qE 'Bearer [A-Za-z0-9]'; }
	check "no token is on the instance's command line" si_cmdline
	si_listed() { si_list=$(control alice GET /v1/sign-ins) && jq -e '.sign_ins[0].principal.sub == "alice"' >/dev/null <<<"$si_list" &&
		! grep -q token <<<"$si_list"; }
	check "alice sees her sign-in, without tokens" si_listed
	si_out=$(control alice DELETE /v1/sign-ins/tickets)
	check "alice signs out" grep -q '"signed_out":1' <<<"$si_out"
	si_stopped() { ! systemctl is-active -q "${si_unit:-none}"; }
	check "signing out stops her instance" eventually 10 si_stopped
	check "signing out revokes the tokens and is audited" si_audit mcp-sign-out '"revoked":"yes"'
	check "after signing out, the server offers only sign_in again" si_offers

	rm -f /etc/mcp-gateway/servers.d/tickets.yaml /etc/mcp-gateway/gateway.yaml /etc/pki/trust/anchors/mcp-vmtest-auth.pem
	update-ca-certificates
	systemctl restart mcp-gateway.service
	kill "$oauth_pid" 2>/dev/null
	wait "$oauth_pid" 2>/dev/null
else
	echo "  semanage or openssl not available; signing in not tested"
fi

section "Live reload of server definitions"
# A server added, broken, fixed and removed while the gateway runs: it
# keeps running (same PID), and a broken definition changes nothing.
rl_since=$(date +%s)
gw_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
jq '.roles.tester.permissions += [{"server": "fsreload", "tool": "read_*"}]' \
	/etc/mcp-gateway/policy/rbac/data.json >/root/rl-data.json &&
	cat /root/rl-data.json >/etc/mcp-gateway/policy/rbac/data.json
sed 's/^name: fs$/name: fsreload/' /usr/share/mcp-gateway/servers.d/fs-demo.yaml >/etc/mcp-gateway/servers.d/fsreload.yaml
restorecon /etc/mcp-gateway/servers.d/fsreload.yaml
rl_call() {
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server fsreload --method tools/call \
		--params '{"name":"read_file","arguments":{"path":"/home/alice/secret.txt"}}' 2>&1)
	rc=$?
}
rl_works() { rl_call && grep -qF "alice secret" <<<"$out"; }
rl_journal_has() { journalctl -u mcp-gateway.service -o cat --since "@$rl_since" | grep -qF -- "$1"; }
# The role data changed above: noticed when OPA reloaded it (inotify on
# the policy trees), well within policy.watch_interval (10 s).
check "the policy change is noticed at once" eventually 5 rl_journal_has '"event":"mcp-policy-change"'
check "a new definition is picked up without a restart" eventually 40 rl_works
check "the reload is audited" rl_journal_has '"event":"mcp-config-reload"'

rl_watched() {
	! journalctl -u mcp-gateway.service -o cat \
		_SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value mcp-gateway.service)" |
		grep -F 'noticed by polling only'
}
check "all configuration directories are watched (inotify)" rl_watched

# Noticed when written, well within policy.watch_interval (10 s).
printf 'netwrok: true\n' >>/etc/mcp-gateway/servers.d/fsreload.yaml
check "a broken definition is reported" eventually 5 rl_journal_has 'server definitions not reloaded'
check "with a broken definition the previous ones stay in force" rl_works
status=$(control alice GET /v1/status)
echo "  $status"
check "the control API reports the failed reload" grep -qF '"servers_error":' <<<"$status"
mcp-gateway-admin doctor --no-start 2>&1 | grep -E '^WARN +gateway status' | sed 's/^/  /'
check "the doctor warns about the failed reload" \
	sh -c 'mcp-gateway-admin doctor --no-start 2>&1 | grep -qE "^WARN +gateway status: .*server definitions not reloaded"'
reload_fails() { ! systemctl reload mcp-gateway.service; }
check "systemctl reload fails on a broken definition" reload_fails

sed -i '/^netwrok:/d' /etc/mcp-gateway/servers.d/fsreload.yaml
check "systemctl reload succeeds once it is fixed" systemctl reload mcp-gateway.service
check "the failed reload is no longer reported" \
	eventually 10 sh -c "! curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/status | grep -q servers_error"

# A changed definition: the next call runs on an instance of the new one.
# (Each mcpcall is a session of its own, so no session holds the old
# instance, which therefore stops at once.)
rl_units() { systemctl list-units --type=service --state=running --plain --no-legend 'mcp-fsreload-*' | awk '{print $1}'; }
rl_works
rl_old=$(rl_units)
printf 'env:\n  MCPGW_VMTEST: "2"\n' >>/etc/mcp-gateway/servers.d/fsreload.yaml
check "systemctl reload applies a changed definition" systemctl reload mcp-gateway.service
check "a call after the change works" eventually 20 rl_works
rl_new=$(rl_units)
echo "  instances before: ${rl_old:-none}; after: ${rl_new:-none}"
check "the call after the change runs on a new instance" bash -c '[ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ]' _ "$rl_old" "$rl_new"
rl_definition_current() { control alice GET /v1/servers | jq -e '[.[] | select(.name == "fsreload") | .instances[].definition] | index("current")' >/dev/null; }
check "the control API marks the new instance as current" rl_definition_current

rm -f /etc/mcp-gateway/servers.d/fsreload.yaml
rl_gone() { rl_call; [ "$rc" != 0 ] && ! grep -qF "alice secret" <<<"$out"; } # refused as an unknown server
check "a removed definition is dropped" eventually 40 rl_gone
rl_no_instance() { [ -z "$(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-fsreload-*')" ]; }
check "the removed server's instances are stopped" eventually 10 rl_no_instance
# gateway.yaml: reloadable keys apply, others are reported as needing a
# restart, a broken file changes nothing.
rl_status() { curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/status; }
sed 's/^approval_timeout:.*/approval_timeout: 3m/' /usr/etc/mcp-gateway/gateway.yaml >/etc/mcp-gateway/gateway.yaml
restorecon /etc/mcp-gateway/gateway.yaml
check "a reloadable key of gateway.yaml is applied" \
	eventually 40 rl_journal_has '"changed":"approval_timeout"'
rl_no_restart() { ! rl_status | grep -q restart_needed; }
check "nothing needs a restart for it" rl_no_restart
sed -i 's/^socket_group:.*/socket_group: wheel/' /etc/mcp-gateway/gateway.yaml
check "systemctl reload accepts a key that needs a restart" systemctl reload mcp-gateway.service
rl_restart_reported() { rl_status | grep -qF '"restart_needed":["socket_group"]'; }
check "the key that needs a restart is reported" eventually 10 rl_restart_reported
mcp-gateway-admin doctor --no-start 2>&1 | grep -E '^WARN +gateway status' | sed 's/^/  /'
check "the doctor asks for a restart" \
	sh -c 'mcp-gateway-admin doctor --no-start 2>&1 | grep -qE "^WARN +gateway status: .*next start"'
printf 'approval_timeout: [\n' >>/etc/mcp-gateway/gateway.yaml
check "systemctl reload fails on a broken gateway.yaml" reload_fails
rl_config_error() { rl_status | grep -qF '"config_error":'; }
check "a broken gateway.yaml is reported" eventually 40 rl_config_error
rl_works_fs() { tool alice read_file '{"path":"/home/alice/secret.txt"}' >/dev/null; succeeded_with "alice secret"; }
check "with a broken gateway.yaml the gateway still serves" rl_works_fs
rm -f /etc/mcp-gateway/gateway.yaml
rl_config_clean() { s=$(rl_status); ! grep -q 'config_error\|restart_needed' <<<"$s"; }
check "back to the default gateway.yaml, nothing is reported" eventually 40 rl_config_clean
check "the gateway was not restarted" test "$(systemctl show -p MainPID --value mcp-gateway.service)" = "$gw_pid"

section "Update without restart"
gw_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
ls -li /usr/bin/mcp-gateway | sed 's/^/  before: /'
rpm -Uvh --force --nodeps "$dir"/rpms/mcp-gateway-[0-9]*.rpm >/dev/null 2>&1
sleep 2
ls -li /usr/bin/mcp-gateway | sed 's/^/  after:  /'
check "a package update does not restart the gateway" \
	test "$(systemctl show -p MainPID --value mcp-gateway.service)" = "$gw_pid"
# A reinstall of the same build may leave the file as it is; replace it
# the way an update does (new file renamed over the old one).
cp -p /usr/bin/mcp-gateway /usr/bin/.mcp-gateway.vmtest && mv /usr/bin/.mcp-gateway.vmtest /usr/bin/mcp-gateway &&
	restorecon /usr/bin/mcp-gateway
status=$(control alice GET /v1/status)
echo "  $status"
check "the control API reports the pending restart" grep -qF '"restart_pending":true' <<<"$status"

section "Metrics"
# The counters start with each gateway process, and earlier sections
# restarted it: count calls of this one.
tool alice read_file '{"path":"/home/alice/secret.txt"}'
tool alice delete_file '{"path":"/home/alice/secret.txt"}'
metrics=$(curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/metrics)
grep -E '^mcp_gateway_(decisions_total|instance_starts_total|approvals_decided_total|policy_failures_total|sessions|instances|approvals_pending|restart_pending|build_info)' <<<"$metrics" |
	sed 's/^/  /' | head -40
check "metrics count allowed calls" grep -qE '^mcp_gateway_decisions_total\{action="tools.call",effect="allow"\} [1-9]' <<<"$metrics"
check "metrics count denied calls" grep -qE '^mcp_gateway_decisions_total\{action="tools.call",effect="deny"\} [1-9]' <<<"$metrics"
check "metrics count instance starts" grep -qE '^mcp_gateway_instance_starts_total\{server="fs"\} [1-9]' <<<"$metrics"
check "metrics time OPA's decisions" grep -qE '^mcp_gateway_opa_query_duration_seconds_count\{query="mcp/authz/decision"\} [1-9]' <<<"$metrics"
check "metrics show the pending restart" grep -qx 'mcp_gateway_restart_pending 1' <<<"$metrics"
metrics_refused() { control alice GET /v1/metrics | grep -q 'metrics are for root'; }
check "metrics are for root only" metrics_refused
# The listener (metrics.listen) on a port labelled mcp_metrics_port_t.
zypper -n in --no-recommends policycoreutils-python-utils >/dev/null 2>&1 || true
if command -v semanage >/dev/null; then
	semanage port -a -t mcp_metrics_port_t -p tcp 9464 2>/dev/null || semanage port -m -t mcp_metrics_port_t -p tcp 9464
	{ cat /usr/etc/mcp-gateway/gateway.yaml; printf 'metrics:\n  listen: 127.0.0.1:9464\n'; } >/etc/mcp-gateway/gateway.yaml
	restorecon /etc/mcp-gateway/gateway.yaml
	systemctl restart mcp-gateway.service
	check "the metrics listener serves /metrics" bash -c "curl -sf http://127.0.0.1:9464/metrics | grep -q '^# TYPE mcp_gateway_decisions_total counter'"
	rm -f /etc/mcp-gateway/gateway.yaml
	systemctl restart mcp-gateway.service
else
	echo "  semanage not available; metrics listener not tested"
fi

section "Self-check"
# carol may connect (mcp-users) but holds no role: the doctor names her.
useradd -m carol && usermod -aG mcp-users carol
mcp-gateway-admin doctor >/root/doctor.txt 2>&1
rc=$?
sed 's/^/  /' /root/doctor.txt | head -100
echo "  exit status $rc (the profiling run's denials count as failures)"
doctor_says() { grep -qE "$1" /root/doctor.txt; }
check "doctor: the gateway and OPA are active" doctor_says '^OK +mcp-(gateway|opa)\.service: active'
check "doctor: the role data is valid" doctor_says '^OK +role data: '
check "doctor: OPA decides" doctor_says '^OK +policy: OPA decides'
check "doctor: the demo server starts" doctor_says '^OK +server fs: starts: .*[1-9][0-9]* tools'
check "doctor: names the user without a role" doctor_says '^WARN +principals: .*hold no role'
check "doctor: ... and it is carol" doctor_says '^ +carol$'
if [ -d "$dir/servers" ]; then
	check "doctor: systemd-mcp starts" doctor_says '^OK +server systemd: starts'
	check "doctor: a polkit rule names mcp-sysmgmt" doctor_says '^OK +polkit mcp-sysmgmt: '
fi
check "doctor: every server's SELinux type is in the policy" doctor_says '^OK +SELinux types: '
check "doctor: instances of fs, gateway-docs and exec start under Landlock" \
	doctor_says '^OK +landlock: Landlock ABI [0-9]+: instances of .*exec.*fs.*gateway-docs.* start restricted'
check "doctor: the servers' programs are labeled as the policy says" doctor_says '^OK +program labels: '
# A program that lost its label (installed before its module): the doctor
# names it and the fix.
chcon -t bin_t /usr/libexec/mcp-servers/mcp-server-fs
mcp-gateway-admin doctor --server fs --no-start >/root/doctor-label.txt 2>&1
grep -A1 '^FAIL *program' /root/doctor-label.txt | sed 's/^/  /'
check "doctor: names a program labeled bin_t, and restorecon" \
	bash -c 'grep -qE "^FAIL +program fs: .* is labeled bin_t" /root/doctor-label.txt && grep -q "restorecon -v /usr/libexec/mcp-servers/mcp-server-fs" /root/doctor-label.txt'
restorecon /usr/libexec/mcp-servers/mcp-server-fs
# A helper a server starts (zypp's worker, rpm_exec_t) is checked too.
if [ -x /usr/libexec/mcp-server-zypp/zypp-mcp-tool ]; then
	chcon -t bin_t /usr/libexec/mcp-server-zypp/zypp-mcp-tool
	mcp-gateway-admin doctor --no-start >/root/doctor-helper.txt 2>&1
	grep -A1 '^FAIL *program' /root/doctor-helper.txt | sed 's/^/  /'
	check "doctor: names a helper program labeled bin_t" \
		grep -qE '^FAIL +program /usr/libexec/mcp-server-zypp/zypp-mcp-tool: .* is labeled bin_t, the policy says rpm_exec_t' /root/doctor-helper.txt
	restorecon /usr/libexec/mcp-server-zypp/zypp-mcp-tool
fi
no_type_warning() { ! journalctl -u mcp-gateway.service -o cat | grep -q 'not in the loaded SELinux policy'; }
check "the gateway found every server's SELinux type" no_type_warning
# A definition whose selinux_type has no module (as when a server
# definition is installed without it): systemd could not start it, even
# in permissive mode. The doctor and the gateway say why.
cat >/etc/mcp-gateway/servers.d/notype.yaml <<'END'
name: notype
command: ["/usr/libexec/mcpgw-privtest"]
run_as: root
selinux_type: mcpsrv_notype_t
privileged: true
END
mcp-gateway-admin doctor --server notype --no-start >/root/doctor-notype.txt 2>&1
sed 's/^/  /' /root/doctor-notype.txt | grep -i 'selinux type'
check "doctor: names the SELinux type that is not in the policy" \
	grep -qE '^FAIL +SELinux type mcpsrv_notype_t: .*servers notype cannot start' /root/doctor-notype.txt
# Not $since: audit_since reads it (the start of the test).
restarted=$(date +%s)
systemctl restart mcp-gateway.service
wait_socket
type_warning() { journalctl -u mcp-gateway.service -o cat --since "@$restarted" | grep 'not in the loaded SELinux policy' | grep -q 'selinux_type=mcpsrv_notype_t'; }
check "the gateway warns of the missing SELinux type at start" type_warning
rm -f /etc/mcp-gateway/servers.d/notype.yaml
systemctl restart mcp-gateway.service
wait_socket

# Run by hand as root, the gateway would leave state files the service
# cannot read: it refuses, and a root-owned file in the state directory
# is named by the doctor and at start.
timeout 10 /usr/bin/mcp-gateway >/root/as-root.txt 2>&1
sed 's/^/  /' /root/as-root.txt
check "the gateway refuses to run as root" grep -q 'refusing to run as root' /root/as-root.txt
echo '[]' >/var/lib/mcp-gateway/stray.json
mcp-gateway-admin doctor --no-start >/root/doctor-state.txt 2>&1
grep 'state files' /root/doctor-state.txt | sed 's/^/  /'
check "doctor: names the state file root owns" \
	grep -qE '^FAIL +state files: not owned by mcp-gateway: 1 ' /root/doctor-state.txt
restarted=$(date +%s)
systemctl restart mcp-gateway.service 2>/dev/null
state_error() { journalctl -u mcp-gateway.service -o cat --since "@$restarted" | grep 'state files not owned by mcp-gateway' | grep -q 'stray.json'; }
check "the gateway names the state file root owns" eventually 30 state_error
rm -f /var/lib/mcp-gateway/stray.json
systemctl reset-failed mcp-gateway.service
systemctl restart mcp-gateway.service
wait_socket
check "doctor: the state files are the gateway's" sh -c 'mcp-gateway-admin doctor --no-start 2>&1 | grep -qE "^OK +state files: "'
# Since 0.8 the old command is unknown, and says where it went.
mcp-gateway doctor --no-start >/root/doctor-moved.txt 2>&1
check "mcp-gateway doctor: unknown, naming mcp-gateway-admin doctor" \
	grep -q '"mcp-gateway-admin doctor" since 0.7' /root/doctor-moved.txt
userdel -r carol 2>/dev/null

section "Kernel audit"
echo "  auditd: $(systemctl is-active auditd); records since the install: $(audit_since ALL | wc -l)"
audit_since SERVICE_START | grep -o 'unit=mcp-[a-z-]*' | sort | uniq -c | sed 's/^/  /'
audit_since TRUSTED_APP |
	grep -o 'op=mcp-[a-z-]*' | sort | uniq -c | sed 's/^/  /'
audit_since TRUSTED_APP | grep 'op=mcp-decision' | cut -c1-600 | sed 's/^/  /'
check "the audit log has the gateway's service start" audit_log_works
check "the gateway start is audited" audited mcp-gateway-start
check "the denial is audited" audited mcp-decision
check "audit records keep their last character (res=failed)" denial_res_complete
check "decisions are in the journal" journal_has_audit

section "SELinux denials"
avc=$(audit_since AVC,USER_AVC,SELINUX_ERR)
# One line per distinct denial (pids, inodes and /proc names removed).
grep -E 'avc:|type=SELINUX_ERR' <<<"$avc" |
	sed -E 's/^.*(avc: |type=SELINUX_ERR)/\1/; s/ (pid|ino)=[0-9]+//g; s/ name="[0-9]+"//' |
	sort | uniq -c | sort -rn | sed 's/^/  /' | head -60
[ "$dontaudit_off_to" = 0 ] ||
	echo "  (denials from $(date -d "@$dontaudit_off_from" +%T) to $(date -d "@$dontaudit_off_to" +%T), while profiling turned dontaudit rules off, do not count)"
check "no denials involving the gateway, OPA or MCP servers" no_mcp_denials

section "Logs"
journalctl -u mcp-gateway.service -u mcp-opa.service --no-pager -o short-precise | tail -60
journalctl -u 'mcp-fs-*' --no-pager -o short-precise 2>/dev/null | tail -20

section "Result"
if [ "$failed" = 0 ]; then echo "all checks passed"; else echo "some checks FAILED"; fi
exit "$failed"
