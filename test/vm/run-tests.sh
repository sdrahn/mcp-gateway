#!/bin/bash
# Functional tests of the installed gateway on a real openSUSE or SLES
# system with SELinux enforcing: domains, MCS pairs, polkit, credentials,
# calls, approvals, obligations, limits, failing closed, signed policy
# bundles, users from a directory, reloads, kernel audit, no SELinux
# denials, and uninstalling. Package mcp-gateway-tests installs it as
# /usr/libexec/mcp-gateway/tests/run-tests.sh for openQA and other test
# systems; the CI VM runs the same (test/vm/run-vm.sh, after
# test/vm/prepare.sh). Next to it:
#   mcpcall   the test client (test/vm/mcpcall)
#   privsrv   test server for privileged backends (test/vm/privsrv)
#
# Usage: run-tests.sh --disposable [--results DIR] [--rpms DIR] [--servers DIR]
#
# It runs as root on a system that is there for testing: it creates users
# (alice, bob, carol, dora, erin), replaces the role data and gateway.yaml, loads
# SELinux modules, installs packages and restarts the gateway, and does
# not undo any of it. --disposable says that this is fine.
#   --results DIR  writes results.tap (TAP) and results.xml (JUnit) there
#   --rpms DIR     the packages it was installed from (CI): an update test
#                  with them, and the setup packages
#   --servers DIR  the setup packages' servers, laid out like the root file
#                  system (test/vm/build-servers.sh); without it, the
#                  setups are tested if their packages are installed
# Every check prints PASS, FAIL or SKIP; the script exits 1 if any failed,
# 2 on wrong usage.
set -u
dir=$(cd "$(dirname "$0")" && pwd)
failed=0
disposable= results= rpms= servers=
usage() {
	echo "usage: $0 --disposable [--results DIR] [--rpms DIR] [--servers DIR]" >&2
	exit 2
}
while [ $# -gt 0 ]; do
	case $1 in
	--disposable) disposable=1 ;;
	--results) results=${2:?}; shift ;;
	--rpms) rpms=$(realpath "${2:?}"); shift ;;
	--servers) servers=$(realpath "${2:?}"); shift ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done
if [ -z "$disposable" ]; then
	echo "$0: changes this system for good (users, role data, gateway.yaml, SELinux modules, packages);" >&2
	echo "run it on a system that is there for testing, with --disposable" >&2
	exit 2
fi
[ "$(id -u)" = 0 ] || { echo "$0: runs as root" >&2; exit 2; }
# Scratch files of the tests.
mkdir -p /root/vmtest

# The results, for TAP and JUnit: one line per check (section, status,
# description, seconds since the check before).
current_section=start
last_check=$SECONDS
results_list=()
record() {
	results_list+=("$current_section"$'\t'"$1"$'\t'"$2"$'\t'"$((SECONDS - last_check))")
	last_check=$SECONDS
}

pass() { echo "PASS: $*"; record pass "$*"; }
fail() { echo "FAIL: $*"; failed=1; record fail "$*"; fail_context; }
# skip <description>: a check that cannot run here, with why.
skip() { echo "SKIP: $*"; record skip "$*"; }
# fail_context prints what the gateway and systemd logged about it and its
# instances in the seconds before a failure (the journal at the end of
# the run shows only its last lines): the gateway's errors and warnings,
# and instances that failed to start or exited.
fail_context() {
	journalctl --since -20s --no-pager -o short-precise 2>/dev/null |
		grep -E 'mcp' | grep -E 'level=(ERROR|WARN)|[Ff]ailed|status=[0-9]|code=exited' |
		tail -15 | sed 's/^/    | /'
}
check() { # check <description> <command...>
	local desc=$1
	shift
	if "$@"; then pass "$desc"; else fail "$desc"; fi
}
section() {
	printf '\n=== %s\n' "$*"
	current_section=$*
}
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
# The file server refused ~/.config without mcpsrv_fs_manage_xdg and
# ~/.ssh always, and the gateway the mail server without
# mcpgw_can_send_mail, on purpose ("Files written through the gateway",
# "E-mail approvals").
expected_denial='scontext=[^ ]*:mcpsrv_fs_t:[^ ]* tcontext=[^ ]*:(config_home_t|ssh_home_t):|scontext=[^ ]*:mcpgw_t:[^ ]* tcontext=[^ ]*:smtp_port_t:'
no_mcp_denials() {
	! outside_dontaudit_off <<<"$avc" | grep -E 'mcpgw_|mcpopa_|mcpsrv_|mcp_port_t' | grep -v 'permissive=1' |
		grep -vE "$expected_denial" | grep -q .
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
# The packages are installed (CI: test/vm/prepare.sh; openQA: from the
# product's repositories); the gateway has not run yet, or is stopped
# here so that its start is the tests'.
for p in mcp-gateway mcp-gateway-selinux mcp-gateway-fs-server mcp-gateway-exec-server mcp-gateway-tools \
	mcp-gateway-tests jq curl rpm-build selinux-policy-devel; do
	rpm -q "$p" >/dev/null 2>&1 || die "package $p is not installed"
done
# OPA: the distribution's package, or (CI on Leap) a release binary.
command -v opa >/dev/null || die "opa is not installed"
echo "  $(rpm -q mcp-gateway mcp-gateway-tests | tr '\n' ' ')"
systemctl stop mcp-gateway.service mcp-opa.service 2>/dev/null || true
systemctl enable --now auditd
install -m 0755 "$dir/mcpcall" /usr/local/bin/mcpcall
install -D -m 0755 "$dir/privsrv" /usr/libexec/mcpgw-privtest
# Audit records and denials count from here.
since=$(date +%s)
# The setups (section Server setups): their servers built from upstream
# (--servers), else the setup packages and their servers as installed.
setups= missing=
setup_packages="mcp-gateway-profile-systemd mcp-gateway-profile-firewalld mcp-gateway-profile-zypp
	mcp-gateway-profile-snapper mcp-gateway-profile-suseconnect mcp-gateway-profile-podman"
if [ -n "$servers" ]; then
	setups=built
else
	# shellcheck disable=SC2086 # a list of package names
	missing=$(rpm -q $setup_packages systemd-mcp firewalld-mcp mcp-server-zypp mcp-server-snapper mcp-server-suseconnect \
		podman-mcp-server 2>/dev/null | sed -n 's/^package \(.*\) is not installed$/\1/p' | tr '\n' ' ')
	[ -z "$missing" ] && setups=installed
fi
echo "  setups: ${setups:-not tested (${missing}not installed)}"
check "SELinux module mcp_gateway is loaded" bash -c 'semodule -l | grep -qx mcp_gateway'
# The default role data is the package's, outside /etc (chapter 6): no
# file in /etc/mcp-gateway/policy/rbac until the administrator writes one.
check "the package installs no role data in /etc" bash -c '! ls /etc/mcp-gateway/policy/rbac/data.* >/dev/null 2>&1'
check "the default role data is in /usr/share/mcp-gateway/rbac" test -s /usr/share/mcp-gateway/rbac/data.yaml
check "the setups' shipped roles are YAML" bash -c '! ls /usr/share/mcp-gateway/policy/mcp/profiles/*/data.json >/dev/null 2>&1 && ls /usr/share/mcp-gateway/policy/mcp/profiles/*/data.yaml >/dev/null'
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
# JSON, which is YAML too: the sections below edit it with jq.
cat >/etc/mcp-gateway/policy/rbac/data.yaml <<'EOF'
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
  wait: {argv: [/usr/bin/sleep, "120"], timeout: 150s}
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
# Stage B: our own servers restrict themselves, whatever starts them.
# The exec server run by alice herself (no gateway, systemd or launcher)
# with a command that names no tree: bob's public file is refused.
cat >/etc/ll-exec-test.yaml <<'END'
version: 1
commands:
  show:
    argv: [/usr/bin/cat, "{path}"]
    args: {path: {pattern: "/[a-z0-9/._-]+"}}
    read_only: true
END
chmod 644 /etc/ll-exec-test.yaml
ll_exec() {
	{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"show\",\"arguments\":{\"path\":\"$1\"}}}"
		sleep 2; } | runuser -u alice -- /usr/libexec/mcp-servers/mcp-server-exec --commands /etc/ll-exec-test.yaml 2>&1
}
out=$(ll_exec /etc/os-release); echo "  ${out:0:300}"
check "landlock: the exec server restricts itself" grep -q "mcp-server-exec: 1 commands from /etc/ll-exec-test.yaml; Landlock ABI" <<<"$out"
check "landlock: ... its command reads the system" grep -q "NAME=" <<<"$out"
out=$(ll_exec /home/bob/public.txt); echo "  ${out:0:300}"
check "landlock: ... and is refused bob's public file" bash -c 'grep -q "public.txt: Permission denied" <<<"$1" && ! grep -q "bob public" <<<"$1"' _ "$out"
# Stage C: inspect runs a server started by command under Landlock,
# with a home of its own that is removed afterwards.
out=$(cd /tmp && runuser -u alice -- mcp-gateway-admin inspect -name llx -- \
	/usr/libexec/mcp-servers/mcp-server-exec --commands /etc/ll-exec-test.yaml 2>&1); echo "  ${out:0:400}"
check "landlock: inspect runs a command under Landlock" grep -q "llx runs without systemd and SELinux, under Landlock" <<<"$out"
check "landlock: ... and lists its tools" grep -q "show" <<<"$out"
ll_dir=$(grep -o '/tmp/mcp-inspect-[0-9]*' <<<"$out" | head -1)
check "landlock: ... and removes its home afterwards" test -n "$ll_dir" -a ! -e "${ll_dir:-/nonexistent}"
rm -f /etc/ll-exec-test.yaml
check "landlock: an fs instance restricts itself too" \
	bash -c 'journalctl -q --no-pager -u "mcp-fs-*" -o cat | grep -q "mcp-server-fs: serving /home/alice; Landlock ABI"'
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
# It reads the role data as OPA has it (mcpopa_rbac_t) and finds it current.
check "gateway-admin: doctor compares the role data with OPA's" succeeded_with "/run/mcp-opa/rbac is current"
stool alice gateway-admin check_config '{}'
check "gateway-admin: check_config" succeeded_with "role data: /etc/mcp-gateway/policy/rbac/data.yaml valid"
stool_approved alice gateway-admin explain_decision '{"user":"bob","server":"fs","name":"delete_file"}'
check "gateway-admin: explain_decision" succeeded_with "bob tools.call fs/delete_file: deny"
stool_approved alice gateway-admin show_config '{"file":"/etc/mcp-gateway/policy/rbac/data.yaml"}'
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
if ! succeeded_with "Linux"; then
	# Why the instance did not start: its own output, and the gateway's.
	journalctl -q --no-pager -u 'mcp-exec-*' -o cat | tail -20 | sed 's/^/  [exec] /'
	journalctl -q --no-pager -u mcp-gateway.service -o cat | grep -E '"server":"exec"|server=exec' | tail -5 | cut -c1-400 | sed 's/^/  [gateway] /'
fi
stool alice exec os_release '{}'
check "exec: os_release" succeeded_with "openSUSE"
stool alice exec uptime '{}'
check "exec: uptime" succeeded_with "load average"
stool alice exec memory '{}'
check "exec: memory" succeeded_with "Mem:"
stool alice exec disk_usage '{}'
check "exec: disk_usage" succeeded_with "Filesystem"
stool alice exec package_version '{"package":"mcp-gateway"}'
check "exec: package_version" succeeded_with "mcp-gateway-$(rpm -q --qf '%{VERSION}' mcp-gateway)"
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

section "Role data in YAML"
# Chapter 6: the role data is data.yaml in /etc/mcp-gateway/policy/rbac.
# OPA does not load that directory itself but its rendering by
# mcp-policy-render.service (root, rendering again on each change it
# sees): /run/mcp-opa/rbac, which neither the gateway nor OPA can write.
# The test's role data so far is JSON in data.yaml (JSON is YAML too).
rbac_dir=/etc/mcp-gateway/policy/rbac
ry_since=$(date +%s)
opa_pid=$(systemctl show -p MainPID --value mcp-opa.service)
check "mcp-policy-render.service watches the role data" systemctl is-active --quiet mcp-policy-render.service
check "OPA skips rbac/ and loads the rendering as data.mcp.rbac" \
	bash -c 'tr "\0" " " </proc/$1/cmdline | grep -qF -- "--ignore rbac" && tr "\0" " " </proc/$1/cmdline | grep -qF "mcp.rbac:/run/mcp-opa/rbac"' _ "$opa_pid"
check "OPA reads no data in JSON (--ignore *.json, since 1.7)" \
	bash -c 'tr "\0" " " </proc/$1/cmdline | grep -qF -- "--ignore *.json"' _ "$opa_pid"
ls -ldZ /run/mcp-opa/rbac /run/mcp-opa/rbac/* 2>&1 | sed 's/^/  /'
check "/run/mcp-opa/rbac is labeled mcpopa_rbac_t" file_has_type /run/mcp-opa/rbac mcpopa_rbac_t
check "/run/mcp-opa/rbac/data.yaml is labeled mcpopa_rbac_t" file_has_type /run/mcp-opa/rbac/data.yaml mcpopa_rbac_t
check "/run/mcp-opa/rbac belongs to root, writable by root only" test "$(stat -c %U:%a /run/mcp-opa/rbac)" = root:755
# ry_rendered: the rendering (JSON, as data.yaml) has the role data in
# force, as policy show reads it.
ry_rendered() { mcp-gateway-admin policy show | jq -S .data | cmp -s - <(jq -S . /run/mcp-opa/rbac/data.yaml); }
check "the rendering is the role data in force" ry_rendered
check "the gateway's account cannot change the rendering" as_gateway_user_fails touch /run/mcp-opa/rbac/data.yaml
check "the gateway's account cannot add to the rendering" as_gateway_user_fails touch /run/mcp-opa/rbac/x.yaml
# data.yaml in block style, with a comment and one change (bob gets the
# role "commands", which the test's role data does not give him); the
# role data so far as data.json next to it, which is ignored.
cp "$rbac_dir/data.yaml" /root/vmtest/ry-json.yaml
ry_yaml() {
	echo "# Role data in YAML (chapter 6): data.json next to it is ignored."
	jq -r '.bindings.users.bob += ["commands"] | to_entries[] | "\(.key): \(.value | tojson)"' /root/vmtest/ry-json.yaml
}
ry_yaml >"$rbac_dir/data.yaml"
cp /root/vmtest/ry-json.yaml "$rbac_dir/data.json"
restorecon "$rbac_dir/data.yaml" "$rbac_dir/data.json"
sed 's/^/  /' "$rbac_dir/data.yaml" | head -3
ry_bob_exec() { stool bob exec echo_word '{"word":"yaml"}' && [ "$rc" = 0 ] && grep -qF yaml <<<"$out"; }
ry_bob_refused() { stool bob exec echo_word '{"word":"yaml"}'; failed_without yaml; }
check "data.yaml is in force within seconds (bob gets the role it binds)" eventually 15 ry_bob_exec
check "the rendering has data.yaml's role data" bash -c 'jq -e ".bindings.users.bob | index(\"commands\")" /run/mcp-opa/rbac/data.yaml >/dev/null'
check "OPA has one role data, not both files merged" \
	bash -c 'curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac/bindings/users/bob | jq -e ".result | index(\"commands\")" >/dev/null'
ry_ignored() { journalctl -u mcp-policy-render.service -o cat --since "@$ry_since" | grep -qF "$rbac_dir/data.json is ignored: $rbac_dir/data.yaml is in force"; }
check "mcp-policy-render says data.json is ignored" eventually 15 ry_ignored
check "mcp-gateway --check-policy-data checks data.yaml" \
	bash -c 'mcp-gateway --check-policy-data 2>&1 | grep -qF "path=$1/data.yaml"' _ "$rbac_dir"
check "... and says data.json is ignored" bash -c 'mcp-gateway --check-policy-data 2>&1 | grep -qF "role data ignored"'
check "a data.json next to data.yaml blocks nothing" sh -c '! mcp-gateway --check 2>&1 | grep -qF "no longer read"'
# ry_doctor <jq filter>: the doctor's results (without starting servers) match.
ry_doctor() {
	mcp-gateway-admin doctor --no-start --json >/root/vmtest/ry-doctor.json 2>/dev/null
	jq -e "$1" /root/vmtest/ry-doctor.json >/dev/null
}
check "doctor: data.yaml valid, data.json named as ignored" ry_doctor \
	'.[] | select(.id == "role-data" and .status == "warn" and (.summary | contains("data.yaml valid"))) | .details[] | select(contains("data.json is ignored"))'
check "doctor: OPA's role data is current" ry_doctor '.[] | select(.id == "role-data-rendering" and .status == "ok")'
check "doctor: no policy data in JSON is read" ry_doctor '.[] | select(.id == "json-policy-data" and .status == "ok")'
# data.yaml that does not parse: not rendered, the role data in force
# stays, and the renderer keeps watching.
cp "$rbac_dir/data.yaml" /root/vmtest/ry-good.yaml
for _ in 1 2 3 4 5 6; do
	echo 'roles: {}' >>"$rbac_dir/data.yaml"
	sleep 0.3
done
ry_failed() { journalctl -u mcp-policy-render.service -o cat --since "@$ry_since" | grep -qF 'key "roles" is already defined'; }
check "data.yaml that does not parse is not rendered (its line named)" eventually 15 ry_failed
check "... and the last rendering stays in force (bob keeps the role)" ry_bob_exec
check "doctor: the role data fails, with the line" ry_doctor \
	'.[] | select(.id == "role-data" and .status == "fail" and (.summary | contains("is already defined")))'
cat /root/vmtest/ry-good.yaml >"$rbac_dir/data.yaml"
check "fixed again, it is rendered" eventually 15 ry_bob_exec
# What Cockpit's role editor runs (chapter 8): policy show gives the role
# data in force as JSON, policy write merges a change into data.yaml,
# keeping its comments, and refuses what the schema refuses.
ry_show=$(mcp-gateway-admin policy show)
check "policy show: data.yaml in force, as JSON" \
	bash -c 'jq -e --arg f "$2/data.yaml" ".file == \$f and .origin == \"yaml\" and (.data.bindings.users.bob | index(\"commands\"))" <<<"$1" >/dev/null' _ "$ry_show" "$rbac_dir"
check "policy show: data.json named as ignored" bash -c 'jq -e ".ignored | length == 1" <<<"$1" >/dev/null' _ "$ry_show"
jq '.data | .bindings.users.dora = ["tester"]' <<<"$ry_show" >/root/vmtest/ry-edit.json
ry_write=$(mcp-gateway-admin policy write </root/vmtest/ry-edit.json)
echo "  $(jq -c '{file, written, problems}' <<<"$ry_write")"
check "policy write: the change written to data.yaml" bash -c 'jq -e ".written" <<<"$1" >/dev/null' _ "$ry_write"
check "... keeping its comment" grep -qF "# Role data in YAML (chapter 6)" "$rbac_dir/data.yaml"
ry_dora() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac/bindings/users/dora | jq -e '.result == ["tester"]' >/dev/null; }
check "... and in force" eventually 15 ry_dora
cp "$rbac_dir/data.yaml" /root/vmtest/ry-before-bad.yaml
check "policy write refuses data the schema refuses" \
	bash -c '! jq ".data | .roles.tester.permissions[0].require_aproval = true" <<<"$1" | mcp-gateway-admin policy write >/root/vmtest/ry-bad.json' _ "$ry_show"
check "... names the problem" grep -qF "'require_aproval' not allowed" /root/vmtest/ry-bad.json
check "... and leaves data.yaml as it was" cmp -s "$rbac_dir/data.yaml" /root/vmtest/ry-before-bad.yaml
check "policy write --yaml writes YAML as it is" \
	bash -c '{ cat "$1"; echo "# added by hand"; } | mcp-gateway-admin policy write --yaml >/dev/null && tail -1 "$1" | grep -qx "# added by hand"' _ "$rbac_dir/data.yaml"
cat /root/vmtest/ry-good.yaml >"$rbac_dir/data.yaml"
# A subdirectory (rbac/<name>/, chapter 12) is rendered along, as
# data.mcp.rbac.<name>, also when only it changes.
mkdir -p "$rbac_dir/vmtest"
echo 'note: from a subdirectory' >"$rbac_dir/vmtest/data.yaml"
restorecon -R "$rbac_dir/vmtest"
ry_sub() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac/vmtest | jq -e '.result.note == "from a subdirectory"' >/dev/null; }
check "a subdirectory's data.yaml reaches OPA as data.mcp.rbac.vmtest" eventually 15 ry_sub
rm -r "$rbac_dir/vmtest"
ry_sub_gone() { test ! -e /run/mcp-opa/rbac/vmtest; }
check "... and goes once the subdirectory is gone" eventually 15 ry_sub_gone
# Without role data in /etc, the shipped default is in force, taken whole
# (its roles viewer, developer and admin; the test's roles gone).
mv "$rbac_dir/data.yaml" /root/vmtest/ry-data.yaml
mv "$rbac_dir/data.json" /root/vmtest/ry-data.json
ry_default() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac | jq -e '.result.roles | has("viewer") and has("developer") and (has("tester") | not)' >/dev/null; }
check "no role data in /etc: the shipped default is in force" eventually 15 ry_default
check "doctor: the shipped default is valid and named" ry_doctor \
	'.[] | select(.id == "role-data" and .status == "ok" and (.summary | contains("/usr/share/mcp-gateway/rbac/data.yaml valid")))'
check "mcp-gateway --check-policy-data checks the shipped default" \
	bash -c 'mcp-gateway --check-policy-data 2>&1 | grep -qF "path=/usr/share/mcp-gateway/rbac/data.yaml"'
cat /root/vmtest/ry-json.yaml >/root/vmtest/ry-data.yaml
mv /root/vmtest/ry-data.yaml "$rbac_dir/data.yaml"
restorecon "$rbac_dir/data.yaml"
ry_own() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac | jq -e '.result.roles | has("tester") and (has("viewer") | not)' >/dev/null; }
check "data.yaml back: its roles are in force, not the default's" eventually 15 ry_own
check "... bob without the role it gave him" ry_bob_refused

section "Configuration in JSON"
# Step 38: role data and the data of custom Rego in JSON were deprecated
# in 1.6 and are no longer read since 1.7. A file left over that 1.6
# read (a data.json without a data.yaml, a data file in JSON below
# /etc/mcp-gateway/policy) is an error naming it and the command that
# converts it, and the policy fails closed: the gateway denies every
# request and lists nothing until it is converted. Converted, the same
# data is in force.
jd_since=$(date +%s)
mv "$rbac_dir/data.yaml" /root/vmtest/jd-data.yaml
cp /root/vmtest/ry-json.yaml "$rbac_dir/data.json"
restorecon "$rbac_dir/data.json"
jd_cmd="mcp-gateway-admin policy convert $rbac_dir/data.json"
jd_problem="$rbac_dir/data.json: configuration in JSON is no longer read since 1.7: convert it to YAML with $jd_cmd"
jd_render_says() { journalctl -u mcp-policy-render.service -o cat --since "@$jd_since" | grep -qF "$jd_problem"; }
check "mcp-policy-render names the role data in JSON and the command" eventually 15 jd_render_says
jd_no_rbac() { test ! -e /run/mcp-opa/rbac/data.yaml && ! ry_default && ! ry_own; }
check "... renders nothing for it, not the shipped default either" eventually 15 jd_no_rbac
check "mcp-gateway --check refuses it, naming the command" \
	bash -c '! mcp-gateway --check >/root/vmtest/jd-check.txt 2>&1 && grep -qF "$1" /root/vmtest/jd-check.txt' _ "$jd_problem"
check "mcp-gateway --check-policy-data refuses it too" \
	bash -c '! mcp-gateway --check-policy-data >/root/vmtest/jd-check.txt 2>&1 && grep -qF "$1" /root/vmtest/jd-check.txt' _ "$jd_problem"
jd_denied() { tool alice read_file '{"path":"/home/alice/secret.txt"}'; failed_without "alice secret" && grep -qF "no longer read since 1.7" <<<"$out"; }
check "the gateway denies alice's call, naming the file" eventually 15 jd_denied
jd_nothing_listed() { call alice --method tools/list --params '{}'; ! grep -qF '"read_file"' <<<"$out"; }
check "... and lists her nothing" jd_nothing_listed
jd_logged() { journalctl -u mcp-gateway.service -o cat --since "@$jd_since" | grep -F "every request is denied until it is converted" | grep -qF "path=$rbac_dir/data.json"; }
check "... and logs why" jd_logged
check "doctor: the role data fails, naming the command" ry_doctor \
	".[] | select(.id == \"role-data\" and .status == \"fail\" and (.summary == \"$jd_problem\"))"
check "doctor: policy data in JSON fails, naming the file" ry_doctor \
	"[.[] | select(.id == \"json-policy-data\" and .status == \"fail\") | .details[]] | any(. == \"$rbac_dir/data.json: $jd_cmd\")"
check "policy show: the JSON, converted, for the role editor to save" \
	bash -c 'mcp-gateway-admin policy show | jq -e --arg f "$1/data.json" ".file == \$f and .origin == \"json\" and (.yaml | length > 0) and (.data.roles | has(\"tester\"))" >/dev/null' _ "$rbac_dir"
jd_out=$(mcp-gateway-admin policy convert)
echo "$jd_out" | sed 's/^/  /'
check "policy convert: data.yaml written next to data.json" grep -qF "$rbac_dir/data.yaml is in force now; $rbac_dir/data.json is ignored" <<<"$jd_out"
check "... and its roles are in force again" eventually 15 ry_own
check "... the same data as the JSON" bash -c 'jq -S . /run/mcp-opa/rbac/data.yaml | cmp -s - <(jq -S . "$1")' _ /root/vmtest/ry-json.yaml
jd_decides() { tool alice read_file '{"path":"/home/alice/secret.txt"}'; succeeded_with "alice secret"; }
check "the gateway decides again" eventually 15 jd_decides
jd_again() { journalctl -u mcp-gateway.service -o cat --since "@$jd_since" | grep -qF "the policy decides again"; }
check "... and says so" jd_again
check "policy convert --to json: the role data as JSON, the same data" \
	bash -c 'mcp-gateway-admin policy convert --to json -o - | jq -S . | cmp -s - <(jq -S . "$1")' _ /root/vmtest/ry-json.yaml
rm "$rbac_dir/data.json"
# Data of custom Rego (chapter 12), which OPA loads itself: in JSON, OPA
# no longer loads it, and the gateway denies every request.
jd_since=$(date +%s)
jd_dir=/etc/mcp-gateway/policy/vmtest_custom
mkdir -p "$jd_dir"
echo '{"answer": 42, "words": ["yes", "on", "010"], "nested": {"limit": 1.5}}' >"$jd_dir/data.json"
restorecon -R "$jd_dir"
# jd_opa: OPA's data.mcp.vmtest_custom, sorted.
jd_opa() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/vmtest_custom | jq -S -c .result; }
jd_loaded() { [ "$(jd_opa)" = '{"answer":42,"nested":{"limit":1.5},"words":["yes","on","010"]}' ]; }
jd_custom_denied() { tool alice read_file '{"path":"/home/alice/secret.txt"}'; failed_without "alice secret" && grep -qF "$jd_dir/data.json" <<<"$out"; }
check "custom data in JSON: the gateway denies, naming the file" eventually 15 jd_custom_denied
sleep 2
check "... and OPA does not load it" sh -c '[ "$(curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/vmtest_custom | jq -c .result)" = null ]'
check "doctor: the custom data in JSON named, with its command" ry_doctor \
	"[.[] | select(.id == \"json-policy-data\" and .status == \"fail\") | .details[]] | any(. == \"$jd_dir/data.json: mcp-gateway-admin policy convert $jd_dir/data.json\")"
check "mcp-gateway --check refuses it" \
	bash -c '! mcp-gateway --check >/root/vmtest/jd-check.txt 2>&1 && grep -qF "$1/data.json: configuration in JSON is no longer read since 1.7" /root/vmtest/jd-check.txt' _ "$jd_dir"
jd_out=$(mcp-gateway-admin policy convert "$jd_dir/data.json")
echo "$jd_out" | sed 's/^/  /'
check "policy convert: the custom data written as YAML" test -s "$jd_dir/data.yaml"
check "... and data.json removed" test ! -e "$jd_dir/data.json"
check "... saying so" grep -qF "removed $jd_dir/data.json" <<<"$jd_out"
check "the YAML is labeled as the policy is" bash -c '[ "$(stat -c %C "$1/data.yaml" | cut -d: -f3)" = "$(stat -c %C /etc/mcp-gateway/policy | cut -d: -f3)" ]' _ "$jd_dir"
check "OPA reads the YAML as the same data" eventually 15 jd_loaded
check "... and the gateway decides again" eventually 15 jd_decides
jd_out=$(mcp-gateway-admin policy convert --to json "$jd_dir/data.yaml")
check "policy convert --to json brings the JSON back, saying it is not read" \
	bash -c 'test -s "$1/data.json" && test ! -e "$1/data.yaml" && grep -qF "no longer read since 1.7" <<<"$2"' _ "$jd_dir" "$jd_out"
check "... and the gateway denies again" eventually 15 jd_custom_denied
mcp-gateway-admin policy convert "$jd_dir/data.json" >/dev/null
check "converted once more, the gateway decides" eventually 15 jd_decides
rm -r "$jd_dir"
cat /root/vmtest/jd-data.yaml >"$rbac_dir/data.yaml"
check "the test's role data back" eventually 15 ry_own

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
# Dot-directories with types of their own: ~/.config (config_home_t)
# only with the boolean mcpsrv_fs_manage_xdg, ~/.ssh (ssh_home_t) never.
runuser -u alice -- sh -c 'mkdir -p ~/.config/vmtest ~/.ssh && echo old >~/.config/vmtest/settings && echo key >~/.ssh/vmtest'
restorecon -R /home/alice/.config /home/alice/.ssh
echo "  $(file_label /home/alice/.config/vmtest/settings) ~/.config/vmtest/settings, $(file_label /home/alice/.ssh/vmtest) ~/.ssh/vmtest"
tool alice write_file '{"path":"/home/alice/.config/vmtest/settings","content":"new"}'
check "without mcpsrv_fs_manage_xdg, ~/.config is refused" tool_error_with "permission denied"
check "the boolean mcpsrv_fs_manage_xdg is there, off" bash -c 'getsebool mcpsrv_fs_manage_xdg | grep -q "off$"'
setsebool mcpsrv_fs_manage_xdg on
tool alice write_file '{"path":"/home/alice/.config/vmtest/settings","content":"new"}'
check "with mcpsrv_fs_manage_xdg, alice writes ~/.config" test "$rc" = 0 -a "$(cat /home/alice/.config/vmtest/settings 2>/dev/null)" = new
check "the file keeps its type" file_has_type /home/alice/.config/vmtest/settings config_home_t
tool alice write_file '{"path":"/home/alice/.config/vmtest/new.conf","content":"x"}'
check "a new file in ~/.config is config_home_t" file_has_type /home/alice/.config/vmtest/new.conf config_home_t
tool alice read_file '{"path":"/home/alice/.ssh/vmtest"}'
check "~/.ssh stays out of reach with mcpsrv_fs_manage_xdg" tool_error_with "permission denied"
setsebool mcpsrv_fs_manage_xdg off

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
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/cred-data.json &&
	cat /root/cred-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/privtest/data.json &&
	cat /root/privtest/data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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

section "Server with a capability"
# The same test server in the sandbox with CAP_SYS_ADMIN only
# (sandbox.capabilities), as mcp-server-tukit runs: that capability and
# no other, no_new_privs, its category pair, and approvals as for a
# privileged server. Using it in the kernel is left to SELinux, which does
# not grant it (the denials are checked at the end).
cp /etc/mcp-gateway/servers.d/privtest.yaml /root/privtest/privileged.yaml
cat >/etc/mcp-gateway/servers.d/privtest.yaml <<'END'
name: privtest
command: ["/usr/libexec/mcpgw-privtest"]
run_as: root
selinux_type: mcpsrv_privtest_t
sandbox:
  capabilities: [CAP_SYS_ADMIN]
END
check "the gateway accepts the server with a capability" /usr/bin/mcp-gateway --check --policy-data=
systemctl restart mcp-gateway.service
wait_socket
check "the start log warns about the server with a capability" journal_since_start_has 'server with capabilities'
# read_file is allowed only through the wildcard: it asks.
ptool_approved alice read_file '{"path":"/proc/self/status"}' >/root/privtest/cap-call.log
sed 's/^/  /' /root/privtest/cap-call.log | cut -c1-200
check "a call through a wildcard asks for an approval" grep -q 'approval: a-' /root/privtest/cap-call.log
# (ptool keeps the first 300 characters: the start of /proc/self/status;
# the capability sets are checked on the instance below.)
check "... and runs after it" succeeded_with "mcpgw-privtest"
c_unit=$(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-privtest-*' | awk 'NR==1{print $1}')
c_pid=$(systemctl show -p MainPID --value "${c_unit:-none}" 2>/dev/null)
c_ctx=$(label "${c_pid:-1}")
echo "  ${c_unit:-no unit}: $c_ctx"
check "the instance runs as root" test "$(proc_user "${c_pid:-1}")" = root
check "the instance runs in mcpsrv_privtest_t with a category pair" test -n "$(categories "$c_ctx")"
if [ -n "$c_pid" ] && [ "$c_pid" != 0 ]; then
	grep -E '^(NoNewPrivs|Cap[A-Za-z]+):' "/proc/$c_pid/status" | sed 's/^/  /'
	check "the instance holds CAP_SYS_ADMIN and nothing else" grep -q '^CapEff:[[:space:]]*0000000000200000$' "/proc/$c_pid/status"
	check "... nor can it gain another (bounding set)" grep -q '^CapBnd:[[:space:]]*0000000000200000$' "/proc/$c_pid/status"
	check "the instance has no_new_privs" grep -q '^NoNewPrivs:[[:space:]]*1' "/proc/$c_pid/status"
fi
lists_capability() { control alice GET /v1/servers | jq -e '.[] | select(.name == "privtest") | .capabilities == ["CAP_SYS_ADMIN"]' >/dev/null; }
check "the control API lists the capability" lists_capability
# Not from a package, as a privileged definition.
mkdir -p /usr/share/mcp-gateway/servers.d
sed 's/^name: privtest/name: privvendor/' /etc/mcp-gateway/servers.d/privtest.yaml >/usr/share/mcp-gateway/servers.d/privvendor.yaml
/usr/bin/mcp-gateway --check --policy-data= >/root/privtest/vendor-check.log 2>&1
check "a vendor definition with a capability is refused" grep -q 'sandbox.capabilities: only allowed in' /root/privtest/vendor-check.log
rm -f /usr/share/mcp-gateway/servers.d/privvendor.yaml
cp /root/privtest/privileged.yaml /etc/mcp-gateway/servers.d/privtest.yaml
systemctl restart mcp-gateway.service
wait_socket

section "Server setups"
# The setup packages with the real servers, built from upstream
# (test/vm/build-servers.sh): each server reads through the gateway, and
# systemd changes a unit after an approval, all with SELinux enforcing.
if [ -n "$setups" ]; then
	if [ "$setups" = built ]; then
		# Without their xattrs (SELinux contexts among them): "." would
		# give / that of the directory they come from (admin_home_t).
		cp -r --preserve=mode,ownership,timestamps "$servers/." /
		# CI artifacts do not keep file modes.
		chmod 0755 /usr/bin/systemd-mcp /usr/bin/firewalld-mcp /usr/bin/mcp-server-zypp \
			/usr/bin/suseconnect-mcp /usr/libexec/mcp-server-zypp/zypp-mcp-tool /usr/bin/mcp-server-snapper \
			/usr/bin/podman-mcp-server
		restorecon -R /usr/bin/systemd-mcp /usr/bin/firewalld-mcp /usr/bin/mcp-server-zypp \
			/usr/bin/suseconnect-mcp /usr/libexec/mcp-server-zypp /usr/bin/mcp-server-snapper \
			/usr/bin/podman-mcp-server
		[ -n "$rpms" ] || die "--servers needs --rpms (the setup packages)"
		rpm -Uvh --nodeps "$rpms"/mcp-gateway-profile-*.rpm >/dev/null || die "installing the setup packages failed"
	fi
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
		/usr/bin/suseconnect-mcp:mcpsrv_suseconnect_exec_t /usr/bin/mcp-server-snapper:mcpsrv_snapper_exec_t \
		/usr/bin/podman-mcp-server:mcpsrv_podman_exec_t; do
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
	jq '.bindings.users.alice += ["systemd-operator", "firewalld-reader", "zypp-reader", "suseconnect-reader", "snapper-operator", "podman-operator"]' \
		/etc/mcp-gateway/policy/rbac/data.yaml >/root/vmtest/data.json &&
		cat /root/vmtest/data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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
			-roles "/usr/share/mcp-gateway/policy/mcp/profiles/$s/data.yaml" >"/root/vmtest/inspect-$s.txt" 2>&1
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
	# Without its read action's file, polkit does not know the action:
	# a warning only for systemd-mcp 0.3.4, which checks reads with it,
	# not for the server here (built at 0.3.5 or later, or the product's).
	gk=/usr/share/polkit-1/actions/com.suse.gatekeeper.policy
	sd_version=$(journalctl -u 'mcp-systemd-*' -o cat 2>/dev/null | sed -n 's/.*starting systemd-mcp.* version=\([^ ]*\).*/\1/p' | tail -1)
	echo "  systemd-mcp version: ${sd_version:-unknown}"
	if [ -f "$gk" ] && [ -n "$sd_version" ] && [ "$sd_version" != 0.3.4 ]; then
		mv "$gk" /root/vmtest/gatekeeper.policy
		mcp-gateway-admin doctor --server systemd >/root/vmtest/doctor-gk.txt 2>&1
		mv /root/vmtest/gatekeeper.policy "$gk" && restorecon "$gk"
		grep -E 'polkit mcp-sysmgmt' /root/vmtest/doctor-gk.txt | sed 's/^/  /'
		check "doctor: no readlog warning without the action file for systemd-mcp 0.3.5 or later" \
			bash -c '! grep -q "is not registered" /root/vmtest/doctor-gk.txt'
	fi
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

	# podman: alice's own rootless Podman, through her Podman service
	# (podman.socket of her systemd, kept running by lingering), the
	# instance running as alice in mcpsrv_podman_t.
	zypper -n in --no-recommends podman >/dev/null || echo "  installing podman failed"
	grep -q '^alice:' /etc/subuid || usermod --add-subuids 100000-165535 --add-subgids 100000-165535 alice
	loginctl enable-linger alice
	alice_uid=$(id -u alice)
	eventually 30 test -d "/run/user/$alice_uid"
	systemctl --user -M alice@ enable --now podman.socket 2>&1 | sed 's/^/  /'
	check "podman: alice's Podman socket is there" eventually 30 test -S "/run/user/$alice_uid/podman/podman.sock"
	ls -Z "/run/user/$alice_uid/podman/podman.sock" | sed 's/^/  /'
	# Its roles name only tools the server has (discovery: instance, so
	# through the gateway as alice rather than inspect).
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server podman --method tools/list --params '{}' 2>&1)
	rc=$?
	echo "  [alice podman/tools/list] rc=$rc ${out:0:300}"
	# The shipped roles (YAML) as OPA has them.
	curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/profiles/podman | jq .result >/root/vmtest/podman-roles.json
	podman_missing=$(jq -rn --argjson list "$out" --slurpfile roles /root/vmtest/podman-roles.json \
		'[$roles[0].roles[].permissions[].tool | select(. != "*")] - [$list.tools[].name] | unique | join(" ")' 2>&1)
	check "podman: the roles name only tools the server has${podman_missing:+ (missing: $podman_missing)}" \
		test "$rc" = 0 -a -z "$podman_missing"
	check "podman: image_build's description has the tool note" succeeded_with "Administrator's note: containerFile is an absolute path"
	stool alice podman container_list '{}'
	check "podman: container_list" test "$rc" = 0
	stool alice podman volume_list '{}'
	check "podman: volume_list" test "$rc" = 0
	# Registry credentials, as alice's session has them: podman login's
	# in her runtime directory, and one kept in her home. Rootful Podman
	# has made /run/containers root's (0700); the instance must not look
	# there (the Podman bindings do without XDG_RUNTIME_DIR), and must
	# read both files (Landlock, SELinux).
	mkdir -p -m 0700 /run/containers/"$alice_uid" && chown alice: /run/containers/"$alice_uid" && chmod 0700 /run/containers
	printf '{"auths":{}}\n' >/run/containers/"$alice_uid"/auth.json && chown alice: /run/containers/"$alice_uid"/auth.json
	runuser -u alice -- sh -c "mkdir -p /run/user/$alice_uid/containers ~/.config/containers &&
		printf '%s\n' '{\"auths\":{\"registry.invalid\":{\"auth\":\"dm10ZXN0OnZtdGVzdA==\"}}}' >/run/user/$alice_uid/containers/auth.json &&
		cp /run/user/$alice_uid/containers/auth.json ~/.config/containers/auth.json"
	restorecon -R /home/alice/.config 2>/dev/null
	ls -Z /run/user/"$alice_uid"/containers/auth.json /home/alice/.config/containers/auth.json | sed 's/^/  /'
	stool_approved alice podman image_pull '{"imageName":"registry.opensuse.org/opensuse/busybox:latest"}'
	check "podman: image_pull after an approval, with credentials in the runtime directory and the home" test "$rc" = 0
	podman_pid=""
	for unit in $(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-podman-*' | awk '{print $1}'); do
		pid=$(systemctl show -p MainPID --value "$unit")
		[ "$(proc_user "$pid")" = alice ] && podman_pid=$pid
	done
	podman_env() { tr '\0' '\n' <"/proc/$podman_pid/environ" | grep -qx "$1"; }
	check "podman: the instance has alice's runtime directory" \
		test -n "$podman_pid" -a "$(podman_env "XDG_RUNTIME_DIR=/run/user/$alice_uid" && echo yes)" = yes
	if command -v ausearch >/dev/null; then
		check "podman: no SELinux denials for the server" bash -c '! ausearch -m avc -c podman-mcp-serv >/dev/null 2>&1'
	fi
	# A build from alice's home: the context is read under Landlock.
	mkdir -p /home/alice/vmtest-image
	printf 'FROM registry.opensuse.org/opensuse/busybox:latest\nLABEL vmtest=1\n' >/home/alice/vmtest-image/Containerfile
	chown -R alice: /home/alice/vmtest-image && restorecon -R /home/alice/vmtest-image
	stool_approved alice podman image_build '{"containerFile":"/home/alice/vmtest-image/Containerfile","imageName":"localhost/vmtest-image:1"}'
	check "podman: image_build from the home after an approval" test "$rc" = 0
	stool alice podman image_list '{}'
	check "podman: image_list shows the pulled and the built image" \
		bash -c 'grep -q "busybox" <<<"$1" && grep -q "vmtest-image" <<<"$1"' _ "$out"
	# Asked of alice's Podman service itself, through her socket.
	check "podman: the images are alice's own" bash -c "podman --url unix:///run/user/$alice_uid/podman/podman.sock images --format '{{.Repository}}' | grep -q vmtest-image"

	# The setups' rulesets (step 30): the servers above ran under them.
	for s in systemd firewalld zypp podman; do
		check "landlock: the $s server starts restricted" \
			bash -c "journalctl -q --no-pager -u 'mcp-$s-*' -o cat | grep -q 'mcp-landlock: Landlock ABI'"
	done

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

	# snapper-root.yaml (root in the sandbox, no capabilities): set_config.
	ln -sf /usr/share/mcp-gateway/profiles/snapper-root.yaml /etc/mcp-gateway/servers.d/snapper.yaml
	systemctl restart mcp-gateway.service
	wait_socket
	stool alice snapper list_configs '{}'
	check "snapper (root, sandbox): list_configs" succeeded_with "vmtest"
	sr_pid=""
	for unit in $(systemctl list-units --type=service --state=running --plain --no-legend 'mcp-snapper-*' | awk '{print $1}'); do
		sr_pid=$(systemctl show -p MainPID --value "$unit")
	done
	check "snapper (root, sandbox): the instance runs as root" test "$(proc_user "${sr_pid:-0}")" = root
	check "snapper (root, sandbox): ... without capabilities" bash -c "! has_capabilities ${sr_pid:-0}"
	out=$(runuser -u alice -- /usr/local/bin/mcpcall --server snapper --method tools/list --params '{}' 2>&1)
	rc=$?
	check "snapper (root, sandbox): rollback's description has the tool note" \
		succeeded_with "Administrator's note: Not available in this setup"
	stool_approved alice snapper set_config '{"config":"vmtest","values":{"NUMBER_LIMIT":"9"}}'
	check "snapper (root, sandbox): set_config after an approval" test "$rc" = 0
	check "snapper (root, sandbox): the config changed" grep -q '^NUMBER_LIMIT="9"' /etc/snapper/configs/vmtest
	if command -v ausearch >/dev/null; then
		check "snapper (root, sandbox): no SELinux denials" \
			bash -c '! ausearch -m avc -ts recent 2>/dev/null | grep -q mcpsrv_snapper_t'
	fi

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

	for s in systemd firewalld zypp suseconnect snapper podman; do
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
	grep -A6 '^landlock:' "$prof/fwprof.yaml" | sed 's/^/  | /'
	check "profile: the drafted definition has a landlock" grep -q '^landlock:' "$prof/fwprof.yaml"
	check "profile: the report lists the Landlock trees" grep -q '^Landlock: trees beyond the base' "$prof.txt"
	cp "$prof/fwprof.yaml" /etc/mcp-gateway/servers.d/fwprof.yaml
	check "profile: the drafted definition is valid" mcp-gateway --check --policy-data=
	mcp-gateway-admin profile -server fwprof -verify >"$prof-verify.txt" 2>&1
	rc=$?
	sed 's/^/  /' "$prof-verify.txt" | head -40
	check "profile: with the drafted module the server runs enforcing without denials" test "$rc" = 0
	check "profile: ... and under the drafted landlock" \
		bash -c "journalctl -q --no-pager -u 'mcp-fwprof-*' -o cat | grep -q 'mcp-landlock: Landlock ABI'"
	[ "$rc" = 0 ] || journalctl -u 'mcp-fwprof-*' --no-pager -o cat 2>/dev/null | tail -15 | sed 's/^/  [fwprof] /'
else
	skip "the server setups (${missing}not installed; or --servers)"
fi

section "MCP server over HTTP"
# A server defined with url: each instance is mcp-http-connector in
# mcpsrv_http_t, which reaches only the server's address and sends the
# credential as a header. The server: privsrv -http on an HTTP port.
/usr/libexec/mcpgw-privtest -http 127.0.0.1:8008 &
http_pid=$!
echo vmtest-token | install -m 0600 /dev/stdin /etc/mcp-gateway/credentials/httptoken
jq '.roles.tester.permissions += [{"server": "httpecho", "tool": "whoami"}]' \
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/http-data.json &&
	cat /root/http-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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
check "landlock: the connector restricts itself" \
	bash -c "journalctl -q --no-pager -u '${h_unit:-none}' -o cat | grep -q 'msg=restricted landlock=\"Landlock ABI'"
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
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/http-data.json &&
	cat /root/http-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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
		/etc/mcp-gateway/policy/rbac/data.yaml >/root/si-data.json &&
		cat /root/si-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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
	skip "signing in (semanage or openssl not installed)"
fi

section "HTTPS listener for remote agents"
# The gateway's own listener (http.listen) as remote agents reach it: set
# up with mcp-gateway-admin setup http against an OpenID provider
# (privsrv -idp, https://idp.vmtest, which hands out the tokens the test
# asks for); bearer tokens checked for audience, expiry, signing key and
# the scope every token needs (mcp); the principal acting as the local
# account its preferred_username names; the role data's scope ceiling
# with step-up; an agent of MCP 2026-07-28 without a session; a renewed
# certificate taken without a restart.
if command -v semanage >/dev/null && command -v openssl >/dev/null; then
	hl_since=$(date +%s)
	hl_url=https://gw.vmtest:9443/mcp
	semanage port -a -t mcp_port_t -p tcp 9443 2>/dev/null || semanage port -m -t mcp_port_t -p tcp 9443
	grep -q 'idp\.vmtest' /etc/hosts || echo '127.0.0.6 idp.vmtest' >>/etc/hosts
	grep -q 'gw\.vmtest' /etc/hosts || echo '127.0.0.5 gw.vmtest' >>/etc/hosts
	/usr/libexec/mcpgw-privtest -idp 127.0.0.6:443 /root/vmtest-idp.pem &
	idp_pid=$!
	eventually 10 test -s /root/vmtest-idp.pem
	# hl_cert: a new certificate and key for gw.vmtest; both certificates
	# trusted, as clients and the gateway must.
	hl_cert() {
		install -d -m 0750 -g mcp-gateway /etc/mcp-gateway/tls
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=gw.vmtest \
			-addext subjectAltName=DNS:gw.vmtest -keyout /root/vmtest-gw-key.pem -out /root/vmtest-gw.pem 2>/dev/null
		install -m 0640 -g mcp-gateway /root/vmtest-gw-key.pem /etc/mcp-gateway/tls/key.pem
		install -m 0644 /root/vmtest-gw.pem /etc/mcp-gateway/tls/cert.pem
		restorecon -R /etc/mcp-gateway/tls
		install -m 0644 /root/vmtest-gw.pem /etc/pki/trust/anchors/mcp-vmtest-gw.pem
		install -m 0644 /root/vmtest-idp.pem /etc/pki/trust/anchors/mcp-vmtest-idp.pem
		update-ca-certificates
	}
	hl_cert
	mcp-gateway-admin setup http -url "$hl_url" -issuer https://idp.vmtest -cert /etc/mcp-gateway/tls/cert.pem \
		-key /etc/mcp-gateway/tls/key.pem -local-user-claim preferred_username -scopes mcp -write >/root/hl-setup.txt 2>&1
	sed 's/^/  /' /root/hl-setup.txt | head -30
	hl_dropin=/etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml
	check "setup http writes the http block to the drop-in" grep -qF "audience: $hl_url" "$hl_dropin"
	sed 's/^/  | /' "$hl_dropin"
	check "... and no gateway.yaml: the package default stays in force" test ! -e /etc/mcp-gateway/gateway.yaml
	check "... the drop-in is labeled mcpgw_etc_t" file_has_type "$hl_dropin" mcpgw_etc_t
	check "the configuration with the listener is valid" /usr/bin/mcp-gateway --check --policy-data=
	# http.listen takes effect at the next start.
	systemctl restart mcp-gateway.service
	wait_socket
	hl_listening() { curl -s --noproxy '*' -o /dev/null "https://gw.vmtest:9443/.well-known/oauth-protected-resource/mcp"; }
	check "the gateway listens on 9443" eventually 30 hl_listening

	# hl_tok QUERY: a token from the identity provider (privsrv -idp).
	hl_tok() { curl -sf --noproxy '*' "https://idp.vmtest/token?$1"; }
	# hl_post TOKEN PATH BODY [HEADER...]: a request as a remote agent;
	# sets hl_code, hl_hdr and hl_body.
	hl_post() {
		local tok=$1 path=$2 body=$3 h=()
		shift 3
		for x in "$@"; do h+=(-H "$x"); done
		[ -n "$tok" ] && h+=(-H "Authorization: Bearer $tok")
		hl_code=$(curl -s --noproxy '*' -o /root/hl-body -D /root/hl-hdr -w '%{http_code}' \
			-H 'Content-Type: application/json' -H 'Accept: application/json' "${h[@]}" --data "$body" \
			"https://gw.vmtest:9443$path")
		hl_hdr=$(tr -d '\r' </root/hl-hdr)
		hl_body=$(cat /root/hl-body)
		echo "  POST $path: $hl_code ${hl_body:0:200}"
	}
	hl_init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"vmtest-remote","version":"1"}}}'
	# hl_open TOKEN: a session at /mcp/fs; sets hl_sid. hl_call TOKEN
	# TOOL ARGS: a call in it.
	hl_open() {
		hl_post "$1" /mcp/fs "$hl_init"
		hl_sid=$(sed -n 's/^[Mm][Cc][Pp]-[Ss]ession-[Ii][Dd]: *//p' <<<"$hl_hdr")
		[ "$hl_code" = 200 ] && [ -n "$hl_sid" ] &&
			hl_post "$1" /mcp/fs '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
				"Mcp-Session-Id: $hl_sid" "MCP-Protocol-Version: 2025-06-18"
	}
	hl_call() {
		hl_post "$1" /mcp/fs "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}" \
			"Mcp-Session-Id: $hl_sid" "MCP-Protocol-Version: 2025-06-18"
	}
	hl_ok() { [ "$hl_code" = 200 ] && grep -qF -- "$1" <<<"$hl_body"; }
	hl_status() { [ "$hl_code" = "$1" ] && grep -qiF -- "$2" <<<"$hl_hdr"; }

	hl_meta=$(curl -s --noproxy '*' https://gw.vmtest:9443/.well-known/oauth-protected-resource/mcp)
	echo "  $hl_meta"
	hl_meta_ok() { jq -e --arg r "$hl_url" '.resource == $r and (.authorization_servers | index("https://idp.vmtest")) != null' >/dev/null <<<"$hl_meta"; }
	check "the listener announces its resource and issuer (RFC 9728)" hl_meta_ok
	hl_tok "aud=$hl_url&sub=alice&preferred_username=alice&scope=mcp" >/root/hl-token
	mcp-gateway-admin setup http -token /root/hl-token >/root/hl-setup-token.txt 2>&1
	hl_setup_rc=$?
	sed 's/^/  /' /root/hl-setup-token.txt | head -30
	check "setup http checks the listener end to end with alice's token" test "$hl_setup_rc" = 0

	hl_post "" /mcp/fs "$hl_init"
	check "without a token: 401, pointing to the resource metadata" hl_status 401 'www-authenticate: Bearer resource_metadata='
	for c in "an expired token:exp=-60&aud=$hl_url" "a token for another audience:aud=https://other.vmtest/mcp" \
		"a token signed with an unknown key:key=other&aud=$hl_url"; do
		hl_post "$(hl_tok "sub=alice&preferred_username=alice&scope=mcp&${c#*:}")" /mcp/fs "$hl_init"
		check "${c%%:*}: 401 invalid_token" hl_status 401 'error="invalid_token"'
	done
	hl_post "$(hl_tok "aud=$hl_url&sub=alice&preferred_username=alice&scope=openid")" /mcp/fs "$hl_init"
	check "a token without the scope every token needs: 403 insufficient_scope" hl_status 403 'error="insufficient_scope"'

	hl_alice=$(hl_tok "aud=$hl_url&sub=alice&preferred_username=alice&scope=mcp")
	hl_open "$hl_alice"
	check "alice's token opens a session" test -n "$hl_sid"
	hl_call "$hl_alice" read_file '{"path":"/home/alice/secret.txt"}'
	check "alice reads her file remotely, as her local account" hl_ok "alice secret"
	hl_open "$(hl_tok "aud=$hl_url&sub=zed&scope=mcp")"
	hl_call "$(hl_tok "aud=$hl_url&sub=zed&scope=mcp")" read_file '{"path":"/home/alice/secret.txt"}'
	hl_refused() { [ "$hl_code" = 200 ] && grep -qF 'no matching permission' <<<"$hl_body" && ! grep -qF 'alice secret' <<<"$hl_body"; }
	check "a remote principal without a role is refused" hl_refused

	# The role data's scope ceiling: mcp:read reads, writing needs mcp:write.
	jq '.scopes = {"mcp:read": {"permissions": [{"server": "fs", "tool": "read_*"}]}, "mcp:write": {"roles": ["tester"]}}' \
		/etc/mcp-gateway/policy/rbac/data.yaml >/root/hl-data.json &&
		cat /root/hl-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
	hl_read=$(hl_tok "aud=$hl_url&sub=alice&preferred_username=alice&scope=mcp+mcp:read")
	hl_open "$hl_read"
	hl_reads() { hl_call "$hl_read" read_file '{"path":"/home/alice/secret.txt"}' && hl_ok "alice secret"; }
	check "a token with mcp:read reads" eventually 20 hl_reads
	hl_call "$hl_read" write_file '{"path":"/home/alice/remote.txt","content":"remote"}'
	check "writing is outside its scopes: 403, asking for mcp:write (step-up)" hl_status 403 'mcp:write'
	check "... and nothing is written" test ! -e /home/alice/remote.txt
	# Decision records: "audit":true with the token's scopes.
	hl_scopes_audited() { journalctl -u mcp-gateway.service -o cat --since "@$hl_since" | grep -F '"audit":true' | grep -qF '"scopes":"mcp mcp:read"'; }
	check "the decision is audited with the token's scopes" hl_scopes_audited
	jq 'del(.scopes)' /etc/mcp-gateway/policy/rbac/data.yaml >/root/hl-data.json &&
		cat /root/hl-data.json >/etc/mcp-gateway/policy/rbac/data.yaml

	# An agent of MCP 2026-07-28: no initialize, no session; the protocol
	# version, method and tool name in headers as in the body.
	hl_modern() {
		hl_post "$hl_alice" /mcp/fs '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/alice/secret.txt"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"vmtest-modern","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}' \
			"MCP-Protocol-Version: 2026-07-28" "Mcp-Method: tools/call" "Mcp-Name: read_file"
		hl_ok "alice secret"
	}
	check "an agent of MCP 2026-07-28 reads it without a session" eventually 20 hl_modern
	hl_no_session() { ! grep -qi '^mcp-session-id:' <<<"$hl_hdr"; }
	check "... and gets no session" hl_no_session

	# A renewed certificate: new connections get it, the gateway runs on.
	hl_fp() { openssl s_client -connect 127.0.0.5:9443 -servername gw.vmtest </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256; }
	hl_fp_before=$(hl_fp)
	hl_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
	hl_cert
	hl_renewed() { [ -n "$hl_fp_before" ] && [ "$(hl_fp)" != "$hl_fp_before" ]; }
	check "a renewed certificate is served without a restart" eventually 30 hl_renewed
	check "... and the gateway was not restarted" test "$(systemctl show -p MainPID --value mcp-gateway.service)" = "$hl_pid"
	hl_open "$hl_alice"
	hl_call "$hl_alice" read_file '{"path":"/home/alice/secret.txt"}'
	check "calls work with the renewed certificate" hl_ok "alice secret"

	# A remote principal without a local account (zed: no account on
	# this host, none its token names), with roles for fs and exec. fs
	# works in the user's home (--root ${HOME}), which zed has not: it is
	# not offered (its root would be "/", the working directory of the
	# dynamic user it would run as). exec, whose definition names no
	# home, is.
	jq '.bindings.users.zed = ["tester", "commands"]' /etc/mcp-gateway/policy/rbac/data.yaml >/root/hl-data.json &&
		cat /root/hl-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
	hl_zed=$(hl_tok "aud=$hl_url&sub=zed&scope=mcp")
	# hl_agg TOKEN BODY: a request at the aggregated endpoint, in the
	# session hl_agg_open opened (hl_agg_sid).
	hl_agg() { hl_post "$1" /mcp "$2" ${hl_agg_sid:+"Mcp-Session-Id: $hl_agg_sid"} "MCP-Protocol-Version: 2025-06-18"; }
	hl_agg_open() {
		hl_agg_sid=
		hl_post "$1" /mcp "$hl_init"
		hl_agg_sid=$(sed -n 's/^[Mm][Cc][Pp]-[Ss]ession-[Ii][Dd]: *//p' <<<"$hl_hdr")
		[ -n "$hl_agg_sid" ] && hl_agg "$1" '{"jsonrpc":"2.0","method":"notifications/initialized"}'
	}
	hl_zed_tools() {
		hl_agg_open "$hl_zed" && hl_agg "$hl_zed" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' &&
			jq -e '[.result.tools[].name] | (index("exec__echo_word") != null) and (map(select(startswith("fs__"))) | length == 0)' \
				<<<"$hl_body" >/dev/null
	}
	check "no local account: exec is in its tool list, fs (--root \${HOME}) is not" eventually 20 hl_zed_tools
	hl_no_home="server fs works in the user's home directory; a principal without a local account has none"
	hl_has() { grep -qF -- "$1" <<<"$hl_body"; }
	hl_agg "$hl_zed" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"/etc/os-release"}}}'
	check "... a call to fs is refused: no home directory" hl_has "$hl_no_home"
	check "... and nothing of the file is sent" bash -c '! grep -qF PRETTY_NAME <<<"$1"' _ "$hl_body"
	hl_post "$hl_zed" /mcp/fs "$hl_init"
	check "... and no session opens at fs's own endpoint" hl_has "$hl_no_home"
	hl_agg "$hl_zed" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec__echo_word","arguments":{"word":"remote"}}}'
	check "... exec runs for it" bash -c 'jq -e ".result.isError == false" <<<"$1" >/dev/null && grep -qF remote <<<"$1"' _ "$hl_body"
	hl_no_home_logged() {
		journalctl -u mcp-gateway.service -o cat --since "@$hl_since" |
			grep -F "server not offered to a principal without a home" | grep -q 'server=fs'
	}
	check "... the gateway says why" hl_no_home_logged
	jq 'del(.bindings.users.zed)' /etc/mcp-gateway/policy/rbac/data.yaml >/root/hl-data.json &&
		cat /root/hl-data.json >/etc/mcp-gateway/policy/rbac/data.yaml

	# Limits (D14): at limits.sessions_per_principal, the principal's
	# longest-idle HTTP session makes room for a new one, as agents often
	# leave without ending theirs. bob, whose account the token names
	# (local_user_claim), has no HTTP sessions above to count.
	check "limits: config set lowers sessions_per_principal to 2" \
		sh -c 'mcp-gateway-admin config set limits.sessions_per_principal 2 | grep -qF "is in force"'
	hl_lim=$(hl_tok "aud=$hl_url&sub=bob&preferred_username=bob&scope=mcp")
	hl_open "$hl_lim"
	hl_lim1=$hl_sid
	hl_open "$hl_lim"
	hl_lim2=$hl_sid
	check "limits: a third HTTP session at the limit is admitted" hl_open "$hl_lim"
	hl_sid=$hl_lim1
	hl_call "$hl_lim" read_file '{"path":"/home/bob/secret.txt"}'
	check "limits: ... the longest-idle one made room (404)" test "$hl_code" = 404
	hl_sid=$hl_lim2
	hl_call "$hl_lim" read_file '{"path":"/home/bob/secret.txt"}'
	check "limits: ... and the other goes on" hl_ok "bob secret"
	hl_evicted() {
		journalctl -u mcp-gateway.service -o cat --since "@$hl_since" |
			grep -F "ended an idle session for a new one at the session limit" | grep -q 'sub=bob'
	}
	check "limits: ... the gateway says which it ended" hl_evicted
	mcp-gateway-admin config unset limits.sessions_per_principal >/dev/null

	# config unset takes setup http's keys out of the drop-in again.
	for k in listen cert_file key_file issuer audience local_user_claim scopes groups_claim; do
		mcp-gateway-admin config unset "http.$k" >/dev/null
	done
	check "config unset takes setup http's keys out again" bash -c '! grep -qF "http:" "$1" 2>/dev/null' _ "$hl_dropin"
	rm -f /etc/pki/trust/anchors/mcp-vmtest-gw.pem /etc/pki/trust/anchors/mcp-vmtest-idp.pem
	update-ca-certificates
	systemctl restart mcp-gateway.service
	wait_socket
	kill "$idp_pid" 2>/dev/null
	wait "$idp_pid" 2>/dev/null
else
	skip "the HTTPS listener (semanage or openssl not installed)"
fi

section "Obligations under the real OPA"
# The obligations of chapter 6, as the shipped policy merges them and the
# gateway enforces them: redaction, pseudonymization with
# re-identification, the size limit, the rate limit and full audit. dora
# holds only the role "obligated", so that no other permission adds to
# hers.
ob_since=$(date +%s)
useradd -m dora
usermod -aG mcp-users dora
runuser -u dora -- sh -c 'umask 077
	echo "customer CUST-004711 mail dora@example.com password=hunter2 again dora@example.com" >/home/dora/record.txt
	head -c 4000 /dev/zero | tr "\0" x >/home/dora/large.txt
	echo "under the limit" >/home/dora/small.txt'
jq '.roles.obligated = {"permissions": [
	{"server": "fs", "tool": "read_file", "obligations": {
		"redact_output": "(?i)password=\\S+",
		"pseudonymize": {"detect": ["email"], "patterns": {"customer": "CUST-[0-9]{6}"}},
		"max_output_bytes": 2048, "audit": "full"}},
	{"server": "fs", "tool": "write_file", "args": {"path": "^${home}/"}, "obligations": {"reidentify": "content"}},
	{"server": "fs", "tool": "list_directory"},
	{"server": "fs", "tool": "get_file_info", "obligations": {"rate_limit": "2/m"}}]}
	| .bindings.users.dora = ["obligated"]' \
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/ob-data.json &&
	cat /root/ob-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
check "the role data with obligations is valid" mcp-gateway --check-policy-data
# The role data takes effect at once; dora's first call waits for it.
ob_read() { tool dora read_file '{"path":"/home/dora/record.txt"}' && [ "$rc" = 0 ]; }
check "dora reads her record" eventually 20 ob_read
check "redact_output: the password is replaced by [redacted]" \
	bash -c 'grep -qF "[redacted]" <<<"$1" && ! grep -qF hunter2 <<<"$1"' _ "$out"
check "pseudonymize: the e-mail address is [EMAIL_1], both times" \
	bash -c 'grep -qF "mail [EMAIL_1] [redacted] again [EMAIL_1]" <<<"$1" && ! grep -qF dora@example.com <<<"$1"' _ "$out"
check "pseudonymize: the customer number is [CUSTOMER_1]" \
	bash -c 'grep -qF "customer [CUSTOMER_1]" <<<"$1" && ! grep -qF CUST-004711 <<<"$1"' _ "$out"
# One session: read, read again, write with the pseudonyms. The session's
# vault gives the same value the same pseudonym, and write_file (reidentify
# content) gets the real values.
call dora --method tools/call --params '{"name":"read_file","arguments":{"path":"/home/dora/record.txt"}}' \
	--then '{"name":"read_file","arguments":{"path":"/home/dora/record.txt"}}' \
	--then '{"name":"write_file","arguments":{"path":"/home/dora/reply.txt","content":"to [EMAIL_1] about [CUSTOMER_1]"}}'
check "pseudonymize: a second read in the session gives the same pseudonyms" \
	bash -c '[ "$(grep -cF "mail [EMAIL_1] [redacted] again [EMAIL_1]" <<<"$1")" = 2 ]' _ "$out"
check "reidentify: the session's write reaches the server with the real values" \
	grep -qx 'to dora@example.com about CUST-004711' /home/dora/reply.txt
# Another session has another vault: its pseudonyms are not resolved.
tool dora write_file '{"path":"/home/dora/other.txt","content":"to [EMAIL_1]"}'
check "reidentify: another session's pseudonyms stay as they are" grep -qxF 'to [EMAIL_1]' /home/dora/other.txt
# ob_audited <text> [<text>]: an audit record since the section began
# with both texts.
ob_audited() {
	journalctl -u mcp-gateway.service -o cat --since "@$ob_since" | grep -F '"audit":true' | grep -F -- "$1" |
		grep -qF -- "${2:-$1}"
}
ob_no_email() { ! journalctl -u mcp-gateway.service -o cat --since "@$ob_since" | grep -qF dora@example.com; }
check "audit: what was pseudonymized is recorded, by class" ob_audited '"event":"mcp-pseudonymize"' '"values":"CUSTOMER:1 EMAIL:2"'
check "audit: the decision on the write names the re-identified pseudonyms" ob_audited '"reidentified":2'
check "audit: full, read_file's arguments are recorded verbatim" ob_audited '"args":{"path":"/home/dora/record.txt"}'
check "audit: write_file's arguments only as a digest" ob_audited '"name":"write_file"' '"args_hmac":'
check "the gateway's journal holds no e-mail address" ob_no_email
tool dora read_file '{"path":"/home/dora/small.txt"}'
check "max_output_bytes: a small result is released" succeeded_with "under the limit"
tool dora read_file '{"path":"/home/dora/large.txt"}'
check "max_output_bytes: a larger result is withheld" tool_error_with "output withheld: result of"
check "max_output_bytes: ... and none of it is sent" bash -c '! grep -q xxxxxxxx <<<"$1"' _ "$out"
# The home directory itself, as an agent lists it first. The server
# examines each entry (Go 1.26), and SELinux keeps it from ~/.cache and
# ~/.config: those are listed as [?], the rest as usual.
tool dora list_directory '{"path":"/home/dora"}'
check "list_directory lists the home directory itself" succeeded_with "[FILE] record.txt"
check "... with the entries the server may not examine by name" \
	bash -c 'grep -qE "\[(DIR|\?)\] \.cache" <<<"$1"' _ "$out"
# 2/m per principal, server and tool, across sessions.
call dora --method tools/call --params '{"name":"get_file_info","arguments":{"path":"/home/dora/small.txt"}}' \
	--then '{"name":"get_file_info","arguments":{"path":"/home/dora/small.txt"}}' \
	--then '{"name":"get_file_info","arguments":{"path":"/home/dora/small.txt"}}'
check "rate_limit: two calls a minute, the third is denied" \
	bash -c '[ "$2" = 2 ] && [ "$(grep -c "\"isError\":false" <<<"$1")" = 2 ] && grep -qF "mcp-gateway: rate limit exceeded" <<<"$1"' _ "$out" "$rc"
tool dora get_file_info '{"path":"/home/dora/small.txt"}'
check "rate_limit: ... in a new session too" tool_error_with "rate limit exceeded"
# The kernel record has the reason hex-encoded (it has spaces).
ob_rate_hex=$(printf 'rate limit exceeded' | od -An -tx1 | tr -d ' \n' | tr a-f A-F)
ob_kernel() { audit_since TRUSTED_APP | grep 'op=mcp-decision' | grep 'principal=dora' | grep -q "reason=$ob_rate_hex"; }
check "rate_limit: the denial is in the kernel audit trail" eventually 10 ob_kernel
# dora keeps her role: the self-check names users without one, and that
# is carol alone.

section "Live reload of server definitions"
# A server added, broken, fixed and removed while the gateway runs: it
# keeps running (same PID), and a broken definition changes nothing.
rl_since=$(date +%s)
gw_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
jq '.roles.tester.permissions += [{"server": "fsreload", "tool": "read_*"}]' \
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/rl-data.json &&
	cat /root/rl-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
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
# Drop-ins (step 36): one setting over the default, applied without a
# restart and listed by the doctor; a broken one is named and changes
# nothing; removing it recovers.
check "the package owns gateway.d" test -d /etc/mcp-gateway/gateway.d
printf 'limits:\n  tasks_per_principal: 7\n' >/etc/mcp-gateway/gateway.d/50-vmtest.yaml
ls -Z /etc/mcp-gateway/gateway.d/50-vmtest.yaml | sed 's/^/  /'
check "a drop-in is labeled mcpgw_etc_t" sh -c 'ls -Z /etc/mcp-gateway/gateway.d/50-vmtest.yaml | grep -q ":mcpgw_etc_t:"'
check "a drop-in is applied" eventually 40 rl_journal_has '"changed":"limits.tasks_per_principal"'
check "the doctor lists the drop-in" \
	sh -c 'mcp-gateway-admin doctor --no-start 2>&1 | grep -E "configuration: .*1 drop-in.*50-vmtest.yaml"'
printf 'limits:\n  task_per_principal: 7\n' >/etc/mcp-gateway/gateway.d/60-vmtest-bad.yaml
rl_dropin_error() { rl_status | grep -qF 'gateway.d/60-vmtest-bad.yaml'; }
check "a broken drop-in is reported by its name" eventually 40 rl_dropin_error
check "the audit names the broken drop-in" rl_journal_has '"file":"gateway.d/60-vmtest-bad.yaml"'
check "with a broken drop-in the gateway still serves" rl_works_fs
rm -f /etc/mcp-gateway/gateway.d/50-vmtest.yaml /etc/mcp-gateway/gateway.d/60-vmtest-bad.yaml
check "without the drop-ins, nothing is reported" eventually 40 rl_config_clean
# mcp-gateway-admin config (step 36 B): a reloadable key in force without
# a restart, one that waits for the next start, a refused value that
# changes nothing, only root writes, and unset removes the drop-in again.
cfg_out=$(mcp-gateway-admin config set limits.tasks_per_principal 9 2>&1)
sed 's/^/  /' <<<"$cfg_out"
check "config set puts a reloadable key in force" grep -qF "limits.tasks_per_principal is in force" <<<"$cfg_out"
cfg_get() {
	mcp-gateway-admin config get limits.tasks_per_principal |
		grep -qF "limits.tasks_per_principal: 9  # /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml, line"
}
check "config get names the command's drop-in" cfg_get
check "the command's drop-in is labeled mcpgw_etc_t" \
	sh -c 'ls -Z /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml | grep -q ":mcpgw_etc_t:"'
cfg_restart() { mcp-gateway-admin config set socket_group wheel | grep -qF "socket_group takes effect at the next start"; }
check "config set says when a key takes effect at the next start" cfg_restart
cfg_refused() {
	! mcp-gateway-admin config set limits.tasks_per_principal many 2>/dev/null &&
		grep -qF "tasks_per_principal: 9" /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml
}
check "config set refuses a wrong value and changes nothing" cfg_refused
cfg_not_root() {
	! runuser -u alice -- mcp-gateway-admin config set limits.instances 1 2>/dev/null &&
		! grep -q instances /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml
}
check "config set needs root" cfg_not_root
# supervisor.start_timeout (for small hosts) reloads, and has a minimum.
check "config set puts supervisor.start_timeout in force without a restart" \
	sh -c 'mcp-gateway-admin config set supervisor.start_timeout 2m | grep -qF "supervisor.start_timeout is in force"'
cfg_start_short() {
	! mcp-gateway-admin config set supervisor.start_timeout 500ms >/root/vmtest/cfg-start.txt 2>&1 &&
		grep -qF "supervisor.start_timeout: must be at least 1s" /root/vmtest/cfg-start.txt
}
check "... and refuses less than 1s" cfg_start_short
mcp-gateway-admin config unset supervisor.start_timeout >/dev/null
mcp-gateway-admin config unset socket_group >/dev/null
mcp-gateway-admin config unset limits.tasks_per_principal >/dev/null
check "config unset of the last key removes the drop-in" test ! -e /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml
check "after config unset, nothing is reported" eventually 40 rl_config_clean
check "the gateway was not restarted" test "$(systemctl show -p MainPID --value mcp-gateway.service)" = "$gw_pid"

section "Warm-up (small hosts)"
# supervisor.warm_up: at the next start, the gateway starts the servers'
# shared discovery instances and fills their lists before any client
# asks, so that a slow host's first listing does not wait for them.
check "config set supervisor.warm_up takes effect at the next start" \
	sh -c 'mcp-gateway-admin config set supervisor.warm_up true | grep -qF "supervisor.warm_up takes effect at the next start"'
wu_since=$(date +%s)
systemctl restart mcp-gateway.service
wait_socket
wu_done() { journalctl -u mcp-gateway.service -o cat --since "@$wu_since" | grep -F 'msg="warm-up done"' | grep -q 'failed=0'; }
check "warm-up: done after the start, no server failed" eventually 90 wu_done
journalctl -u mcp-gateway.service -o cat --since "@$wu_since" | grep -F 'warm-up' | sed 's/^/  /'
wu_fs() { systemctl list-units --type=service --state=running --plain --no-legend 'mcp-fs-*' | grep -q .; }
check "... and fs's discovery instance runs, with no client connected yet" wu_fs
wu_listed() { call alice --method tools/list --params '{}' && [ "$rc" = 0 ] && grep -qF list_allowed_directories <<<"$out"; }
check "... and the first listing gets the tools" wu_listed
mcp-gateway-admin config unset supervisor.warm_up >/dev/null
systemctl restart mcp-gateway.service
wait_socket
check "without warm-up, no instance runs after a start" sh -c '! systemctl list-units --type=service --state=running --plain --no-legend "mcp-fs-*" | grep -q .'

section "Listings with custom policy"
# The filter works out the principal's roles once per listing (1.7); an
# addition to mcp.authz.denied is still decided for every tool listed,
# as for calls (user guide, chapter 12).
cl_rego=/etc/mcp-gateway/policy/vmtest_listing.rego
cat >"$cl_rego" <<'EOF'
package mcp.authz

import rego.v1

denied if {
	input.principal.sub == "alice"
	input.resource.server == "fs"
	input.resource.name == "list_allowed_directories"
}
EOF
restorecon "$cl_rego"
cl_list() { call alice --method tools/list --params '{}' && [ "$rc" = 0 ] && grep -qF '"read_file"' <<<"$out"; }
cl_hidden() { cl_list && ! grep -qF '"list_allowed_directories"' <<<"$out"; }
cl_listed() { cl_list && grep -qF '"list_allowed_directories"' <<<"$out"; }
check "a custom denial hides the tool from the listing" eventually 20 cl_hidden
tool alice list_allowed_directories '{}'
check "... and denies its call" failed_without "/home/alice"
rm -f "$cl_rego"
check "without it the tool is listed again" eventually 20 cl_listed
cl_metrics=$(curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/metrics)
check "metrics time the listings' filtering" \
	grep -qE '^mcp_gateway_opa_query_duration_seconds_count\{query="mcp/filter/visible"\} [1-9]' <<<"$cl_metrics"

section "Update without restart"
gw_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
ls -li /usr/bin/mcp-gateway | sed 's/^/  before: /'
if [ -n "$rpms" ]; then
	cp /etc/mcp-gateway/policy/rbac/data.yaml /root/vmtest/up-data.yaml
	rpm -Uvh --force --nodeps "$rpms"/mcp-gateway-[0-9]*.rpm >/dev/null 2>&1
	sleep 2
	ls -li /usr/bin/mcp-gateway | sed 's/^/  after:  /'
	check "a package update does not restart the gateway" \
		test "$(systemctl show -p MainPID --value mcp-gateway.service)" = "$gw_pid"
	check "an update keeps a changed data.yaml as it is" cmp -s /etc/mcp-gateway/policy/rbac/data.yaml /root/vmtest/up-data.yaml
	# An update from 1.4 with its default unchanged in /etc: the copy goes
	# (%posttrans), and the shipped default is in force from then on.
	rm /etc/mcp-gateway/policy/rbac/data.yaml
	cp "$dir/default-1.4.json" /etc/mcp-gateway/policy/rbac/data.json
	restorecon /etc/mcp-gateway/policy/rbac/data.json
	up_out=$(rpm -Uvh --force --nodeps "$rpms"/mcp-gateway-[0-9]*.rpm 2>&1)
	check "an update removes an unchanged default of 1.4 from /etc" test ! -e /etc/mcp-gateway/policy/rbac/data.json
	check "... and says so" grep -qF "the default of an earlier package" <<<"$up_out"
	up_default() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac | jq -e '.result.roles | has("viewer") and (has("tester") | not)' >/dev/null; }
	check "... and the shipped default is in force" eventually 15 up_default
	# Configuration in JSON left over (step 38): the update names it.
	mkdir -p /etc/mcp-gateway/policy/vmtest_up
	echo '{"x": 1}' >/etc/mcp-gateway/policy/vmtest_up/data.json
	up_out=$(rpm -Uvh --force --nodeps "$rpms"/mcp-gateway-[0-9]*.rpm 2>&1)
	check "an update names configuration in JSON left over, with the command" \
		grep -qF "/etc/mcp-gateway/policy/vmtest_up/data.json: configuration in JSON is no longer read since 1.7, and the gateway denies every request until it is converted: mcp-gateway-admin policy convert /etc/mcp-gateway/policy/vmtest_up/data.json" <<<"$up_out"
	rm -r /etc/mcp-gateway/policy/vmtest_up
	cat /root/vmtest/up-data.yaml >/etc/mcp-gateway/policy/rbac/data.yaml
	restorecon /etc/mcp-gateway/policy/rbac/data.yaml
	up_back() { curl -s --unix-socket /run/mcp-gateway/opa.sock http://opa/v1/data/mcp/rbac | jq -e '.result.roles | has("tester")' >/dev/null; }
	check "the test's role data in force again" eventually 15 up_back
else
	skip "a package update does not restart the gateway (no --rpms; the program is replaced below)"
fi
# A reinstall of the same build may leave the file as it is; replace it
# the way an update does (new file renamed over the old one).
cp -p /usr/bin/mcp-gateway /usr/bin/.mcp-gateway.vmtest && mv /usr/bin/.mcp-gateway.vmtest /usr/bin/mcp-gateway &&
	restorecon /usr/bin/mcp-gateway
status=$(control alice GET /v1/status)
echo "  $status"
check "the control API reports the pending restart" grep -qF '"restart_pending":true' <<<"$status"

section "Clients"
# A client through mcp-connect, held open on a fifo: its user sees it
# with its name and the MCP version it got, another user does not, and
# ending it closes its connection (Cockpit's Clients table does the same).
mkdir -p /root/vmtest
rm -f /root/vmtest/client.in
mkfifo /root/vmtest/client.in
runuser -u alice -- mcp-connect --server fs </root/vmtest/client.in >/root/vmtest/client.out 2>&1 &
client_pid=$!
exec 7>/root/vmtest/client.in
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"vmtest-client","version":"1.2"}}}' >&7
cl_listed() {
	clients=$(control alice GET /v1/sessions) &&
		jq -e '[.[] | select(.kind == "session" and .client.name == "vmtest-client" and .client.version == "1.2" and
			.requested == "2025-11-25" and .protocol == "2025-11-25" and .endpoint == "fs")] | length == 1' >/dev/null <<<"$clients"
}
check "a client is listed with its name and MCP version" eventually 10 cl_listed
echo "  $(jq -c '.[] | select(.client.name == "vmtest-client") | {id, sub, transport, client, requested, protocol, endpoint}' <<<"$clients")"
cl_id=$(jq -r '.[] | select(.client.name == "vmtest-client") | .id' <<<"$clients")
cl_hidden() { ! control bob GET /v1/sessions | jq -e '.[] | select(.client.name == "vmtest-client")' >/dev/null; }
check "another user does not see the client" cl_hidden
# The same from the command line (step 35): mcp-gateway-admin clients.
cl_cli=$(runuser -u alice -- mcp-gateway-admin clients 2>&1)
sed 's/^/  /' <<<"$cl_cli"
check "mcp-gateway-admin clients lists the client" grep -qE "^alice +vmtest-client 1.2 +2025-11-25 +fs .* ${cl_id:0:8}" <<<"$cl_cli"
cl_cli_hidden() { ! runuser -u bob -- mcp-gateway-admin clients | grep -q vmtest-client; }
check "mcp-gateway-admin clients: another user does not see it" cl_cli_hidden
cl_cli_refused() {
	local out rc
	out=$(runuser -u bob -- mcp-gateway-admin clients end "${cl_id:0:8}" --yes 2>&1)
	rc=$?
	[ "$rc" = 1 ] && grep -q "no such client" <<<"$out"
}
check "another user may not end it (exit 1, no such client)" cl_cli_refused
check "its user ends the client with mcp-gateway-admin clients end" \
	runuser -u alice -- mcp-gateway-admin clients end "${cl_id:0:8}" --yes
cl_gone() { ! kill -0 "$client_pid" 2>/dev/null; }
check "the ended client's connection closes" eventually 10 cl_gone
exec 7>&-
check "the client got its initialize answer before" grep -q '"protocolVersion":"2025-11-25"' /root/vmtest/client.out
check "ending the client is audited (mcp-session-ended)" eventually 10 journal_since_start_has mcp-session-ended
cl_cli_down() {
	local rc
	runuser -u alice -- mcp-gateway-admin clients --socket /run/mcp-gateway/none.sock >/dev/null 2>&1
	rc=$?
	[ "$rc" = 3 ]
}
check "mcp-gateway-admin clients exits 3 when the gateway does not answer" cl_cli_down

section "Tasks"
# A call of alice's run as a task (MCP 2025-11-25) through mcp-connect:
# mcp-gateway-admin tasks lists it for her, not for bob, and cancels it.
rm -f /root/vmtest/task.in
mkfifo /root/vmtest/task.in
runuser -u alice -- mcp-connect --server exec </root/vmtest/task.in >/root/vmtest/task.out 2>&1 &
task_client=$!
exec 8>/root/vmtest/task.in
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"tasks":{}},"clientInfo":{"name":"vmtest-tasks","version":"1"}}}' >&8
# The call only after the answer: before it, the session has no MCP
# version with tasks yet.
tk_initialized() { grep -q '"protocolVersion":"2025-11-25"' /root/vmtest/task.out; }
check "the task client is initialized" eventually 10 tk_initialized
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
	'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wait","arguments":{},"task":{"ttl":600000}}}' >&8
tk_created() { grep -q '"id":2,"result":{"task":' /root/vmtest/task.out; }
check "the call is answered with a task" eventually 10 tk_created
tk_listed() { tasks=$(runuser -u alice -- mcp-gateway-admin tasks 2>&1) && grep -qE '^exec +wait +alice .* working ' <<<"$tasks"; }
check "mcp-gateway-admin tasks lists the running task" eventually 20 tk_listed
sed 's/^/  /' <<<"$tasks"
tk_id=$(control alice GET /v1/tasks | jq -r '[.[] | select(.server == "exec" and .tool == "wait" and .status == "working")][0].id')
tk_hidden() { ! runuser -u bob -- mcp-gateway-admin tasks | grep -qE '^exec +wait '; }
check "mcp-gateway-admin tasks: another user does not see it" tk_hidden
check "its user cancels it with mcp-gateway-admin tasks cancel" runuser -u alice -- mcp-gateway-admin tasks cancel "${tk_id:0:8}"
tk_cancelled() { control alice GET /v1/tasks | jq -e --arg id "$tk_id" '.[] | select(.id == $id and .status == "cancelled")' >/dev/null; }
check "the task is cancelled" eventually 10 tk_cancelled
tk_ended() {
	local out rc
	out=$(runuser -u alice -- mcp-gateway-admin tasks cancel "$tk_id" 2>&1)
	rc=$?
	[ "$rc" = 1 ] && grep -q "the task has ended" <<<"$out"
}
check "a cancelled task cannot be cancelled again (exit 1)" tk_ended
tk_sleep_gone() { ! pgrep -u alice -x sleep >/dev/null; }
check "the cancelled call's command is ended" eventually 20 tk_sleep_gone
exec 8>&-
kill "$task_client" 2>/dev/null
wait "$task_client" 2>/dev/null

section "Limits"
# The limits per principal (decision D14), lowered with mcp-gateway-admin
# config set while the gateway runs: a session, an instance and a task
# refused at the limit, room again once a session ends or an instance is
# idle, each refusal counted (mcp_gateway_limit_refusals_total) and
# audited (mcp-limit). erin's are the only sessions and instances of hers.
lm_since=$(date +%s)
useradd -m erin
usermod -aG mcp-users erin
jq '.bindings.users.erin = ["tester", "commands"]' /etc/mcp-gateway/policy/rbac/data.yaml >/root/lm-data.json &&
	cat /root/lm-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
# lm_refusals <limit>: the counter of refusals at <limit> (0 before the first).
lm_refusals() {
	local n
	n=$(curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/metrics |
		sed -n "s/^mcp_gateway_limit_refusals_total{limit=\"$1\"} //p")
	echo "${n:-0}"
}
lm_before_sessions=$(lm_refusals sessions)
lm_before_instances=$(lm_refusals instances_per_principal)
lm_before_tasks=$(lm_refusals tasks_per_principal)
# lm_set <key> <value>: a limit in force (config set waits for the reload).
lm_set() { mcp-gateway-admin config set "limits.$1" "$2" | grep -qF "limits.$1 is in force"; }
# lm_hold <name> <server>: a session of erin's held open, with a call made
# in it, so that it uses an instance (a local client holds its connection:
# it is never ended to make room). lm_release <name> ends it.
declare -A lm_pid lm_fd
lm_hold() {
	local fd
	rm -f "/root/vmtest/lm-$1.in"
	mkfifo "/root/vmtest/lm-$1.in"
	runuser -u erin -- mcp-connect --server "$2" <"/root/vmtest/lm-$1.in" >"/root/vmtest/lm-$1.out" 2>&1 &
	lm_pid[$1]=$!
	exec {fd}>"/root/vmtest/lm-$1.in"
	lm_fd[$1]=$fd
	printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"vmtest-limits","version":"1"}}}' >&"$fd"
	eventually 10 grep -q '"id":1,"result"' "/root/vmtest/lm-$1.out" || return 1
	printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
		'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_allowed_directories","arguments":{}}}' >&"$fd"
	eventually 20 grep -q '"id":2,"result"' "/root/vmtest/lm-$1.out"
}
lm_release() {
	eval "exec ${lm_fd[$1]}>&-"
	kill "${lm_pid[$1]}" 2>/dev/null
	wait "${lm_pid[$1]}" 2>/dev/null
}
lm_audited() { # lm_audited <limit>: an mcp-limit record in the journal and the kernel audit trail
	journalctl -u mcp-gateway.service -o cat --since "@$lm_since" | grep -F '"event":"mcp-limit"' |
		grep -F '"principal":"erin"' | grep -qF "\"limit\":\"$1\"" &&
		audit_since TRUSTED_APP | grep 'op=mcp-limit' | grep 'principal=erin' | grep -q "limit=$1"
}

# Sessions: local sessions are never ended to make room, so a third is
# refused; once one ends, there is room again.
check "limits: config set lowers sessions_per_principal to 2" lm_set sessions_per_principal 2
check "limits: erin holds a session" lm_hold one fs
check "limits: ... and a second" lm_hold two fs
call erin --method tools/call --params '{"name":"list_allowed_directories","arguments":{}}'
check "limits: a third session is refused (session limit reached (2))" \
	bash -c '[ "$2" = 1 ] && grep -qF "session limit reached (2)" <<<"$1"' _ "$out" "$rc"
check "limits: ... and audited (mcp-limit)" eventually 10 lm_audited sessions
lm_release two
lm_room() { call erin --method tools/call --params '{"name":"list_allowed_directories","arguments":{}}' && succeeded_with /home/erin; }
check "limits: once a session ends, a new one is admitted" eventually 10 lm_room
mcp-gateway-admin config unset limits.sessions_per_principal >/dev/null

# Instances: the held session uses erin's fs instance, so exec, which needs
# a second, is refused; once the fs instance is idle, it makes room.
check "limits: config set lowers instances_per_principal to 1" lm_set instances_per_principal 1
stool erin exec echo_word '{"word":"limits"}'
check "limits: a second instance is refused while the first is in use (instance limit reached (1))" \
	bash -c '[ "$2" != 0 ] && grep -qF "instance limit reached (1)" <<<"$1"' _ "$out" "$rc"
check "limits: ... and audited" eventually 10 lm_audited instances_per_principal
lm_release one
lm_exec() { stool erin exec echo_word '{"word":"limits"}' && [ "$rc" = 0 ] && grep -qF limits <<<"$out"; }
check "limits: once the first is idle, it makes room for the second" eventually 20 lm_exec
lm_fs_gone() { [ -z "$(instance_pid erin)" ]; }
check "limits: ... and the idle fs instance is stopped" eventually 20 lm_fs_gone
mcp-gateway-admin config unset limits.instances_per_principal >/dev/null

# Tasks: one task (running, or done and kept) at a time; a second is
# refused. The first is cancelled afterwards.
check "limits: config set lowers tasks_per_principal to 1" lm_set tasks_per_principal 1
rm -f /root/vmtest/lm-task.in
mkfifo /root/vmtest/lm-task.in
runuser -u erin -- mcp-connect --server exec </root/vmtest/lm-task.in >/root/vmtest/lm-task.out 2>&1 &
lm_task_client=$!
exec {lm_task_fd}>/root/vmtest/lm-task.in
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"tasks":{}},"clientInfo":{"name":"vmtest-limits","version":"1"}}}' >&"$lm_task_fd"
eventually 10 grep -q '"protocolVersion":"2025-11-25"' /root/vmtest/lm-task.out
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
	'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wait","arguments":{},"task":{"ttl":600000}}}' >&"$lm_task_fd"
lm_task1() { grep -q '"id":2,"result":{"task":' /root/vmtest/lm-task.out; }
check "limits: erin's first task is created" eventually 10 lm_task1
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wait","arguments":{},"task":{"ttl":600000}}}' >&"$lm_task_fd"
lm_task2() { grep '"id":3' /root/vmtest/lm-task.out | grep -qF "task limit reached (1)"; }
check "limits: a second task is refused (task limit reached (1))" eventually 10 lm_task2
grep '"id":3' /root/vmtest/lm-task.out | cut -c1-200 | sed 's/^/  /'
check "limits: ... and audited" eventually 10 lm_audited tasks_per_principal
lm_task_id=$(control erin GET /v1/tasks | jq -r '[.[] | select(.status == "working")][0].id // empty')
[ -n "$lm_task_id" ] && runuser -u erin -- mcp-gateway-admin tasks cancel "$lm_task_id" >/dev/null
exec {lm_task_fd}>&-
kill "$lm_task_client" 2>/dev/null
wait "$lm_task_client" 2>/dev/null
mcp-gateway-admin config unset limits.tasks_per_principal >/dev/null

lm_counted() { [ "$(lm_refusals "$1")" -gt "$2" ]; }
check "limits: the refusals are counted, by limit (sessions)" lm_counted sessions "$lm_before_sessions"
check "limits: ... (instances_per_principal)" lm_counted instances_per_principal "$lm_before_instances"
check "limits: ... (tasks_per_principal)" lm_counted tasks_per_principal "$lm_before_tasks"
check "limits: config unset leaves no drop-in" test ! -e /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml

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
check "metrics tell OPA's query times apart up to 30s" grep -qE '^mcp_gateway_opa_query_duration_seconds_bucket\{query="mcp/authz/decision",le="30"\} [1-9]' <<<"$metrics"
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

section "Failing closed and recovering"
# What fails stays closed, and comes back: OPA stopped denies every call;
# a killed instance is replaced, one that keeps dying is backed off;
# a killed gateway is restarted by systemd, with its grants and pending
# approvals (/var/lib/mcp-gateway). erin's role "asked" needs approvals.
fc_since=$(date +%s)
jq '.roles.asked = {"permissions": [
	{"server": "fs", "tool": "get_file_info", "require_approval": true, "approval_channel": "oob", "approval_scopes": ["once", "1h"]},
	{"server": "fs", "tool": "search_files", "require_approval": true, "approval_channel": "oob"}]}
	| .bindings.users.erin += ["asked"]' \
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/fc-data.json &&
	cat /root/fc-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
runuser -u erin -- sh -c 'echo "erin notes" >/home/erin/notes.txt'
fc_read() { tool erin read_file '{"path":"/home/erin/notes.txt"}' && succeeded_with "erin notes"; }
check "erin reads her file" eventually 20 fc_read

# OPA stopped: no decision, no call; back once OPA is.
systemctl stop mcp-opa.service
tool erin read_file '{"path":"/home/erin/notes.txt"}'
check "OPA stopped: the call is denied (policy evaluation failed)" tool_error_with "policy evaluation failed"
check "... and nothing of the file is sent" failed_without "erin notes"
systemctl start mcp-opa.service
check "OPA back: calls are decided again" eventually 30 fc_read

# A killed instance: the next call starts a new one.
fc_inst=$(instance_pid erin)
echo "  erin's fs instance: ${fc_inst:-none}"
[ -n "$fc_inst" ] && kill -KILL "$fc_inst"
fc_new_inst() { fc_read && [ -n "$(instance_pid erin)" ] && [ "$(instance_pid erin)" != "$fc_inst" ]; }
check "a killed instance is replaced on the next call" eventually 30 fc_new_inst
# An instance that keeps dying soon after its start: each restart waits
# longer (1 s, doubling), and calls meanwhile are told when to retry.
fc_backoff() {
	local pid
	pid=$(instance_pid erin)
	[ -n "$pid" ] && kill -KILL "$pid"
	sleep 0.5
	tool erin read_file '{"path":"/home/erin/notes.txt"}'
	[ "$rc" != 0 ] && grep -qE "backend unavailable; retry in [0-9]+" <<<"$out"
}
check "an instance that keeps dying is backed off (retry in …)" eventually 40 fc_backoff
fc_delayed() {
	journalctl -u mcp-gateway.service -o cat --since "@$fc_since" | grep -F "instance restart delayed" |
		grep -F "server=fs" | grep -qE "failures=[2-9]"
}
check "... and the gateway says so" fc_delayed
check "... until it starts again" eventually 40 fc_read

# fc_approve <scope>: approves erin's first pending approval with <scope>.
fc_approve() {
	local id
	for _ in $(seq 30); do
		id=$(control erin GET /v1/approvals | jq -r '.[0].id // empty')
		[ -n "$id" ] && break
		sleep 1
	done
	echo "  approval: ${id:-none} ($1)"
	[ -n "$id" ] && control erin POST "/v1/approvals/$id" "{\"decision\":\"approve\",\"scope\":\"$1\"}" >/dev/null
}
fc_info() { # fc_info [mcpcall options]: get_file_info of erin's notes; sets $out and $rc
	out=$(runuser -u erin -- /usr/local/bin/mcpcall --server fs "$@" --method tools/call \
		--params '{"name":"get_file_info","arguments":{"path":"/home/erin/notes.txt"}}' 2>&1)
	rc=$?
	echo "  [erin fs/get_file_info] rc=$rc ${out:0:200}"
}
# A grant for 1h (a duration scope: stored, not bound to the session).
fc_info >/root/vmtest/fc-info.out &
fc_call=$!
fc_approve 1h
wait "$fc_call"
cat /root/vmtest/fc-info.out
check "an approved call runs" grep -q 'rc=0 .*size' /root/vmtest/fc-info.out
# A pending approval whose call is lost with the gateway.
runuser -u erin -- /usr/local/bin/mcpcall --server fs --method tools/call \
	--params '{"name":"search_files","arguments":{"path":"/home/erin","pattern":"notes.txt"}}' >/root/vmtest/fc-search.out 2>&1 &
fc_search=$!
fc_pending() { control erin GET /v1/approvals | jq -e '.[] | select(.name == "search_files" and .waiting)' >/dev/null; }
check "a call waits for its approval" eventually 30 fc_pending
fc_pending_id=$(control erin GET /v1/approvals | jq -r '.[] | select(.name == "search_files") | .id')

# The gateway killed: systemd starts it again (Restart=on-failure); the
# watchdog (WatchdogSec) would end a hung one.
check "the gateway has a watchdog" test "$(systemctl show -p WatchdogUSec --value mcp-gateway.service)" != 0
fc_pid=$(systemctl show -p MainPID --value mcp-gateway.service)
kill -KILL "$fc_pid"
fc_restarted() {
	local pid
	pid=$(systemctl show -p MainPID --value mcp-gateway.service)
	[ "$pid" != 0 ] && [ "$pid" != "$fc_pid" ] && systemctl is-active -q mcp-gateway.service && [ -S /run/mcp-gateway/mcp.sock ]
}
check "a killed gateway is started again by systemd" eventually 60 fc_restarted
wait "$fc_search" 2>/dev/null
check "... the waiting call ends with it" bash -c '! grep -q "\"isError\":false" /root/vmtest/fc-search.out'
check "... calls work again" eventually 30 fc_read
fc_info --timeout 15s
check "the 1h grant survives the restart (the call runs without asking)" bash -c '[ "$2" = 0 ] && grep -q size <<<"$1"' _ "$out" "$rc"
fc_grant() { control erin GET /v1/grants | jq -e '.[] | select(.tool == "get_file_info" and .scope == "duration")' >/dev/null; }
check "... and is listed" fc_grant
fc_orphan() {
	control erin GET /v1/approvals | jq -e --arg id "$fc_pending_id" \
		'.[] | select(.id == $id and (.waiting | not) and (.scopes | index("session") | not))' >/dev/null
}
check "the pending approval survives the restart: no call waiting, no session scope" fc_orphan
control erin POST "/v1/approvals/$fc_pending_id" '{"decision":"approve","scope":"once"}' >/dev/null
fc_retry() {
	out=$(runuser -u erin -- /usr/local/bin/mcpcall --server fs --timeout 15s --method tools/call \
		--params '{"name":"search_files","arguments":{"path":"/home/erin","pattern":"notes.txt"}}' 2>&1)
	rc=$?
	echo "  [erin fs/search_files] rc=$rc ${out:0:200}"
	[ "$rc" = 0 ] && grep -q notes.txt <<<"$out"
}
check "... approved once, the same call runs without asking again" fc_retry
gw_pid=$(systemctl show -p MainPID --value mcp-gateway.service)

section "Signed policy bundles"
# Chapter 6, "Signed policy bundles": a change previewed with what-if,
# then OPA switched to a bundle signed on this host (mcp-policy-bundle).
# In bundle mode only signed policy is enforced: role data written to
# /etc/mcp-gateway/policy has no effect until it is signed, and OPA
# refuses a tampered bundle or one signed with another key (the gateway
# then denies everything). OPA goes back to the policy directories after.
# The change: erin may use search_text.
root_control() { curl -s --unix-socket /run/mcp-gateway/control.sock -X "$1" ${3:+--data-binary "$3"} "http://gw$2"; }
pb_search() { # pb_search: erin's search_text; sets $out and $rc
	tool erin search_text '{"path":"/home/erin","query":"erin notes"}'
}
pb_allowed() { pb_search && [ "$rc" = 0 ] && grep -qF notes.txt <<<"$out"; }
pb_denied() { pb_search && [ "$rc" != 0 ] && ! grep -qF notes.txt <<<"$out"; }
pb_read_ok() { tool erin read_file '{"path":"/home/erin/notes.txt"}' && succeeded_with "erin notes"; }
pb_opa_up() { systemctl is-active -q mcp-opa.service && pb_read_ok; }
jq '.roles.searcher = {"permissions": [{"server": "fs", "tool": "search_text"}]} | .bindings.users.erin += ["searcher"]' \
	/etc/mcp-gateway/policy/rbac/data.yaml >/root/pb-data.json
check "erin may not search text yet" pb_denied

# What-if: the decisions the edit would change, without applying it.
root_control POST /v1/policy/whatif "$(cat /root/pb-data.json)" >/root/pb-whatif.json
jq -c '.changes[]? | select(.principal == "user:erin")' /root/pb-whatif.json | head -5 | sed 's/^/  /'
check "what-if: erin's search_text would go from deny to allow" \
	jq -e '.changes[] | select(.principal == "user:erin" and .server == "fs" and .name == "search_text" and .before == "deny" and .after == "allow")' /root/pb-whatif.json
check "... and nothing changed" pb_denied

# Bundle mode, with a key pair made here.
check "mcp-policy-bundle -G makes a key pair" mcp-policy-bundle -G
check "the signing key is labeled mcpgw_signing_key_t" file_has_type /etc/mcp-gateway/bundle/signing.pem mcpgw_signing_key_t
check "mcp-policy-bundle signs a bundle" mcp-policy-bundle -n -r vmtest-1
# Module ids are paths in the bundle: the same for every build, not the
# build's temporary directory.
check "... with the policy at its path in the bundle (/mcp/authz.rego)" \
	bash -c 'tar -tzf /etc/mcp-gateway/bundle/policy.tar.gz 2>/dev/null | grep -qx /mcp/authz.rego'
install -D -m0644 /usr/share/mcp-gateway/opa/signed-bundle.conf /etc/systemd/system/mcp-opa.service.d/policy.conf
systemctl daemon-reload
systemctl restart mcp-opa.service
check "OPA runs the signed bundle" eventually 30 pb_opa_up
root_control GET /v1/policy | jq -c '{mode, bundles}' | sed 's/^/  /'
check "GET /v1/policy: bundle mode, the bundle's revision" \
	bash -c 'curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/policy | jq -e ".mode == \"bundle\" and ([.bundles[]] | index(\"vmtest-1\"))" >/dev/null'

# Role data written to the directory is not signed: no effect.
cat /root/pb-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
sleep 3
check "bundle mode: role data written but not signed has no effect" pb_denied
check "mcp-policy-bundle signs it and restarts OPA" mcp-policy-bundle -r vmtest-2
check "... then it is in force" eventually 30 pb_allowed

# A tampered bundle: a policy file changed after signing, the archive
# repacked with the same entry names (with the leading / opa build
# writes), so that the file's digest is what fails.
rm -rf /root/pb-tamper && mkdir /root/pb-tamper
cp /etc/mcp-gateway/bundle/policy.tar.gz /root/pb-good.tar.gz
tar -xzf /root/pb-good.tar.gz -C /root/pb-tamper 2>/dev/null
pb_rego=$(find /root/pb-tamper -name authz.rego | head -1)
echo "  tampering with ${pb_rego#/root/pb-tamper}"
echo '# changed after signing' >>"${pb_rego:-/root/pb-tamper/none}"
(cd /root/pb-tamper && tar -tzf /root/pb-good.tar.gz 2>/dev/null | sed 's,^/,,' |
	tar -czPf /etc/mcp-gateway/bundle/policy.tar.gz --transform 's,^,/,' --no-recursion -T -)
restorecon /etc/mcp-gateway/bundle/policy.tar.gz
pb_since=$(date +%s)
systemctl restart mcp-opa.service
pb_refused() {
	journalctl -u mcp-opa.service -o cat --since "@$pb_since" | grep -qiE 'verif|signature|digest|hash' &&
		! systemctl is-active -q mcp-opa.service
}
check "OPA refuses a tampered bundle" eventually 30 pb_refused
journalctl -u mcp-opa.service -o cat --since "@$pb_since" | grep -iE 'verif|signature|digest|hash' | head -2 | cut -c1-240 | sed 's/^/  | /'
tool erin read_file '{"path":"/home/erin/notes.txt"}'
check "... and the gateway denies everything (policy evaluation failed)" tool_error_with "policy evaluation failed"
cp /root/pb-good.tar.gz /etc/mcp-gateway/bundle/policy.tar.gz
restorecon /etc/mcp-gateway/bundle/policy.tar.gz
systemctl reset-failed mcp-opa.service
systemctl restart mcp-opa.service
check "the signed bundle back: calls are decided again" eventually 30 pb_allowed

# A bundle signed with another key.
mkdir -p /root/pb-other
mcp-policy-bundle -G -k /root/pb-other/signing.pem -o /root/pb-other/policy.tar.gz >/dev/null
pb_since=$(date +%s)
mcp-policy-bundle -k /root/pb-other/signing.pem -r vmtest-other >/dev/null 2>&1
check "OPA refuses a bundle signed with another key" eventually 30 pb_refused
tool erin read_file '{"path":"/home/erin/notes.txt"}'
check "... and the gateway denies everything" tool_error_with "policy evaluation failed"
# (mcp-policy-bundle restarts OPA only if it runs: here it does not.)
check "signed with the right key again" mcp-policy-bundle -n -r vmtest-3
systemctl reset-failed mcp-opa.service
systemctl restart mcp-opa.service
check "... it is in force: calls are decided again" eventually 30 pb_allowed

# Back to the policy directories.
rm -f /etc/systemd/system/mcp-opa.service.d/policy.conf
systemctl daemon-reload
systemctl reset-failed mcp-opa.service
systemctl restart mcp-opa.service
check "OPA back on the policy directories" eventually 30 pb_opa_up
check "GET /v1/policy: directories mode" \
	bash -c 'curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/policy | jq -e ".mode == \"directories\"" >/dev/null'

section "E-mail approvals"
# Chapter 7, "E-mail": notifications.email with the local postfix. hank's
# calls of fs/read_file need an approval from group:mailers, whose members
# are frank (listed in the group) and gina (her primary group). Without
# the boolean mcpgw_can_send_mail the gateway may not connect to the mail
# server: no mail, the approval as before. With it, both approvers get one
# mail (undisclosed recipients) without the call's arguments; hank, who
# is no approver, gets none.
if zypper -n in --no-recommends postfix >/root/vmtest/mail-install.log 2>&1; then
	systemctl enable --now postfix >/dev/null 2>&1
	groupadd mailers
	useradd -m hank
	useradd -m -G mailers frank
	useradd -m -g mailers gina
	for u in hank frank gina; do usermod -aG mcp-users "$u"; done
	runuser -u hank -- sh -c 'echo "hank notes" >/home/hank/notes.txt'
	cp /etc/mcp-gateway/policy/rbac/data.yaml /root/ml-data-before.json
	jq '.roles.mailed = {"permissions": [{"server": "fs", "tool": "read_file", "require_approval": true, "approval_channel": "oob"}]}
		| .bindings.users.hank = ["mailed"] | .approvers.fs = ["group:mailers"]' \
		/root/ml-data-before.json >/root/ml-data.json &&
		cat /root/ml-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
	check "notifications.email: config set from" sh -c 'mcp-gateway-admin config set notifications.email.from mcp-gateway@localhost | grep -qF "is in force"'
	check "notifications.email: config set smtp localhost:25" sh -c 'mcp-gateway-admin config set notifications.email.smtp localhost:25 | grep -qF "is in force"'
	ml_listening() { (exec 3<>/dev/tcp/127.0.0.1/25) 2>/dev/null; }
	check "postfix listens on port 25" eventually 20 ml_listening
	ml_mail() { cat "/var/spool/mail/$1" 2>/dev/null; }
	# ml_call: hank's read_file, approved by frank once it waits; sets
	# ml_id (the approval) and leaves the result in /root/vmtest/ml-call.out.
	ml_call() {
		runuser -u hank -- /usr/local/bin/mcpcall --server fs --method tools/call \
			--params '{"name":"read_file","arguments":{"path":"/home/hank/notes.txt"}}' >/root/vmtest/ml-call.out 2>&1 &
		local pid=$!
		ml_id=
		for _ in $(seq 30); do
			ml_id=$(control frank GET /v1/approvals | jq -r '.[] | select(.name == "read_file" and .principal.sub == "hank") | .id' 2>/dev/null | head -1)
			[ -n "$ml_id" ] && break
			sleep 1
		done
		echo "  approval: ${ml_id:-none}"
		[ -n "$ml_id" ] && control frank POST "/v1/approvals/$ml_id" '{"decision":"approve","scope":"once"}' >/dev/null
		wait "$pid"
		grep -q '"isError":false' /root/vmtest/ml-call.out
	}

	# Without the boolean: refused by SELinux, logged, the approval works.
	setsebool mcpgw_can_send_mail off
	ml_since=$(date +%s)
	check "without mcpgw_can_send_mail: frank, an approver by group, approves hank's call" ml_call
	ml_not_sent() {
		journalctl -u mcp-gateway.service -o cat --since "@$ml_since" | grep -F "approval mail not sent" | grep -qF "$ml_id"
	}
	check "... the mail is not sent, and the gateway says so" eventually 20 ml_not_sent
	check "... nothing reached frank" bash -c '! grep -qF "$1" "/var/spool/mail/frank" 2>/dev/null' _ "$ml_id"

	# With it: one mail to both approvers.
	setsebool mcpgw_can_send_mail on
	check "with mcpgw_can_send_mail: frank approves hank's call" ml_call
	ml_got() { ml_mail "$1" | grep -qF "$ml_id"; }
	check "... frank, a listed member of the approvers' group, got the mail" eventually 30 ml_got frank
	check "... and gina, whose primary group it is" eventually 30 ml_got gina
	ml_mail frank | grep -E '^(From|To|Subject):' | tail -3 | sed 's/^/  | /'
	check "... its subject names the call and the principal" \
		bash -c 'grep -qF "Subject: [mcp-gateway] Approval needed: fs/read_file for hank" <<<"$1"' _ "$(ml_mail frank)"
	check "... to undisclosed recipients (no approver sees the others)" \
		bash -c 'grep -qF "To: undisclosed-recipients:;" <<<"$1" && ! grep -qw gina <<<"$1"' _ "$(ml_mail frank)"
	check "... without the call's arguments (include_args: false)" bash -c '! grep -qF /home/hank/notes.txt <<<"$1"' _ "$(ml_mail frank)"
	check "hank, who asked and is no approver, got no mail" bash -c '! grep -qF "$1" /var/spool/mail/hank 2>/dev/null' _ "$ml_id"
	ml_sent() {
		journalctl -u mcp-gateway.service -o cat --since "@$ml_since" | grep -F "approval mail sent" | grep -F "$ml_id" | grep -q 'recipients=2'
	}
	check "the gateway logs the mail, to 2 recipients" ml_sent

	mcp-gateway-admin config unset notifications.email.smtp >/dev/null
	mcp-gateway-admin config unset notifications.email.from >/dev/null
	setsebool mcpgw_can_send_mail off
	cat /root/ml-data-before.json >/etc/mcp-gateway/policy/rbac/data.yaml
	# Out of mcp-users again: without roles, the self-check would name them.
	for u in hank frank gina; do gpasswd -d "$u" mcp-users >/dev/null; done
else
	tail -5 /root/vmtest/mail-install.log | sed 's/^/  | /'
	skip "e-mail approvals (postfix not installable)"
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
if [ -n "$setups" ]; then
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

# Landlock refuses what SELinux allows (step 30, stage D): the exec
# server reads its command file below /opt (usr_t, which mcpsrv_exec_t
# reads), which the definition's landlock leaves out. It does not start;
# with no SELinux denial, the doctor names the ruleset.
mkdir -p /opt/ll-test
printf 'version: 1\ncommands:\n  up:\n    argv: [/usr/bin/uptime]\n    read_only: true\n' >/opt/ll-test/c.yaml
restorecon -R /opt/ll-test
cat >/etc/mcp-gateway/servers.d/llfail.yaml <<'END'
name: llfail
command: ["/usr/libexec/mcp-servers/mcp-server-exec", "--commands", "/opt/ll-test/c.yaml"]
selinux_type: mcpsrv_exec_t
landlock:
  read: ["/var"]
END
mcp-gateway-admin doctor --server llfail >/root/doctor-llfail.txt 2>&1
sed 's/^/  /' /root/doctor-llfail.txt | grep -iE 'llfail|landlock' | head -8
check "doctor: names Landlock for a server it keeps from starting" \
	grep -qE '^WARN +landlock llfail: does not start, and SELinux denied mcpsrv_exec_t nothing: Landlock is the likely cause' /root/doctor-llfail.txt
check "doctor: ... with its rules" grep -q "its definition's landlock (read /var)" /root/doctor-llfail.txt
rm -f /etc/mcp-gateway/servers.d/llfail.yaml /opt/ll-test/c.yaml
rmdir /opt/ll-test

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
# (reset-failed: the starts before, "Failing closed" among them, must not
# reach systemd's start limit.)
systemctl reset-failed mcp-gateway.service
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

section "Users from a directory"
# Principals that are not in /etc/passwd: users and groups of an LDAP
# directory (389 Directory Server on this host) through SSSD. dirk and
# dana are directory users, mcp-dir (both) and dir-approvers (dana) are
# directory groups. The socket's group is mcp-dir (socket_group, with the
# group added to the gateway's unit), roles are bound to mcp-dir, and
# approvals for fs are decided by group:dir-approvers. The packages come
# from the distribution's repositories; without them the section is
# skipped.
if zypper -n in --no-recommends 389-ds sssd sssd-ldap openldap2-client >/root/vmtest/dir-install.log 2>&1; then
	dir_pw=Vmtest-dir-1
	cat >/root/vmtest/dir.inf <<'END'
[general]
full_machine_name = localhost
strict_host_checking = False
[slapd]
instance_name = vmtest
root_password = Vmtest-dir-1
port = 389
self_sign_cert = False
[backend-userroot]
suffix = dc=vmtest,dc=example
create_suffix_entry = True
sample_entries = no
END
	check "a directory server is set up (389 Directory Server)" bash -c 'dscreate from-file /root/vmtest/dir.inf >/root/vmtest/dscreate.log 2>&1'
	tail -3 /root/vmtest/dscreate.log | sed 's/^/  | /'
	dir_entry() { # dir_entry <uid> <number> <groups...>: a directory user with a group of its own
		printf 'dn: uid=%s,ou=People,dc=vmtest,dc=example\nobjectClass: top\nobjectClass: inetOrgPerson\nobjectClass: posixAccount\ncn: %s\nsn: %s\nuid: %s\nuidNumber: %s\ngidNumber: %s\nhomeDirectory: /home/%s\nloginShell: /bin/bash\n\n' \
			"$1" "$1" "$1" "$1" "$2" "$2" "$1"
		printf 'dn: cn=%s,ou=Groups,dc=vmtest,dc=example\nobjectClass: top\nobjectClass: posixGroup\ncn: %s\ngidNumber: %s\n\n' "$1" "$1" "$2"
	}
	{
		printf 'dn: ou=People,dc=vmtest,dc=example\nobjectClass: top\nobjectClass: organizationalUnit\nou: People\n\n'
		printf 'dn: ou=Groups,dc=vmtest,dc=example\nobjectClass: top\nobjectClass: organizationalUnit\nou: Groups\n\n'
		dir_entry dirk 20001
		dir_entry dana 20002
		printf 'dn: cn=mcp-dir,ou=Groups,dc=vmtest,dc=example\nobjectClass: top\nobjectClass: posixGroup\ncn: mcp-dir\ngidNumber: 20100\nmemberUid: dirk\nmemberUid: dana\n\n'
		printf 'dn: cn=dir-approvers,ou=Groups,dc=vmtest,dc=example\nobjectClass: top\nobjectClass: posixGroup\ncn: dir-approvers\ngidNumber: 20101\nmemberUid: dana\n\n'
	} >/root/vmtest/dir.ldif
	check "the users and groups are in the directory" bash -c \
		'ldapadd -x -H ldap://127.0.0.1 -D "cn=Directory Manager" -w "$1" -f /root/vmtest/dir.ldif >/root/vmtest/ldapadd.log 2>&1' _ "$dir_pw"
	install -d -m 0700 /etc/sssd
	cat >/etc/sssd/sssd.conf <<END
[sssd]
services = nss
domains = vmtest

[domain/vmtest]
id_provider = ldap
auth_provider = none
ldap_uri = ldap://127.0.0.1
ldap_search_base = dc=vmtest,dc=example
ldap_schema = rfc2307
ldap_default_bind_dn = cn=Directory Manager
ldap_default_authtok = $dir_pw
ldap_id_use_start_tls = false
ldap_auth_disable_tls_never_use_in_production = true
cache_credentials = false
END
	chmod 0600 /etc/sssd/sssd.conf
	[ -e /etc/nsswitch.conf ] || cp /usr/etc/nsswitch.conf /etc/nsswitch.conf
	sed -i -E '/^(passwd|group):/{/ sss( |$)/!s/$/ sss/}' /etc/nsswitch.conf
	grep -E '^(passwd|group):' /etc/nsswitch.conf | sed 's/^/  /'
	systemctl enable --now sssd >/dev/null 2>&1
	dir_known() { getent passwd dirk >/dev/null && id -nG dana | grep -qw dir-approvers; }
	check "SSSD serves the directory's users and groups" eventually 30 dir_known
	echo "  $(getent passwd dirk); dana: $(id dana)"
	check "... and they are not in /etc/passwd" bash -c '! grep -qE "^(dirk|dana):" /etc/passwd'
	for u in dirk dana; do
		install -d -m 0700 -o "$u" -g "$u" "/home/$u"
		runuser -u "$u" -- sh -c "echo '$u from the directory' >/home/$u/notes.txt"
	done
	restorecon -R /home/dirk /home/dana

	# The socket's group a directory group: the gateway must be a member
	# to give it the socket.
	mcp-gateway-admin config set socket_group mcp-dir >/dev/null
	systemctl reset-failed mcp-gateway.service
	systemctl restart mcp-gateway.service 2>/dev/null
	sleep 2
	dir_no_start() { ! systemctl is-active -q mcp-gateway.service; }
	check "socket_group a group the gateway is not in: the gateway does not start" dir_no_start
	journalctl -u mcp-gateway.service -o cat --since "-30s" | grep -iE 'chown|not permitted|socket' | tail -2 | cut -c1-200 | sed 's/^/  | /'
	mkdir -p /etc/systemd/system/mcp-gateway.service.d
	printf '[Service]\nSupplementaryGroups=mcp-dir\n' >/etc/systemd/system/mcp-gateway.service.d/vmtest-socket-group.conf
	systemctl daemon-reload
	systemctl reset-failed mcp-gateway.service
	systemctl restart mcp-gateway.service
	wait_socket
	check "... with the group added to its unit, it does" systemctl is-active -q mcp-gateway.service
	check "the socket belongs to the directory group" test "$(stat -c %G /run/mcp-gateway/mcp.sock)" = mcp-dir

	# Roles and approvers by directory group.
	jq '.bindings.groups["mcp-dir"] = ["tester", "dir-asked"]
		| .roles["dir-asked"] = {"permissions": [{"server": "fs", "tool": "get_file_info", "require_approval": true, "approval_channel": "oob"}]}
		| .approvers.fs = ["group:dir-approvers"]' \
		/etc/mcp-gateway/policy/rbac/data.yaml >/root/dir-data.json &&
		cat /root/dir-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
	dir_read() { tool dirk read_file '{"path":"/home/dirk/notes.txt"}' && succeeded_with "dirk from the directory"; }
	check "a directory user reads his file (role through a directory group)" eventually 30 dir_read
	dir_inst=$(instance_pid dirk)
	check "... his instance runs as him" test "$(ps -o uid= -p "${dir_inst:-1}" 2>/dev/null | tr -d ' ')" = 20001
	check "... in mcpsrv_fs_t" proc_has_type "${dir_inst:-1}" mcpsrv_fs_t
	tool dana read_file '{"path":"/home/dirk/notes.txt"}'
	check "another directory user cannot read it" failed_without "dirk from the directory"

	# dirk's call waits for an approval only dir-approvers may give.
	runuser -u dirk -- /usr/local/bin/mcpcall --server fs --method tools/call \
		--params '{"name":"get_file_info","arguments":{"path":"/home/dirk/notes.txt"}}' >/root/vmtest/dir-call.out 2>&1 &
	dir_call=$!
	dir_pending() { control dana GET /v1/approvals | jq -e '.[] | select(.name == "get_file_info")' >/dev/null; }
	check "a member of the approvers' directory group sees the approval" eventually 30 dir_pending
	dir_hidden() { control dirk GET /v1/approvals | jq -e 'type == "array" and (map(select(.name == "get_file_info")) | length == 0)' >/dev/null; }
	check "... the requester, not a member, does not" dir_hidden
	dir_id=$(control dana GET /v1/approvals | jq -r '.[] | select(.name == "get_file_info") | .id')
	control dana POST "/v1/approvals/$dir_id" '{"decision":"approve","scope":"once"}' >/dev/null
	wait "$dir_call"
	check "... and approves it: the call runs" grep -q '"isError":false' /root/vmtest/dir-call.out

	# Back to mcp-users.
	jq 'del(.approvers.fs)' /etc/mcp-gateway/policy/rbac/data.yaml >/root/dir-data.json &&
		cat /root/dir-data.json >/etc/mcp-gateway/policy/rbac/data.yaml
	mcp-gateway-admin config unset socket_group >/dev/null
	rm -f /etc/systemd/system/mcp-gateway.service.d/vmtest-socket-group.conf
	systemctl daemon-reload
	systemctl reset-failed mcp-gateway.service
	systemctl restart mcp-gateway.service
	wait_socket
	check "the gateway serves mcp-users again" bash -c 'test "$(stat -c %G /run/mcp-gateway/mcp.sock)" = mcp-users'
else
	tail -5 /root/vmtest/dir-install.log | sed 's/^/  | /'
	skip "users from a directory (389-ds or SSSD not installable)"
fi

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

section "Uninstall"
# Last, as it removes the gateway (this package too: bash keeps reading
# the script it opened). Chapter 2, "Uninstalling", without stopping the
# services by hand first: the packages' scripts stop and disable them,
# the SELinux modules are unloaded, nothing of the gateway keeps
# running, and /etc/mcp-gateway (the role data as it is) and
# /var/lib/mcp-gateway stay. As the
# chapter says, what was built on the gateway's SELinux types goes first:
# the tests' own modules (a privileged server's, profile's) and the ports
# given mcp_port_t and mcp_metrics_port_t; the gateway's module cannot be
# removed while they use its types.
# un_units: the gateway's units still running or stopping.
un_units() {
	systemctl list-units --plain --no-legend --state=active,activating,deactivating,reloading 'mcp-*' 2>/dev/null |
		awk '{print $1}'
}
# A setup package first, if they are installed: its server and polkit
# rule go; the gateway keeps running without the server.
if rpm -q mcp-gateway-profile-systemd >/dev/null 2>&1; then
	check "a setup package is removed" rpm -e --nodeps mcp-gateway-profile-systemd
	check "... its polkit rule is gone" test ! -e /usr/share/polkit-1/rules.d/60-mcp-gateway-systemd.rules
	un_no_systemd() { ! curl -s --unix-socket /run/mcp-gateway/control.sock http://gw/v1/servers | jq -e '.[] | select(.name == "systemd" and (.removed | not))' >/dev/null; }
	check "... and the gateway no longer offers its server" eventually 30 un_no_systemd
	echo "  its account: $(getent passwd mcp-sysmgmt >/dev/null && echo kept || echo removed)"
else
	skip "removing a setup package (none installed)"
fi
for m in mcp_privtest mcp_fwprof; do
	semodule -l | awk '{print $1}' | grep -qx "$m" && semodule -r "$m" >/dev/null
done
# (-C: the local changes only; "mcp_port_t  tcp  9443, 8443")
semanage port -l -C 2>/dev/null | awk '$1 ~ /^mcp_(metrics_)?port_t$/ {for (i = 3; i <= NF; i++) print $2, $i}' |
	tr -d ',' | while read -r proto port; do semanage port -d -p "$proto" "$port"; done
# Something running: an instance of alice's.
tool alice read_file '{"path":"/home/alice/secret.txt"}' >/dev/null
echo "  before: $(un_units | tr '\n' ' ')"
un_packages=$(rpm -qa --qf '%{NAME}\n' 'mcp-gateway*' | sort | tr '\n' ' ')
echo "  removing: $un_packages"
# shellcheck disable=SC2086 # a list of package names
rpm -e --nodeps $un_packages >/root/vmtest/uninstall.log 2>&1
un_rc=$?
sed 's/^/  | /' /root/vmtest/uninstall.log | head -20
check "the packages are removed" test "$un_rc" = 0 -a -z "$(rpm -qa 'mcp-gateway*')"
check "the gateway and OPA are stopped" \
	bash -c '! systemctl is-active -q mcp-gateway.service && ! systemctl is-active -q mcp-opa.service'
check "... and their units are gone" bash -c '! systemctl cat mcp-gateway.service mcp-opa.service >/dev/null 2>&1'
un_none() { [ -z "$(un_units)" ]; }
check "no instance of an MCP server is left" eventually 30 un_none
un_units | sed 's/^/  left: /'
un_modules_gone() { ! semodule -l | awk '{print $1}' | grep -qE '^mcp_(gateway|systemd|firewalld|zypp|snapper|suseconnect|podman)$'; }
check "the SELinux modules are unloaded" un_modules_gone
semodule -l | awk '{print $1}' | grep -E '^mcp_' | sed 's/^/  still loaded: /'
check "the programs are gone" bash -c '! test -e /usr/bin/mcp-gateway && ! test -e /usr/libexec/mcp-servers/mcp-server-fs'
check "the polkit rules are gone" bash -c '! ls /usr/share/polkit-1/rules.d/*mcp-gateway* >/dev/null 2>&1'
check "the gateway's sockets are gone" test ! -S /run/mcp-gateway/mcp.sock
# The role data is the administrator's (the package owns it as %ghost
# %config): rpm keeps it in place, without .rpmsave; what the tests added
# stays as it is.
check "the role data is kept as it is" test -s /etc/mcp-gateway/policy/rbac/data.yaml
check "... not as data.yaml.rpmsave" test ! -e /etc/mcp-gateway/policy/rbac/data.yaml.rpmsave
check "the configuration added stays (/etc/mcp-gateway/exec.d)" test -s /etc/mcp-gateway/exec.d/vmtest.yaml
check "the state stays (/var/lib/mcp-gateway)" test -d /var/lib/mcp-gateway

section "Result"
# write_results <dir>: the checks as TAP (results.tap) and JUnit
# (results.xml, a test suite per section), for openQA's parse_extra_log.
xml() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' <<<"$1"; }
write_results() {
	local r sec st desc secs n=0 last= tests fails skips
	mkdir -p "$1" || return
	{
		echo "1..${#results_list[@]}"
		for r in "${results_list[@]}"; do
			IFS=$'\t' read -r sec st desc secs <<<"$r"
			n=$((n + 1))
			desc=${desc//#/\\#} # not a TAP directive
			case $st in
			pass) echo "ok $n - $sec: $desc" ;;
			skip) echo "ok $n - $sec: $desc # SKIP" ;;
			*) echo "not ok $n - $sec: $desc" ;;
			esac
		done
	} >"$1/results.tap"
	{
		echo '<?xml version="1.0" encoding="UTF-8"?>'
		printf '<testsuites name="mcp-gateway" tests="%d">\n' "${#results_list[@]}"
		for r in "${results_list[@]}" ""; do
			IFS=$'\t' read -r sec st desc secs <<<"$r"
			if [ "$sec" != "$last" ] && [ -n "$last" ]; then
				tests=$(printf '%s\n' "${results_list[@]}" | awk -F'\t' -v s="$last" '$1 == s' | wc -l)
				fails=$(printf '%s\n' "${results_list[@]}" | awk -F'\t' -v s="$last" '$1 == s && $2 == "fail"' | wc -l)
				skips=$(printf '%s\n' "${results_list[@]}" | awk -F'\t' -v s="$last" '$1 == s && $2 == "skip"' | wc -l)
				printf '  <testsuite name="%s" tests="%d" failures="%d" errors="0" skipped="%d">\n' \
					"$(xml "$last")" "$tests" "$fails" "$skips"
				printf '%s' "$cases"
				echo '  </testsuite>'
			fi
			[ -z "$r" ] && break
			[ "$sec" != "$last" ] && cases=
			last=$sec
			cases+=$(printf '    <testcase classname="mcp-gateway.%s" name="%s" time="%s">' "$(xml "$sec")" "$(xml "$desc")" "$secs")
			case $st in
			fail) cases+='<failure message="failed"/>' ;;
			skip) cases+='<skipped/>' ;;
			esac
			cases+=$'</testcase>\n'
		done
		echo '</testsuites>'
	} >"$1/results.xml"
	echo "  results: $1/results.tap, $1/results.xml"
}
[ -n "$results" ] && write_results "$results"
n_fail=$(printf '%s\n' "${results_list[@]}" | awk -F'\t' '$2 == "fail"' | wc -l)
n_skip=$(printf '%s\n' "${results_list[@]}" | awk -F'\t' '$2 == "skip"' | wc -l)
echo "  ${#results_list[@]} checks: $n_fail failed, $n_skip skipped"
if [ "$failed" = 0 ]; then echo "all checks passed"; else echo "some checks FAILED"; fi
exit "$failed"
