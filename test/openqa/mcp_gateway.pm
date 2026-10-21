# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Package: mcp-gateway mcp-gateway-tests
# Summary: Functional tests of mcp-gateway (package mcp-gateway-tests):
#          domains, calls, approvals, servers, reloads, audit, no SELinux
#          denials. Each check becomes a result of its own (JUnit).
# Maintainer: mcp-gateway maintainers

use Mojo::Base 'consoletest';
use testapi;
use serial_terminal 'select_serial_terminal';
use utils qw(zypper_call);

my $results = '/var/tmp/mcp-gateway-tests';

sub run {
    select_serial_terminal;
    # The tests need SELinux enforcing, as the product ships it.
    assert_script_run('test "$(getenforce)" = Enforcing');
    zypper_call('in mcp-gateway-tests');
    # The setups' tests run when their packages are there.
    zypper_call('in mcp-gateway-profile-systemd mcp-gateway-profile-firewalld mcp-gateway-profile-zypp '
          . 'mcp-gateway-profile-snapper mcp-gateway-profile-suseconnect mcp-gateway-profile-podman',
        exitcode => [0, 4, 104])
      if get_var('MCP_GATEWAY_SETUPS');
    assert_script_run("mkdir -p $results");
    # Exit status 0: all passed; 1: a check failed (the JUnit results say
    # which); 2: wrong usage.
    my $rc = script_run("/usr/libexec/mcp-gateway/tests/run-tests.sh --disposable --results $results "
          . "> $results/run.log 2>&1", timeout => 1800);
    upload_logs("$results/run.log");
    die "run-tests.sh did not run (exit status $rc)" if $rc == 2 || script_run("test -s $results/results.xml") != 0;
    upload_logs("$results/results.tap");
    parse_extra_log(XUnit => "$results/results.xml");
}

sub post_fail_hook {
    my ($self) = @_;
    select_serial_terminal;
    script_run("journalctl --no-pager -o short-precise -u mcp-gateway -u mcp-opa -u 'mcp-*' > $results/journal.txt 2>&1");
    upload_logs("$results/journal.txt", failok => 1);
    script_run("ausearch -m AVC,USER_AVC,SELINUX_ERR -ts boot > $results/avc.txt 2>&1");
    upload_logs("$results/avc.txt", failok => 1);
    $self->SUPER::post_fail_hook;
}

sub test_flags {
    return {fatal => 0};
}

1;
