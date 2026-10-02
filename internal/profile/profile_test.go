package profile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/inspect"
)

// Records as the VM tests saw them (shortened where it does not matter).
const records = `type=AVC msg=audit(1790867838.100:500): avc:  denied  { read } for  pid=3001 comm="fw-mcp" name="hpage_pmd_size" dev="sysfs" ino=1 scontext=system_u:system_r:mcpsrv_fw_t:s0:c1,c2 tcontext=system_u:object_r:sysfs_t:s0 tclass=file permissive=1
type=AVC msg=audit(1790867838.200:501): avc:  denied  { connectto } for  pid=3001 comm="fw-mcp" path="/run/dbus/system_bus_socket" scontext=system_u:system_r:mcpsrv_fw_t:s0:c1,c2 tcontext=system_u:system_r:system_dbusd_t:s0-s0:c0.c1023 tclass=unix_stream_socket permissive=1
type=AVC msg=audit(1790867838.300:502): avc:  denied  { connectto } for  pid=3002 comm="fw-mcp" path="/run/dbus/system_bus_socket" scontext=system_u:system_r:mcpsrv_fw_t:s0:c3,c4 tcontext=system_u:system_r:system_dbusd_t:s0-s0:c0.c1023 tclass=unix_stream_socket permissive=1
type=USER_AVC msg=audit(1790867838.400:503): pid=900 uid=499 auid=4294967295 ses=4294967295 subj=system_u:system_r:system_dbusd_t:s0-s0:c0.c1023 msg='avc:  denied  { send_msg } for msgtype=method_return dest=:1.40 spid=800 tpid=3001 scontext=system_u:system_r:firewalld_t:s0 tcontext=system_u:system_r:mcpsrv_fw_t:s0:c1,c2 tclass=dbus permissive=1 exe="/usr/bin/dbus-daemon" sauid=499 hostname=? addr=? terminal=?'
type=USER_AVC msg=audit(1790867838.500:504): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  denied  { start } for auid=n/a uid=471 gid=471 path="/etc/systemd/system/x.service" cmdline="/usr/bin/fw-mcp" function="bus_unit_method_start_generic" scontext=system_u:system_r:mcpsrv_fw_t:s0:c1,c2 tcontext=unconfined_u:object_r:systemd_unit_file_t:s0 tclass=service permissive=0 exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?'
type=AVC msg=audit(1790867838.600:505): avc:  denied  { name_connect } for  pid=3001 comm="fw-mcp" dest=443 scontext=system_u:system_r:mcpsrv_fw_t:s0:c1,c2 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=1
type=AVC msg=audit(1790867838.700:506): avc:  denied  { execute execute_no_trans } for  pid=3001 comm="fw-mcp" name="zypper" dev="vda3" ino=2 scontext=system_u:system_r:mcpsrv_fw_t:s0:c1,c2 tcontext=system_u:object_r:rpm_exec_t:s0 tclass=file permissive=1
type=AVC msg=audit(1790867838.800:507): avc:  denied  { read } for  pid=4000 comm="other" name="x" scontext=system_u:system_r:other_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0
type=SELINUX_ERR msg=audit(1790867838.900:508): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:init_t:s0 newcontext=system_u:system_r:mcpsrv_fw_t:s0
type=AVC msg=audit(1790860000.000:1): avc:  denied  { read } for  pid=1 comm="old" scontext=system_u:system_r:mcpsrv_fw_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1
`

var since = time.Unix(1790867838, 0)

func TestParse(t *testing.T) {
	all, errs := Parse([]byte(records), since)
	if len(all) != 8 || len(errs) != 1 {
		t.Fatalf("parsed %d denials, %d errors", len(all), len(errs))
	}
	d := all[3] // the D-Bus reply, a USER_AVC
	if !d.User || d.Source != "firewalld_t" || d.Target != "mcpsrv_fw_t" || d.Class != "dbus" || d.Perms[0] != "send_msg" || !d.Permissive {
		t.Errorf("USER_AVC = %+v", d)
	}
	if all[4].Path != "/etc/systemd/system/x.service" || all[4].Permissive {
		t.Errorf("systemd USER_AVC = %+v", all[4])
	}
	if all[0].Path != "hpage_pmd_size" || all[0].Comm != "fw-mcp" {
		t.Errorf("name as path: %+v", all[0])
	}
	if p := all[6].Perms; len(p) != 2 || p[1] != "execute_no_trans" {
		t.Errorf("perms = %v", p)
	}
	mine, myErrs := Involving(all, errs, "mcpsrv_fw_t")
	if len(mine) != 7 || len(myErrs) != 1 {
		t.Errorf("involving: %d denials, %d errors", len(mine), len(myErrs))
	}
}

func TestDraftNewDomain(t *testing.T) {
	all, errs := Parse([]byte(records), since)
	mine, myErrs := Involving(all, errs, "mcpsrv_fw_t")
	d := NewDomain("fw", "mcpsrv_generic_t", "mcpsrv_generic_t", "/usr/libexec/fw-mcp.bin")
	if !d.New || d.Type != "mcpsrv_fw_t" || d.ExecType() != "mcpsrv_fw_exec_t" || d.ModuleName() != "mcp_fw" {
		t.Fatalf("domain = %+v", d)
	}
	dr := DraftModule(d, mine, myErrs)
	for _, want := range []string{
		"policy_module(mcp_fw, 1.0.0)",
		"mcp_gateway_backend_template(fw)",
		"\ttype system_dbusd_t;",
		"\tclass dbus send_msg;",
		"\tclass file { execute execute_no_trans };",
		"allow mcpsrv_fw_t system_dbusd_t:unix_stream_socket connectto;",
		"# /run/dbus/system_bus_socket (fw-mcp)",
		"allow firewalld_t mcpsrv_fw_t:dbus send_msg;",
		"allow mcpsrv_fw_t systemd_unit_file_t:service start;",
	} {
		if !strings.Contains(dr.TE, want) {
			t.Errorf("missing %q in\n%s", want, dr.TE)
		}
	}
	if strings.Contains(dr.TE, "sysfs_t") {
		t.Error("the template's dontaudited sysfs probe was drafted")
	}
	if strings.Contains(dr.TE, "type mcpsrv_fw_t;") {
		t.Error("the new domain is required instead of declared")
	}
	if strings.Count(dr.TE, "allow mcpsrv_fw_t system_dbusd_t:unix_stream_socket") != 1 {
		t.Error("rules not merged")
	}
	if dr.FC != "/usr/libexec/fw-mcp\\.bin\t--\tgen_context(system_u:object_r:mcpsrv_fw_exec_t,s0)\n" {
		t.Errorf("fc = %q", dr.FC)
	}
	hints := strings.Join(dr.Hints, "\n")
	for _, want := range []string{"network: it connects to or binds http_port_t", "programs: it runs files of type rpm_exec_t (zypper", "SELINUX_ERR", "D-Bus"} {
		if !strings.Contains(hints, want) {
			t.Errorf("missing hint %q in\n%s", want, hints)
		}
	}
}

func TestDraftExistingDomain(t *testing.T) {
	d := NewDomain("systemd", "mcpsrv_systemd_t", "mcpsrv_generic_t", "/usr/bin/systemd-mcp")
	if d.New || d.ModuleName() != "mcp_systemd_local" || d.FileContexts() != "" {
		t.Fatalf("domain = %+v", d)
	}
	dr := DraftModule(d, []Denial{{Source: "mcpsrv_systemd_t", Target: "mcpsrv_systemd_t", Class: "process", Perms: []string{"setsched"}}}, nil)
	for _, want := range []string{"\ttype mcpsrv_systemd_t;", "allow mcpsrv_systemd_t self:process setsched;"} {
		if !strings.Contains(dr.TE, want) {
			t.Errorf("missing %q in\n%s", want, dr.TE)
		}
	}
	if strings.Contains(dr.TE, "backend_template") {
		t.Error("template for an existing domain")
	}
	name, te, _ := d.ProfilingModule()
	if name != "mcpprof_systemd" || !strings.Contains(te, "permissive mcpsrv_systemd_t;") || strings.Contains(te, "template") {
		t.Errorf("profiling module %s:\n%s", name, te)
	}
	empty := DraftModule(d, nil, nil)
	if !strings.Contains(empty.TE, "no denials") || strings.Contains(empty.TE, "gen_require") {
		t.Errorf("empty draft:\n%s", empty.TE)
	}
}

func TestProfilingModuleNew(t *testing.T) {
	d := NewDomain("my-srv", "", "mcpsrv_generic_t", "/opt/my/srv")
	name, te, fc := d.ProfilingModule()
	if name != "mcpprof_my_srv" || !strings.Contains(te, "mcp_gateway_backend_template(my_srv)") ||
		!strings.Contains(te, "permissive mcpsrv_my_srv_t;") || !strings.Contains(fc, "mcpsrv_my_srv_exec_t") {
		t.Errorf("%s:\n%s\n%s", name, te, fc)
	}
	if !Interpreter("/usr/bin/python3.11") || !Interpreter("/usr/bin/node") || Interpreter("/usr/bin/firewalld-mcp") {
		t.Error("Interpreter")
	}
}

func TestSampleArgs(t *testing.T) {
	schema := `{"type":"object","required":["path","count","mode","flags","opt","nested","kind"],"properties":{
		"path":{"type":"string"},
		"count":{"type":"integer","minimum":1},
		"mode":{"type":"string","enum":["a","b"]},
		"flags":{"type":"array","items":{"type":"string"},"minItems":1},
		"opt":{"type":["null","boolean"]},
		"nested":{"type":"object","required":["unit_name"],"properties":{"unit_name":{"type":"string","default":"x.service"}}},
		"kind":{"anyOf":[{"type":"number"},{"type":"string"}]},
		"unused":{"type":"string"}}}`
	got, _ := json.Marshal(SampleArgs(json.RawMessage(schema)))
	want := `{"count":1,"flags":[""],"kind":0,"mode":"a","nested":{"unit_name":"x.service"},"opt":false,"path":"/"}`
	if string(got) != want {
		t.Errorf("SampleArgs = %s, want %s", got, want)
	}
	if len(SampleArgs(nil)) != 0 || len(SampleArgs(json.RawMessage(`"x"`))) != 0 {
		t.Error("no schema")
	}
}

func TestPlan(t *testing.T) {
	tools := []inspect.Tool{
		{Name: "get_x", InputSchema: json.RawMessage(`{"type":"object","required":["zone"],"properties":{"zone":{"type":"string"}}}`)},
		{Name: "set_x"},
		{Name: "plan_x"},
	}
	verdicts := inspect.Classify(tools, inspect.Options{})
	calls, unknown := Plan(tools, verdicts, nil, false)
	if len(calls) != 1 || calls[0].Tool != "get_x" || calls[0].Args["zone"] != "" || len(unknown) != 0 {
		t.Errorf("read only: %+v %v", calls, unknown)
	}
	if calls, _ := Plan(tools, verdicts, nil, true); len(calls) != 3 {
		t.Errorf("all: %+v", calls)
	}
	given, err := ParseCalls([]byte(`{"set_x":[{"a":1},{"a":2}],"get_x":{"zone":"public"},"nope":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	calls, unknown = Plan(tools, verdicts, given, false)
	if len(calls) != 3 || !calls[0].Given || calls[0].Args["zone"] != "public" || calls[2].Args["a"] != float64(2) {
		t.Errorf("given: %+v", calls)
	}
	if len(unknown) != 1 || unknown[0] != "nope" {
		t.Errorf("unknown = %v", unknown)
	}
	if _, err := ParseCalls([]byte(`{"x":3}`)); err == nil {
		t.Error("bad calls file accepted")
	}
}

func TestReport(t *testing.T) {
	all, errs := Parse([]byte(records), since)
	d := NewDomain("fw", "", "mcpsrv_generic_t", "/usr/bin/fw-mcp")
	mine, myErrs := Involving(all, errs, d.Type)
	calls := []Outcome{
		{Call: Call{Tool: "get_default_zone", Args: map[string]any{}}, Text: `{"DefaultZone":"public"}`},
		{Call: Call{Tool: "get_zone", Args: map[string]any{"zone": ""}}, IsError: true, Text: "org.freedesktop.DBus.Error.AccessDenied: not authorized"},
	}
	dr := DraftModule(d, mine, myErrs)
	r := &Report{Server: "fw", Program: "firewalld 0.1.0", Domain: d, Calls: calls, Denials: mine, Errs: myErrs,
		Hints: append(dr.Hints, CallHints(calls)...), Files: []string{"mcp_fw.te"}, ExecPath: d.Exec}
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Server fw (firewalld 0.1.0): mcpsrv_fw_t, new domain, permissive (profiling)",
		`ok     get_default_zone {} (sample args): {"DefaultZone":"public"}`,
		"error  get_zone",
		"authorization: get_zone was refused",
		"2  mcpsrv_fw_t system_dbusd_t:unix_stream_socket { connectto } /run/dbus/system_bus_socket (fw-mcp)",
		"restorecon -F /usr/bin/fw-mcp",
		"mcp-gateway profile --server fw --verify",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
