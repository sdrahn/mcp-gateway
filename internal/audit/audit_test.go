package audit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeKernel struct {
	msgs []string
	err  error
}

func (f *fakeKernel) Send(msg string) error {
	f.msgs = append(f.msgs, msg)
	return f.err
}

func TestLogKeyedDigestAndKernel(t *testing.T) {
	var out bytes.Buffer
	k := &fakeKernel{}
	a := New(&out, Options{Key: bytes.Repeat([]byte{1}, 32), Kernel: k})
	args := map[string]any{"path": "/etc/shadow"}
	a.Log(Record{Session: "s1", Sub: "alice", Action: "tools.call", Server: "fs", Name: "read_file",
		Effect: "allow", DecisionID: "d-1", Args: args})
	a.Log(Record{Session: "s1", Sub: "alice", Action: "tools.call", Server: "fs", Name: "delete_file",
		Effect: "deny", Reason: "denied by policy", DecisionID: "d-2"})

	logs := out.String()
	if strings.Contains(logs, Digest(args)) || !strings.Contains(logs, `"args_hmac"`) || strings.Contains(logs, "shadow") {
		t.Fatalf("digest not keyed or args leaked: %s", logs)
	}
	if !strings.Contains(logs, `"decision_id":"d-1"`) {
		t.Fatalf("decision id missing: %s", logs)
	}
	if len(k.msgs) != 1 {
		t.Fatalf("kernel got %d messages, want only the denial: %v", len(k.msgs), k.msgs)
	}
	want := "op=mcp-decision action=tools.call decision_id=d-2 principal=alice reason=" +
		strings.ToUpper("64656e69656420627920706f6c696379") + " server=fs session=s1 target=delete_file res=failed"
	if k.msgs[0] != want {
		t.Fatalf("kernel message\n got %s\nwant %s", k.msgs[0], want)
	}
}

func TestLogPrivilegedToKernel(t *testing.T) {
	var out bytes.Buffer
	k := &fakeKernel{}
	a := New(&out, Options{Key: bytes.Repeat([]byte{1}, 32), Kernel: k})
	a.Log(Record{Session: "s1", Sub: "alice", Action: "tools.call", Server: "zypp", Name: "confirm_install",
		Effect: "allow", Reason: "approved", GrantID: "g-1", DecisionID: "d-1", Privileged: true})
	if !strings.Contains(out.String(), `"privileged":true`) {
		t.Fatalf("journal record: %s", out.String())
	}
	if len(k.msgs) != 1 || !strings.Contains(k.msgs[0], " grant=g-1 ") || !strings.Contains(k.msgs[0], " privileged=yes ") ||
		!strings.HasSuffix(k.msgs[0], " res=success") {
		t.Fatalf("kernel messages %v", k.msgs)
	}
}

func TestEventAndKernelFailure(t *testing.T) {
	var out bytes.Buffer
	k := &fakeKernel{err: errors.New("EPERM")}
	a := New(&out, Options{Kernel: k})
	a.Event("mcp-approval", true, map[string]string{"id": "a-1", "by": "carol"})
	a.Event("mcp-grant-revoke", true, map[string]string{"id": "g-1"})
	if len(k.msgs) != 2 || k.msgs[0] != "op=mcp-approval by=carol id=a-1 res=success" {
		t.Fatalf("kernel %v", k.msgs)
	}
	if n := strings.Count(out.String(), "kernel audit subsystem failed"); n != 1 {
		t.Fatalf("failure warned %d times, want once", n)
	}
}

func TestFormatKernelHexEncodesUntrusted(t *testing.T) {
	got := FormatKernel("op1", false, map[string]string{"target": `x" res=success`, "empty": ""})
	if strings.Contains(got, `res=success`) || got != "op=op1 target="+strings.ToUpper("78222072657"+"33d73756363657373")+" res=failed" {
		t.Fatalf("got %s", got)
	}
}

func TestLoadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	k1, err := LoadKey(path)
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %v %d", err, len(k1))
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	k2, err := LoadKey(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("key not persisted")
	}
	short := filepath.Join(t.TempDir(), "short")
	_ = os.WriteFile(short, []byte("x"), 0o600)
	if _, err := LoadKey(short); err == nil {
		t.Fatal("short key accepted")
	}
}

// The real kernel interface, where the environment allows it (needs
// CAP_AUDIT_WRITE and an audit-enabled kernel).
func TestUserMessageNULTerminated(t *testing.T) {
	const msg = "op=mcp-decision res=success"
	buf := userMessage(7, msg)
	payload := buf[unix.NLMSG_HDRLEN:]
	if int(binary.NativeEndian.Uint32(buf[0:4])) != len(buf) || binary.NativeEndian.Uint32(buf[8:12]) != 7 {
		t.Fatalf("header % x", buf[:unix.NLMSG_HDRLEN])
	}
	if string(payload) != msg+"\x00" {
		t.Fatalf("payload %q, want the message and a NUL", payload)
	}
}

func TestNetlink(t *testing.T) {
	n, err := OpenNetlink()
	if err != nil {
		t.Skipf("kernel audit not available here: %v", err)
	}
	defer func() { _ = n.Close() }()
	if err := n.Send("op=mcp-gateway-test res=success"); err != nil {
		t.Fatal(err)
	}
}

func TestNoteAndReidentified(t *testing.T) {
	var out bytes.Buffer
	k := &fakeKernel{}
	a := New(&out, Options{Kernel: k})
	a.Note("mcp-pseudonymize", map[string]string{"values": "EMAIL:2", "server": "crm"})
	a.Log(Record{Session: "s1", Sub: "alice", Action: "tools.call", Server: "crm", Effect: "allow", Reidentified: 2})
	logs := out.String()
	if !strings.Contains(logs, `"event":"mcp-pseudonymize","server":"crm","values":"EMAIL:2"`) {
		t.Errorf("note: %s", logs)
	}
	if !strings.Contains(logs, `"reidentified":2`) {
		t.Errorf("reidentified count missing: %s", logs)
	}
	if len(k.msgs) != 0 {
		t.Errorf("notes must not reach the kernel: %v", k.msgs)
	}
}
