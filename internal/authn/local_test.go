package authn

import (
	"os"
	"os/user"
	"regexp"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/transport"
)

func TestLocalCurrentUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	p, err := Local(transport.PeerCred{UID: uint32(os.Getuid()), Label: "staff_u:staff_r:staff_t:s0"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Sub != me.Username || p.Home != me.HomeDir || p.UID == nil || *p.UID != uint32(os.Getuid()) {
		t.Errorf("principal = %+v", p)
	}
	if p.SELinux != "staff_u:staff_r:staff_t:s0" || p.Transport != "unix" {
		t.Errorf("principal = %+v", p)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(p.SessionID) {
		t.Errorf("session id %q", p.SessionID)
	}
}

func TestLocalUnknownUID(t *testing.T) {
	if _, err := Local(transport.PeerCred{UID: 4000000123}); err == nil {
		t.Fatal("expected error")
	}
}
