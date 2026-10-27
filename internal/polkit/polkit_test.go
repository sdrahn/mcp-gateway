package polkit

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

// polkitd answers CheckAuthorization with one struct, (bba{ss}); Check
// stores it into one value (VM test: "length mismatch" when stored into
// three).
func TestStoreResult(t *testing.T) {
	answer := []any{[]any{true, false, map[string]string{"polkit.retains_authorization_after_challenge": "1"}}}
	var result struct {
		Authorized, Challenge bool
		Details               map[string]string
	}
	if err := dbus.Store(answer, &result); err != nil || !result.Authorized || result.Challenge || result.Details["polkit.retains_authorization_after_challenge"] != "1" {
		t.Fatalf("%+v %v", result, err)
	}
}
