package egress

import "testing"

func TestClusterName(t *testing.T) {
	for host, want := range map[string]bool{
		"echo.agents.svc":                        true,
		"echo.agents.svc.cluster.local":          true,
		"ECHO.Agents.SVC":                        true,
		"echo.agents.svc.":                       true,
		"svc":                                    false,
		".svc":                                   false,
		"x..svc":                                 false,
		"echo.agents.svc.evil.com":               false,
		"echo.agents.svc.cluster.local.evil.com": false,
		"example.com":                            false,
		"10.0.0.1":                               false,
		"localhost":                              false,
	} {
		if got := ClusterName(host); got != want {
			t.Errorf("ClusterName(%q) = %v, want %v", host, got, want)
		}
	}
}
