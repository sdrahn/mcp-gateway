package config

import (
	"slices"
	"strings"
	"testing"
)

func TestIssuers(t *testing.T) {
	if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", httpYAML+"  issuers:\n    - issuer: https://a.example.com\n      audience: \"a b\"\n")); err == nil ||
		!strings.Contains(err.Error(), "http.issuers[0].audience") {
		t.Fatalf("an audience with a space: %v", err)
	}
	g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", httpYAML+`  issuers:
    - issuer: https://kubernetes.default.svc
      audience: mcp-gateway
      scopes: []
      subject_prefix: "k8s:"
    - issuer: https://partner.example.com
      groups_claim: roles
`))
	if err != nil {
		t.Fatal(err)
	}
	all := g.HTTP.AllIssuers()
	if len(all) != 3 || all[0].Issuer != g.HTTP.Issuer || all[0].Audience != g.HTTP.Audience || !slices.Equal(all[0].Scopes, []string{"mcp"}) {
		t.Fatalf("http.issuer first: %+v", all)
	}
	if k := all[1]; k.Audience != "mcp-gateway" || k.Scopes == nil || len(k.Scopes) != 0 ||
		k.GroupsClaim != "groups" || k.SubjectPrefix != "k8s:" {
		t.Errorf("the cluster's issuer: %+v", k)
	}
	if p := all[2]; p.Audience != g.HTTP.Audience || !slices.Equal(p.Scopes, []string{"mcp"}) || p.GroupsClaim != "roles" || p.LocalUserClaim != "" {
		t.Errorf("the partner's issuer (defaults): %+v", p)
	}
	if g.HTTP.SignInIssuer() != g.HTTP.Issuer {
		t.Errorf("sign-in issuer %q", g.HTTP.SignInIssuer())
	}

	// Only issuers: the first is the one people sign in with.
	only := strings.Replace(httpYAML, "  issuer: http://127.0.0.1:9000/realms/mcp\n", "  issuers:\n    - issuer: https://a.example.com\n    - issuer: https://b.example.com\n", 1)
	g, err = LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", only))
	if err != nil {
		t.Fatal(err)
	}
	if g.HTTP.SignInIssuer() != "https://a.example.com" || len(g.HTTP.AllIssuers()) != 2 {
		t.Errorf("issuers only: %q %+v", g.HTTP.SignInIssuer(), g.HTTP.AllIssuers())
	}

	noIssuer := strings.Replace(httpYAML, "  issuer: http://127.0.0.1:9000/realms/mcp\n", "", 1)
	for content, want := range map[string]string{
		noIssuer: "issuer (or issuers) and audience are required",
		httpYAML + "  issuers:\n    - audience: https://x.example.com/mcp\n":                                                    "http.issuers[0].issuer: required",
		httpYAML + "  issuers:\n    - issuer: http://127.0.0.1:9000/realms/mcp\n":                                               "named twice",
		httpYAML + "  issuers:\n    - issuer: https://a.example.com\n    - issuer: https://a.example.com\n":                     "http.issuers[1].issuer: https://a.example.com is named twice",
		httpYAML + "  issuers:\n    - issuer: http://idp.example.com\n":                                                         "http.issuers[0].issuer",
		httpYAML + "  issuers:\n    - issuer: https://a.example.com\n      subject_prefix: k8s\n":                               "subject_prefix",
		httpYAML + "  issuers:\n    - issuer: https://a.example.com\n      token_file: token\n":                                 "token_file: must be an absolute path",
		httpYAML + "  issuers:\n    - issuer: http://127.0.0.1:9100\n      token_file: /run/token\n":                            "token_file: only for an https:// issuer",
		only + "  local_user_claim: uid\n":                                                                                      "http.local_user_claim: applies to the tokens of http.issuer",
		"deployment: container\n" + httpYAML + "  issuers:\n    - issuer: https://a.example.com\n      local_user_claim: uid\n": "http.issuers[0].local_user_claim: not in container mode",
	} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", content)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}
}

// Without http.issuer, a first issuer that looks like a cluster's (no
// scopes, or a token_file) is warned about: it is the one people sign in
// with (#412). With http.issuer, or a people's provider first, nothing.
func TestSignInIssuerWarning(t *testing.T) {
	without := func(issuers string) string {
		return strings.Replace(httpYAML, "  issuer: http://127.0.0.1:9000/realms/mcp\n", "  issuers:\n"+issuers, 1)
	}
	cluster := "    - issuer: https://kubernetes.default.svc\n      audience: mcp-gateway\n      scopes: []\n"
	people := "    - issuer: https://idp.example.com\n"
	tokenFile := "    - issuer: https://kubernetes.default.svc\n      token_file: /run/token\n"
	for name, tc := range map[string]struct {
		yaml string
		warn bool
	}{
		"cluster first":            {without(cluster + people), true},
		"token_file first":         {without(tokenFile + people), true},
		"people first":             {without(people + cluster), false},
		"http.issuer and cluster":  {httpYAML + "  issuers:\n" + cluster, false},
		"one issuer, its defaults": {without(people), false},
	} {
		g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", tc.yaml))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		warned := slices.ContainsFunc(g.Warnings, func(w string) bool { return strings.Contains(w, "is the issuer people sign in with") })
		if warned != tc.warn {
			t.Errorf("%s: warnings %q", name, g.Warnings)
		}
	}
}
