package discovery

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
)

func svc(ns, name string, ann map[string]string, ports ...kube.ServicePort) kube.Service {
	return kube.Service{APIVersion: "v1", Kind: "Service",
		Metadata: kube.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"mcp-gateway.io/server": "true"}, Annotations: ann},
		Spec:     kube.ServiceSpec{Ports: ports}}
}

func port(name string, n int) kube.ServicePort {
	return kube.ServicePort{Name: name, Port: n, Protocol: "TCP"}
}

func ptr(s string) *string { return &s }

func TestDefinition(t *testing.T) {
	for _, c := range []struct {
		name   string
		s      kube.Service
		prefix string
		server string
		url    string
		err    string
	}{
		{"the only port", svc("team-a", "tickets", nil, port("http", 8080)), "team-a-", "team-a-tickets",
			"http://tickets.team-a.svc:8080/mcp", ""},
		{"the port named mcp", svc("team-a", "tickets", nil, port("metrics", 9090), port("mcp", 8080)), "team-a-", "team-a-tickets",
			"http://tickets.team-a.svc:8080/mcp", ""},
		{"annotations", svc("team-a", "tickets-v2", map[string]string{config.DiscoveryNameAnnotation: "tickets",
			config.DiscoveryPortAnnotation: "web", config.DiscoveryPathAnnotation: "/api/mcp"}, port("web", 80), port("metrics", 9090)),
			"t-", "t-tickets", "http://tickets-v2.team-a.svc:80/api/mcp", ""},
		{"a port by number", svc("ns", "s", map[string]string{config.DiscoveryPortAnnotation: "9000"}, port("a", 80), port("b", 9000)),
			"", "s", "http://s.ns.svc:9000/mcp", ""},
		{"several ports, none mcp", svc("ns", "s", nil, port("a", 80), port("b", 81)), "ns-", "", "", "none is named mcp"},
		{"no port", svc("ns", "s", nil), "ns-", "", "", "no TCP port"},
		{"a UDP port only", svc("ns", "s", nil, kube.ServicePort{Name: "dns", Port: 53, Protocol: "UDP"}), "ns-", "", "", "no TCP port"},
		{"an annotated port that is not there", svc("ns", "s", map[string]string{config.DiscoveryPortAnnotation: "mcp"}, port("http", 80)),
			"ns-", "", "", "no TCP port mcp"},
		{"a path that is not one", svc("ns", "s", map[string]string{config.DiscoveryPathAnnotation: "mcp"}, port("mcp", 80)),
			"ns-", "", "", "is not a path"},
		{"a name too long", svc("ns", strings.Repeat("x", 40), nil, port("mcp", 80)), "ns-", "", "", "must match"},
		{"a name that is not one", svc("ns", "s", map[string]string{config.DiscoveryNameAnnotation: "Tickets"}, port("mcp", 80)),
			"ns-", "", "", "must match"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := Definition(c.s, c.prefix)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b.Name != c.server || b.URL != c.url || b.Discovered == nil || b.Discovered.Service != c.s.Metadata.Name ||
				b.Discovered.Namespace != c.s.Metadata.Namespace {
				t.Errorf("got %s %s %+v", b.Name, b.URL, b.Discovered)
			}
			// Nothing but the name and the url: the defaults of a server
			// that speaks HTTP.
			want := &config.Backend{Version: 1, Name: b.Name, URL: b.URL}
			want.ApplyDefaults()
			if b.Discovery != want.Discovery || b.Isolation != want.Isolation || len(b.Headers) != 0 || b.SignIn != nil ||
				b.Proxy != "" || b.CAFile != "" || len(b.Credentials) != 0 {
				t.Errorf("not the defaults: %+v", b)
			}
		})
	}
	// Only ClusterIP Services.
	s := svc("ns", "s", nil, port("mcp", 80))
	s.Spec.Type = "LoadBalancer"
	if _, err := Definition(s, ""); err == nil || !strings.Contains(err.Error(), "ClusterIP") {
		t.Errorf("a LoadBalancer: %v", err)
	}
	s.Spec.Type = "ClusterIP"
	if _, err := Definition(s, ""); err != nil {
		t.Errorf("ClusterIP: %v", err)
	}
}

func watcher(api *kubetest.Secrets, namespaces ...config.DiscoveryNamespace) *Watcher {
	d := config.ServerDiscovery{Namespaces: namespaces}.WithDefaults()
	return &Watcher{Client: api.Client(), Config: d, MinBackoff: 10 * time.Millisecond}
}

func ns(name string, prefix *string) config.DiscoveryNamespace {
	return config.DiscoveryNamespace{Namespace: name, Prefix: prefix}
}

// The labelled Services of the named namespaces, and no others; two that
// give one name give neither.
func TestDefinitions(t *testing.T) {
	api := kubetest.NewSecrets(t)
	api.PutObject("services", "team-a", svc("team-a", "tickets", nil, port("mcp", 8080)))
	api.PutObject("services", "team-a", svc("team-a", "broken", nil, port("a", 1), port("b", 2)))
	unlabelled := svc("team-a", "db", nil, port("pg", 5432))
	unlabelled.Metadata.Labels = nil
	api.PutObject("services", "team-a", unlabelled)
	api.PutObject("services", "elsewhere", svc("elsewhere", "secret", nil, port("mcp", 80)))
	// Two Services that give the server x-y: team-b's x-y, and team-c's y
	// with the prefix x- .
	api.PutObject("services", "team-b", svc("team-b", "y", map[string]string{config.DiscoveryNameAnnotation: "y"}, port("mcp", 80)))
	api.PutObject("services", "team-c", svc("team-c", "z", map[string]string{config.DiscoveryNameAnnotation: "y"}, port("mcp", 80)))
	w := watcher(api, ns("team-a", nil), ns("team-b", ptr("x-")), ns("team-c", ptr("x-")))
	if err := w.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	defs, problems := w.Definitions()
	if len(defs) != 1 || defs["team-a-tickets"] == nil || defs["team-a-tickets"].URL != "http://tickets.team-a.svc:8080/mcp" {
		t.Fatalf("definitions: %v", defs)
	}
	var got []string
	for _, p := range problems {
		got = append(got, p.Namespace+"/"+p.Service+" "+p.Server)
		if p.Overridden {
			t.Errorf("overridden: %v", p)
		}
	}
	want := "team-a/broken team-a-broken,team-b/y x-y,team-c/z x-y"
	if strings.Join(got, ",") != want {
		t.Errorf("problems %q, want %q (%v)", strings.Join(got, ","), want, problems)
	}
}

// A Service added, changed and deleted changes its server, and says so.
func TestWatch(t *testing.T) {
	api := kubetest.NewSecrets(t)
	w := watcher(api, ns("team-a", nil))
	var changes atomic.Int32
	w.OnChange = func() { changes.Add(1) }
	if err := w.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	url := func() string {
		defs, _ := w.Definitions()
		if b := defs["team-a-tickets"]; b != nil {
			return b.URL
		}
		return ""
	}
	await := func(what, want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for url() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: url %q, want %q", what, url(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	api.PutObject("services", "team-a", svc("team-a", "tickets", nil, port("mcp", 8080)))
	await("added", "http://tickets.team-a.svc:8080/mcp")
	n := changes.Load()
	api.PutObject("services", "team-a", svc("team-a", "tickets", map[string]string{config.DiscoveryPathAnnotation: "/v2"}, port("mcp", 8080)))
	await("changed", "http://tickets.team-a.svc:8080/v2")
	if changes.Load() == n {
		t.Error("no change told")
	}
	// A change that gives the same definition (another label) is not
	// one.
	n = changes.Load()
	same := svc("team-a", "tickets", map[string]string{config.DiscoveryPathAnnotation: "/v2"}, port("mcp", 8080))
	same.Metadata.Labels["team"] = "a"
	api.PutObject("services", "team-a", same)
	api.PutObject("services", "team-a", svc("team-a", "other", nil, port("mcp", 1)))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if defs, _ := w.Definitions(); defs["team-a-other"] != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("other not seen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d := changes.Load() - n; d != 1 {
		t.Errorf("%d changes told for a relabelling and an addition, want 1", d)
	}
	api.RemoveObject("services", "team-a", "tickets")
	await("deleted", "")
	// The watch broken and the history compacted: listed again.
	api.Compact()
	api.Break()
	api.PutObject("services", "team-a", svc("team-a", "tickets", nil, port("mcp", 9)))
	await("after a broken watch", "http://tickets.team-a.svc:9/mcp")
	cancel()
	<-done
}

// A namespace that does not list (no Role there) has no servers and says
// why; it is listed again.
func TestLoadError(t *testing.T) {
	// An API server that is not there.
	client, err := kube.NewClient("http://127.0.0.1:1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	w := &Watcher{Client: client, Config: config.ServerDiscovery{Namespaces: []config.DiscoveryNamespace{ns("team-a", nil)}}.WithDefaults()}
	if err := w.Load(t.Context()); err == nil || !strings.Contains(err.Error(), "team-a") {
		t.Fatalf("load: %v", err)
	}
	if w.Errors()["team-a"] == "" {
		t.Error("no error for team-a")
	}
}

// A server file of the same name wins; an empty file masks the name.
func TestMerge(t *testing.T) {
	file := &config.Backend{Name: "team-a-tickets", URL: "https://tickets.example/mcp"}
	found := map[string]*config.Backend{
		"team-a-tickets": {Name: "team-a-tickets", URL: "http://tickets.team-a.svc:80/mcp", Discovered: &config.Discovered{Namespace: "team-a", Service: "tickets"}},
		"team-a-masked":  {Name: "team-a-masked", URL: "http://masked.team-a.svc:80/mcp", Discovered: &config.Discovered{Namespace: "team-a", Service: "masked"}},
		"team-a-new":     {Name: "team-a-new", URL: "http://new.team-a.svc:80/mcp", Discovered: &config.Discovered{Namespace: "team-a", Service: "new"}},
	}
	files := map[string]*config.Backend{"team-a-tickets": file}
	out, problems := Merge(files, map[string]bool{"team-a-masked": true}, found)
	if len(out) != 2 || out["team-a-tickets"] != file || out["team-a-new"] == nil {
		t.Errorf("merged: %v", out)
	}
	if len(files) != 1 {
		t.Error("the files' map changed")
	}
	if len(problems) != 2 || !problems[0].Overridden || !problems[1].Overridden ||
		!strings.Contains(problems[0].Reason, "empty server file team-a-masked.yaml") || !strings.Contains(problems[1].Reason, "a server file defines") {
		t.Errorf("problems: %+v", problems)
	}
}
