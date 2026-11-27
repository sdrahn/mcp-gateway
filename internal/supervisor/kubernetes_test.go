package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// fakeAPI is the API server's part the launcher uses: pods (Pending, then
// Running, or waiting with waitReason), Secrets, NetworkPolicies.
type fakeAPI struct {
	mu         sync.Mutex
	created    []string // kinds, in order
	pod        kube.Pod
	gets       int
	deleted    []string
	waitReason string
	policy     kube.NetworkPolicy
	secret     kube.Secret
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer sa-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := r.URL.Path
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/pods"):
		_ = json.NewDecoder(r.Body).Decode(&f.pod)
		f.pod.Metadata.UID = "uid-1"
		f.created = append(f.created, "Pod")
		_ = json.NewEncoder(w).Encode(f.pod)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/networkpolicies"):
		_ = json.NewDecoder(r.Body).Decode(&f.policy)
		f.created = append(f.created, "NetworkPolicy")
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/secrets"):
		_ = json.NewDecoder(r.Body).Decode(&f.secret)
		f.created = append(f.created, "Secret")
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && strings.Contains(path, "/pods/"):
		f.gets++
		st := &kube.PodStatus{Phase: "Pending"}
		switch {
		case f.waitReason != "":
			st.ContainerStatuses = []kube.ContainerStatus{{Name: "server", State: kube.ContainerState{
				Waiting: &kube.ContainerStateWaiting{Reason: f.waitReason, Message: "no such image"}}}}
		case f.gets > 1:
			st = &kube.PodStatus{Phase: "Running", PodIP: "127.0.0.1"}
		}
		p := f.pod
		p.Status = st
		_ = json.NewEncoder(w).Encode(p)
	case r.Method == http.MethodDelete:
		f.deleted = append(f.deleted, path+"?"+r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeBridge answers the gateway as mcp-stdio-bridge does and echoes.
func fakeBridge(t *testing.T, token string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				r := bufio.NewReader(c)
				req, err := http.ReadRequest(r)
				if err != nil || req.Header.Get("Authorization") != "Bearer "+token || req.Header.Get("Upgrade") != BridgeUpgrade {
					_, _ = io.WriteString(c, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
					_ = c.Close()
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: mcp-stdio\r\nConnection: Upgrade\r\n\r\n")
				_, _ = io.Copy(c, r)
				_ = c.Close()
			}()
		}
	}()
	return l.Addr().String()
}

func testKubernetes(t *testing.T, api *fakeAPI) (*Kubernetes, *string) {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	tokenFile := t.TempDir() + "/token"
	writeTestFile(t, tokenFile, "sa-token\n")
	c, err := kube.NewClient(srv.URL, tokenFile, "")
	if err != nil {
		t.Fatal(err)
	}
	var dialed string
	k := &Kubernetes{Client: c, Options: podOpts, poll: 10 * time.Millisecond, StartTimeout: 5 * time.Second,
		readFile: func(p string) ([]byte, error) { return []byte("secret of " + p), nil }}
	k.dial = func(ctx context.Context, addr, token string) (io.ReadWriteCloser, error) {
		dialed = addr
		return DialBridge(ctx, fakeBridge(t, token), token)
	}
	return k, &dialed
}

func TestKubernetesStart(t *testing.T) {
	api := &fakeAPI{}
	k, dialed := testKubernetes(t, api)
	k.MCS = NewMCSAllocator(1024, 1100)
	b := podBackend(t, config.Backend{Name: "tickets", Command: []string{"/usr/bin/tickets-mcp"},
		Image: "registry.example.com/tickets-mcp:1", Credentials: []string{"api-token:/etc/mcp-gateway/credentials/api"}})
	inst, err := k.Start(context.Background(), b, remotePrincipal(), "0123abcd")
	if err != nil {
		t.Fatal(err)
	}
	if inst.Name() != "mcp-instances/mcp-tickets-0123abcd" || *dialed != "127.0.0.1:8765" {
		t.Errorf("name %q, dialed %q", inst.Name(), *dialed)
	}
	api.mu.Lock()
	// The pod first (its UID owns the others), its policy before the
	// Secret it cannot start without.
	if strings.Join(api.created, ",") != "Pod,NetworkPolicy,Secret" {
		t.Errorf("created %v", api.created)
	}
	for _, refs := range [][]kube.OwnerReference{api.policy.Metadata.OwnerReferences, api.secret.Metadata.OwnerReferences} {
		if len(refs) != 1 || refs[0].UID != "uid-1" || refs[0].Kind != "Pod" {
			t.Errorf("owner %+v", refs)
		}
	}
	if api.secret.StringData["credential.api-token"] != "secret of /etc/mcp-gateway/credentials/api" || len(api.secret.StringData[bridgeTokenKey]) != 64 {
		t.Errorf("secret %v", api.secret.StringData)
	}
	if lvl := api.pod.Spec.SecurityContext.SELinuxOptions; lvl == nil || !strings.HasPrefix(lvl.Level, "s0:c") {
		t.Errorf("no MCS level: %+v", lvl)
	}
	api.mu.Unlock()

	// stdio across the pod boundary.
	if _, err := io.WriteString(inst, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(inst).ReadString('\n'); err != nil || line != "ping\n" {
		t.Errorf("echo %q %v", line, err)
	}
	_ = inst.Close()
	_ = inst.Close()
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.deleted) != 1 || !strings.HasSuffix(strings.Split(api.deleted[0], "?")[0], "/pods/mcp-tickets-0123abcd") {
		t.Errorf("deleted %v", api.deleted)
	}
}

// A pod whose image does not pull fails the start at once, with the
// reason, and is deleted.
func TestKubernetesStartImagePull(t *testing.T) {
	api := &fakeAPI{waitReason: "ErrImagePull"}
	k, _ := testKubernetes(t, api)
	b := podBackend(t, config.Backend{Name: "x", Command: []string{"/usr/bin/x"}, Image: "registry.example.com/missing:1"})
	start := time.Now()
	_, err := k.Start(context.Background(), b, remotePrincipal(), "abc")
	if err == nil || !strings.Contains(err.Error(), "ErrImagePull") || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.deleted) != 1 {
		t.Errorf("deleted %v", api.deleted)
	}
}

func TestKubernetesCleanup(t *testing.T) {
	api := &fakeAPI{}
	k, _ := testKubernetes(t, api)
	if err := k.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.deleted) != 1 || !strings.Contains(api.deleted[0], "labelSelector=app.kubernetes.io%2Fmanaged-by%3Dmcp-gateway") {
		t.Errorf("deleted %v", api.deleted)
	}
}

func TestSplit(t *testing.T) {
	var got []string
	rec := func(kind string) Launcher {
		return launcherFunc(func(b *config.Backend) { got = append(got, kind+":"+b.Name) })
	}
	s := Split{HTTP: rec("http"), Stdio: rec("stdio")}
	_, _ = s.Start(context.Background(), &config.Backend{Name: "a", URL: "https://a/"}, remotePrincipal(), "1")
	_, _ = s.Start(context.Background(), &config.Backend{Name: "b", Command: []string{"/b"}}, remotePrincipal(), "2")
	if strings.Join(got, ",") != "http:a,stdio:b" {
		t.Errorf("%v", got)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// launcherFunc records the definitions it is asked to start.
type launcherFunc func(*config.Backend)

func (f launcherFunc) Start(_ context.Context, b *config.Backend, _ principal.Principal, _ string) (Instance, error) {
	f(b)
	return nil, nil
}
