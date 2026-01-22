package agbero

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

func createTempFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to create %s: %v", name, err)
	}
	return path
}

func TestProxy_EndToEnd(t *testing.T) {
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response from backend 1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response from backend 2"))
	}))
	defer backend2.Close()

	hostsDir := t.TempDir()

	hostHCL := fmt.Sprintf(`
		domains = ["example.com", "api.example.com"]

		route "/api*" {
			backends = ["%s"]
			strip_prefixes = ["/api"]
		}

		route "/balanced" {
			backends = ["%s", "%s"]
			lb_strategy = "roundrobin"
		}
	`, backend1.URL, backend1.URL, backend2.URL)

	createTempFile(t, hostsDir, "example.hcl", hostHCL)

	webDir := t.TempDir()
	createTempFile(t, webDir, "hello.html", "<h1>Hello World</h1>")
	createTempFile(t, webDir, "index.html", "<h1>Index Page</h1>")

	webHostHCL := fmt.Sprintf(`
		domains = ["static.com"]
		web { root = "%s" }
	`, webDir)
	createTempFile(t, hostsDir, "static.hcl", webHostHCL)

	hm := discovery.NewHost(hostsDir)
	if _, err := hm.LoadAll(); err != nil {
		t.Fatalf("failed to load hosts: %v", err)
	}

	globalCfg := &woos.GlobalConfig{Bind: ":0"}
	logger := ll.New("test")

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(globalCfg),
		WithLogger(logger),
	)

	tests := []struct {
		name           string
		hostHeader     string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{"Route Proxy Success", "example.com", "/api/data", 200, "response from backend 1"},
		{"Static Web File Success", "static.com", "/hello.html", 200, "<h1>Hello World</h1>"},
		{"Static Web Index Default", "static.com", "/", 200, "<h1>Index Page</h1>"},
		{"Host Not Found", "unknown.com", "/", 404, "Host not found"},
		{"Path Not Found on Known Host", "example.com", "/missing", 404, "Not found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tc.hostHeader+tc.path, nil)
			req.Host = tc.hostHeader
			w := httptest.NewRecorder()

			srv.handleRequest(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("path %s: expected status %d, got %d", tc.path, tc.expectedStatus, resp.StatusCode)
			}

			if !strings.Contains(string(body), tc.expectedBody) {
				t.Errorf("path %s: expected body to contain %q, got %q", tc.path, tc.expectedBody, string(body))
			}
		})
	}
}

func TestProxy_LoadBalancing_RoundRobin(t *testing.T) {
	counts := make(map[string]int)

	b1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("B1"))
	}))
	defer b1.Close()

	b2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("B2"))
	}))
	defer b2.Close()

	hostsDir := t.TempDir()
	hcl := fmt.Sprintf(`
		domains = ["lb.com"]
		route "/" {
			backends = ["%s", "%s"]
			lb_strategy = "roundrobin"
		}
	`, b1.URL, b2.URL)
	createTempFile(t, hostsDir, "lb.hcl", hcl)

	hm := discovery.NewHost(hostsDir)
	if _, err := hm.LoadAll(); err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(&woos.GlobalConfig{Bind: ":80"}),
		WithLogger(ll.New("test")),
	)

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "http://lb.com/", nil)
		req.Host = "lb.com"
		w := httptest.NewRecorder()
		srv.handleRequest(w, req)

		body, _ := io.ReadAll(w.Result().Body)
		counts[string(body)]++
	}

	if counts["B1"] == 0 || counts["B2"] == 0 {
		t.Fatalf("round robin failed: %v", counts)
	}
}

func TestRouteHandler_LeastConnPrefersLowerInflight(t *testing.T) {
	// Build a handler with 2 backends; then simulate inflight on backend 0.
	r := &woos.Route{
		Path:       "/",
		LBStrategy: "leastconn",
		Backends:   []string{"http://a:1", "http://b:2"},
	}

	h := core.NewRouteHandler(r)
	if len(h.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(h.Backends))
	}

	// Make backend[0] "busy"
	h.Backends[0].Inflight.Add(10)
	h.Backends[1].Inflight.Add(1)

	b := h.PickBackend()
	if b != h.Backends[1] {
		t.Fatalf("expected backend[1] (lower inflight) selected")
	}
}

func TestServer_RouteCache_ReusesHandler(t *testing.T) {
	r := &woos.Route{
		Path:          "/api*",
		LBStrategy:    "roundrobin",
		Backends:      []string{"http://a:1"},
		StripPrefixes: []string{"/api"},
	}

	s := &Server{}
	h1 := s.getOrBuildRouteHandler(r)
	h2 := s.getOrBuildRouteHandler(r)

	if h1 != h2 {
		t.Fatalf("expected cached handler reuse")
	}
}

func TestServer_StripPrefix_RestoresPath(t *testing.T) {
	// Make a minimal server that calls handleRoute and ensures path is restored.
	r := &woos.Route{
		Path:          "/api*",
		LBStrategy:    "roundrobin",
		Backends:      []string{"http://a:1"}, // invalid URL host will be skipped; handler will have 0 backends
		StripPrefixes: []string{"/api"},
	}

	s := &Server{}
	req := httptest.NewRequest("GET", "http://x/api/hello", nil)
	rr := httptest.NewRecorder()

	origPath := req.URL.Path
	s.handleRoute(rr, req, r)

	if req.URL.Path != origPath {
		t.Fatalf("expected path restored to %q, got %q", origPath, req.URL.Path)
	}
}
