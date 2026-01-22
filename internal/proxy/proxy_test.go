// internal/proxy/proxy_test.go
package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/config"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/olekukonko/ll"
)

// Helper to create a temp file
func createTempFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to create %s: %v", name, err)
	}
	return path
}

func TestProxy_EndToEnd(t *testing.T) {
	// 1. Setup Mock Backends
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

	// 2. Setup Host Configuration Directory
	hostsDir := t.TempDir()

	// Create a host config that routes to our mock backends
	// FIX: Added '*' to /api* to allow matching /api/data
	hostHCL := fmt.Sprintf(`
		server_names = ["example.com", "api.example.com"]

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

	// Create a static web host
	webDir := t.TempDir()
	// FIX: Use hello.html instead of index.html for direct access test
	// http.ServeFile forces a 301 redirect for "index.html" -> "./"
	createTempFile(t, webDir, "hello.html", "<h1>Hello World</h1>")
	createTempFile(t, webDir, "index.html", "<h1>Index Page</h1>")

	webHostHCL := fmt.Sprintf(`
		server_names = ["static.com"]
		web {
			root = "%s"
		}
	`, webDir)
	createTempFile(t, hostsDir, "static.hcl", webHostHCL)

	// 3. Initialize Server Dependencies
	hm := discovery.NewHost(hostsDir)
	_, err := hm.LoadAll()
	if err != nil {
		t.Fatalf("failed to load hosts: %v", err)
	}

	globalCfg := &config.GlobalConfig{
		Bind: ":0",
	}

	logger := ll.New("test")

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(globalCfg),
		WithLogger(logger),
	)

	// 4. Test Cases

	tests := []struct {
		name           string
		hostHeader     string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Route Proxy Success",
			hostHeader:     "example.com",
			path:           "/api/data",
			expectedStatus: 200,
			expectedBody:   "response from backend 1",
		},
		{
			name:           "Static Web File Success",
			hostHeader:     "static.com",
			path:           "/hello.html", // Accessing non-index file directly
			expectedStatus: 200,
			expectedBody:   "<h1>Hello World</h1>",
		},
		{
			name:           "Static Web Index Default",
			hostHeader:     "static.com",
			path:           "/",
			expectedStatus: 200,
			expectedBody:   "<h1>Index Page</h1>",
		},
		{
			name:           "Host Not Found",
			hostHeader:     "unknown.com",
			path:           "/",
			expectedStatus: 404,
			expectedBody:   "Host not found",
		},
		{
			name:           "Path Not Found on Known Host",
			hostHeader:     "example.com",
			path:           "/missing",
			expectedStatus: 404,
			expectedBody:   "Not found",
		},
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

func TestProxy_LoadBalancing(t *testing.T) {
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
		server_names = ["lb.com"]
		route "/" {
			backends = ["%s", "%s"]
			lb_strategy = "roundrobin"
		}
	`, b1.URL, b2.URL)
	createTempFile(t, hostsDir, "lb.hcl", hcl)

	hm := discovery.NewHost(hostsDir)
	hm.LoadAll()

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(&config.GlobalConfig{Bind: ":80"}),
		WithLogger(ll.New("test")),
	)

	// Make 10 requests, expect distribution
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "http://lb.com/", nil)
		w := httptest.NewRecorder()
		srv.handleRequest(w, req)

		body, _ := io.ReadAll(w.Result().Body)
		counts[string(body)]++
	}

	if counts["B1"] == 0 || counts["B2"] == 0 {
		t.Errorf("Load balancing failed, distribution: %v", counts)
	}
}
