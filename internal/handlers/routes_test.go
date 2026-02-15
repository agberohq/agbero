package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("test").Disable()

func TestRouteHandler_Proxy_RoundRobin(t *testing.T) {
	// 1. Create 2 dummy backends
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend1"))
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend2"))
	}))
	defer srv2.Close()

	// 2. Config
	route := &alaye.Route{
		Status: alaye.Success,
		Path:   "/",
		Backends: &alaye.Backend{
			Status:     alaye.Success,
			LBStrategy: alaye.StrategyRoundRobin,
			Servers:    alaye.NewServers(srv1.URL, srv2.URL),
		},
	}

	// 3. Init Handler
	h := NewRoute(route, nil, testLogger)
	defer h.Close()

	// 4. Test Round Robin (Should oscillate)
	// Note: The atomic counter increment order depends on implementation details,
	// but it should distribute.
	hits := make(map[string]int)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		body, _ := io.ReadAll(w.Result().Body)
		hits[string(body)]++
	}

	if hits["backend1"] < 4 || hits["backend2"] < 4 {
		t.Errorf("Round robin distribution uneven: %v", hits)
	}
}

func TestRouteHandler_Proxy_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: &alaye.Backend{
			Status:  alaye.Success,
			Servers: alaye.NewServers(srv.URL),
		},
		RateLimit: &alaye.RouteRate{
			Status: alaye.Success,
			Rule: &alaye.RateRule{
				Requests: 1,
				Window:   time.Minute,
				Key:      "ip",
			},
		},
	}

	h := NewRoute(route, nil, testLogger)
	defer h.Close()

	// First request (allowed)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	// Second request (rate limited)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests, got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_HeadersMiddleware(t *testing.T) {
	// Server checks for header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "Added" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: &alaye.Backend{
			Status:  alaye.Success,
			Servers: alaye.NewServers(srv.URL),
		},
		Headers: &alaye.Headers{
			Request: &alaye.Header{
				Set: map[string]string{"X-Test": "Added"},
			},
		},
	}

	h := NewRoute(route, nil, testLogger)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Headers middleware failed, backend got code %d", w.Code)
	}
}

func TestRouteHandler_Proxy_NoHealthyBackends(t *testing.T) {
	// Point to closed port
	route := &alaye.Route{
		Path: "/",
		Backends: &alaye.Backend{
			Status:  alaye.Success,
			Servers: alaye.NewServers("http://127.0.0.1:54321"),
		},
	}

	h := NewRoute(route, nil, testLogger)
	defer h.Close()

	// Manually mark dead for test immediate response
	// (Real world relies on health check or dial failure, but middleware might just error)
	for _, b := range h.Backends {
		b.Alive.Store(false)
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 Bad Gateway, got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("slow"))
	}))
	defer srv.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: &alaye.Backend{
			Status:  alaye.Success,
			Servers: alaye.NewServers(srv.URL),
		},
		Timeouts: &alaye.TimeoutRoute{
			Request: 10 * time.Millisecond, // Very short
		},
	}

	h := NewRoute(route, nil, testLogger)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// backend proxy usually returns 502 on context cancel/timeout
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 (Timeout), got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_StripPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users" {
			t.Errorf("Expected path /users, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := &alaye.Route{
		Path: "/api",
		Backends: &alaye.Backend{
			Status:  alaye.Success,
			Servers: alaye.NewServers(srv.URL),
		},
		StripPrefixes: []string{"/api"},
	}

	h := NewRoute(route, nil, testLogger)
	defer h.Close()

	// Simulate what handleRoute does: strip prefix before calling handler
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.URL.Path = "/users" // Simulate strip

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRouteHandler_Web_BasicFileServing(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("INDEX"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.html"), []byte("HELLO"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Status: alaye.Success,
		Path:   "/",
		Web: &alaye.Web{
			Status: alaye.Success,
			Root:   alaye.WebRoot(root),
			Index:  "index.html",
		},
	}

	h := NewRoute(route, nil, testLogger)

	// Test index file
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "INDEX" {
		t.Fatalf("expected INDEX, got %q", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html content type, got %q", w.Header().Get("Content-Type"))
	}

	// Test specific file
	req = httptest.NewRequest("GET", "/hello.html", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "HELLO" {
		t.Fatalf("expected HELLO, got %q", w.Body.String())
	}
}

func TestRouteHandler_Web_GzipPreCompressed(t *testing.T) {
	root := t.TempDir()

	// Create regular and gzipped versions
	if err := os.WriteFile(filepath.Join(root, "style.css"), []byte("/* regular */"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "style.css.gz"), []byte("/* gzipped */"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Status: alaye.Success,
		Path:   "/",
		Web: &alaye.Web{
			Status: alaye.Success,
			Root:   alaye.WebRoot(root),
		},
	}

	h := NewRoute(route, nil, testLogger)

	// Request with gzip support
	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Should serve the gzipped version with proper headers
	if w.Body.String() != "/* gzipped */" {
		t.Fatalf("expected gzipped content, got %q", w.Body.String())
	}
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip, got %q", w.Header().Get("Content-Encoding"))
	}
	if w.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("expected text/css content type, got %q", w.Header().Get("Content-Type"))
	}
}

func TestRouteHandler_Web_CustomIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "home.htm"), []byte("HOME"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: &alaye.Web{
			Status: alaye.Success,
			Root:   alaye.WebRoot(root),
			Index:  "home.htm",
		},
	}

	h := NewRoute(route, nil, testLogger)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "HOME" {
		t.Fatalf("expected HOME, got %q", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html content type, got %q", w.Header().Get("Content-Type"))
	}
}

func TestRouteHandler_Web_MethodNotAllowed(t *testing.T) {
	root := t.TempDir()
	route := &alaye.Route{
		Path: "/",
		Web: &alaye.Web{
			Status: alaye.Success,
			Root:   alaye.WebRoot(root),
		},
	}

	h := NewRoute(route, nil, testLogger)

	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRouteHandler_Web_DirectoryWithoutIndex(t *testing.T) {
	root := t.TempDir()
	// Create empty directory, no index file
	os.MkdirAll(filepath.Join(root, "subdir/"), 0755)

	route := &alaye.Route{
		Status: alaye.Success,
		Path:   "/",
		Web: &alaye.Web{
			Status:  alaye.Success,
			Root:    alaye.WebRoot(root),
			Listing: false,
		},
	}

	h := NewRoute(route, nil, testLogger)

	req := httptest.NewRequest(http.MethodGet, "/subdir/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for directory without index, got %d", w.Code)
	}
}

func TestRouteHandler_Web_PathTraversalPrevented(t *testing.T) {
	root := t.TempDir()

	// Create a file outside the temp dir to test traversal
	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("SECRET"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Status: alaye.Success,
		Path:   "/files",
		Web: &alaye.Web{
			Status: alaye.Success,
			Root:   alaye.WebRoot(root),
		},
	}

	h := NewRoute(route, nil, testLogger)

	// Try to traverse outside the root
	req := httptest.NewRequest("GET", "/files/../../../"+filepath.Base(outsideFile), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should be blocked by os.OpenRoot
	if w.Code != http.StatusNotFound && w.Code != http.StatusForbidden {
		t.Fatalf("expected 404 or 403 for path traversal, got %d", w.Code)
	}
}

func TestRouteHandler_Web_WithMiddleware(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "test.txt"), []byte("test"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Status: alaye.Success,
		Path:   "/",
		Web: &alaye.Web{
			Status: alaye.Success,
			Root:   alaye.WebRoot(root),
		},
		CompressionConfig: &alaye.Compression{
			Status: alaye.Success,
			Type:   "gzip",
			Level:  5,
		},
		Headers: &alaye.Headers{
			Status: alaye.Success,
			Response: &alaye.Header{
				Set: map[string]string{
					"X-Custom-Header": "TestValue",
					"Cache-Control":   "public, max-age=3600",
				},
			},
		},
	}

	h := NewRoute(route, nil, testLogger)

	req := httptest.NewRequest("GET", "/test.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Custom-Header") != "TestValue" {
		t.Errorf("expected custom header, got %q", w.Header().Get("X-Custom-Header"))
	}
	if w.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("expected cache control header, got %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("expected Vary header for compression, got %q", w.Header().Get("Vary"))
	}
}

func TestRouteHandler_Validation(t *testing.T) {
	type tc struct {
		name       string
		route      *alaye.Route
		wantStatus int
		prepare    func(t *testing.T, r *alaye.Route) // optional per-case setup
	}

	tests := []tc{
		{
			name: "valid proxy route",
			route: &alaye.Route{
				Status: alaye.Success,
				Path:   "/api",
				// Changed from localhost:3000 to avoid port conflicts in CI/dev environments.
				// Using a high, presumably unused port ensures a connection error (502).
				Backends: &alaye.Backend{
					Status:  alaye.Success,
					Servers: alaye.NewServers("http://127.0.0.1:59999"),
				},
			},
			wantStatus: http.StatusBadGateway, // backend not running
		},
		{
			name: "valid web route",
			route: &alaye.Route{
				Path: "/",
				Web:  &alaye.Web{}, // filled in prepare()
			},
			prepare: func(t *testing.T, r *alaye.Route) {
				t.Helper()

				root := t.TempDir()
				if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("OK"), woos.FilePerm); err != nil {
					t.Fatal(err)
				}

				r.Web.Root = alaye.WebRoot(root)
				r.Web.Index = "index.html"
				// listing stays default false, but index exists => 200
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "invalid: both web and backends",
			route: &alaye.Route{
				Path: "/",
				Backends: &alaye.Backend{
					Status:  alaye.Success,
					Servers: alaye.NewServers("http://localhost:3000"),
				},
				Web: &alaye.Web{Root: alaye.WebRoot("/tmp")},
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "invalid: neither web nor backends",
			route:      &alaye.Route{Path: "/"},
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepare != nil {
				tt.prepare(t, tt.route)
			}

			h := NewRoute(tt.route, nil, testLogger)
			if h == nil {
				t.Fatal("handler must never be nil")
			}
			defer h.Close()

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}
