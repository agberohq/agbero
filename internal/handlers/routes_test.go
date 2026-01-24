package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("test")

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
		Path:       "/",
		Backends:   []string{srv1.URL, srv2.URL},
		LBStrategy: alaye.StrategyRoundRobin,
	}

	// 3. Init Handler
	h := NewRouteHandler(route, testLogger)
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

func TestRouteHandler_Proxy_HeadersMiddleware(t *testing.T) {
	// Backend checks for header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "Added" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := &alaye.Route{
		Path:     "/",
		Backends: []string{srv.URL},
		Headers: &alaye.Headers{
			Request: &alaye.Header{
				Set: map[string]string{"X-Test": "Added"},
			},
		},
	}

	h := NewRouteHandler(route, testLogger)
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
		Path:     "/",
		Backends: []string{"http://127.0.0.1:54321"},
	}

	h := NewRouteHandler(route, testLogger)
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
		Path:     "/",
		Backends: []string{srv.URL},
		Timeouts: &alaye.TimeoutRoute{
			Request: 10 * time.Millisecond, // Very short
		},
	}

	h := NewRouteHandler(route, testLogger)
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
		Path:          "/api",
		Backends:      []string{srv.URL},
		StripPrefixes: []string{"/api"},
	}

	h := NewRouteHandler(route, testLogger)
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
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("INDEX"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.html"), []byte("HELLO"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root:  alaye.WebRoot(root),
			Index: "index.html",
		},
	}

	h := NewRouteHandler(route, testLogger)

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
	if err := os.WriteFile(filepath.Join(root, "style.css"), []byte("/* regular */"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "style.css.gz"), []byte("/* gzipped */"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	h := NewRouteHandler(route, testLogger)

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
	if err := os.WriteFile(filepath.Join(root, "home.htm"), []byte("HOME"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root:  alaye.WebRoot(root),
			Index: "home.htm",
		},
	}

	h := NewRouteHandler(route, testLogger)

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
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	h := NewRouteHandler(route, testLogger)

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
	os.MkdirAll(filepath.Join(root, "subdir"), 0755)

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	h := NewRouteHandler(route, testLogger)

	req := httptest.NewRequest("GET", "/subdir", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should return 403 Forbidden (no index file)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for directory without index, got %d", w.Code)
	}
}

func TestRouteHandler_Web_PathTraversalPrevented(t *testing.T) {
	root := t.TempDir()

	// Create a file outside the temp dir to test traversal
	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("SECRET"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/files",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	h := NewRouteHandler(route, testLogger)

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
	if err := os.WriteFile(filepath.Join(root, "test.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
		CompressionConfig: alaye.Compression{
			Compression: true,
			Type:        "gzip",
			Level:       5,
		},
		Headers: &alaye.Headers{
			Response: &alaye.Header{
				Set: map[string]string{
					"X-Custom-Header": "TestValue",
					"Cache-Control":   "public, max-age=3600",
				},
			},
		},
	}

	h := NewRouteHandler(route, testLogger)

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
	tests := []struct {
		name    string
		route   *alaye.Route
		wantErr bool
	}{
		{
			name: "valid proxy route",
			route: &alaye.Route{
				Path:     "/api",
				Backends: []string{"http://localhost:3000"},
			},
			wantErr: false,
		},
		{
			name: "valid web route",
			route: &alaye.Route{
				Path: "/",
				Web: alaye.Web{
					Root: alaye.WebRoot("/tmp"),
				},
			},
			wantErr: false,
		},
		{
			name: "invalid: both web and backends",
			route: &alaye.Route{
				Path:     "/",
				Backends: []string{"http://localhost:3000"},
				Web: alaye.Web{
					Root: alaye.WebRoot("/tmp"),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid: neither web nor backends",
			route: &alaye.Route{
				Path: "/",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.wantErr {
						t.Errorf("unexpected panic: %v", r)
					}
				}
			}()

			h := NewRouteHandler(tt.route, testLogger)
			if h != nil {
				h.Close()
			}

			if tt.wantErr && h != nil {
				t.Error("expected error but handler was created")
			}
			if !tt.wantErr && h == nil {
				t.Error("expected handler but got nil")
			}
		})
	}
}
