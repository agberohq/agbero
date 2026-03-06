package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("test").Disable()
var global = &alaye.Global{}
var testHost = &alaye.Host{
	Domains: []string{"example.com", "test.local"},
}

func TestRouteHandler_Proxy_RoundRobin(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend1"))
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend2"))
	}))
	defer srv2.Close()

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled:  alaye.Active,
			Strategy: alaye.StrategyRoundRobin,
			Servers:  alaye.NewServers(srv1.URL, srv2.URL),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	hits := make(map[string]int)

	for range 10 {
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
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
		RateLimit: alaye.RouteRate{
			Enabled: alaye.Active,
			Rule: alaye.RateRule{
				Enabled:  alaye.Active,
				Requests: 1,
				Window:   time.Minute,
				Key:      "ip",
			},
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests, got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_HeadersMiddleware(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "Added" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
		Headers: alaye.Headers{
			Enabled: alaye.Active,
			Request: alaye.Header{
				Enabled: alaye.Active,
				Set:     map[string]string{"X-Test": "Added"},
			},
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Headers middleware failed, backend got code %d", w.Code)
	}
}

func TestRouteHandler_Proxy_NoHealthyBackends(t *testing.T) {
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://127.0.0.1:54321"),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	for _, b := range h.Backends {
		b.Status(false)
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
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
		Timeouts: alaye.TimeoutRoute{
			Enabled: alaye.Active,
			Request: 10 * time.Millisecond,
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

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
		Enabled: alaye.Active,
		Path:    "/api",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
		StripPrefixes: []string{"/api"},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/users", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_WithFallback(t *testing.T) {
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://127.0.0.1:54321"),
		},
		Fallback: alaye.Fallback{
			Enabled:     alaye.Active,
			Type:        "static",
			Body:        "Fallback content",
			StatusCode:  http.StatusServiceUnavailable,
			ContentType: "text/plain",
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
	if w.Body.String() != "Fallback content" {
		t.Errorf("Expected 'Fallback content', got %q", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("Expected Content-Type: text/plain, got %q", w.Header().Get("Content-Type"))
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
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
			Index:   "index.html",
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

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

	if err := os.WriteFile(filepath.Join(root, "style.css"), []byte("/* regular */"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "style.css.gz"), []byte("/* gzipped */"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
		CompressionConfig: alaye.Compression{
			Enabled: alaye.Active,
			Type:    "gzip",
			Level:   5,
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

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
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
			Index:   "home.htm",
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

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
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRouteHandler_Web_DirectoryWithoutIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
			Listing: false,
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/subdir/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for directory without index, got %d", w.Code)
	}
}

func TestRouteHandler_Web_PathTraversalPrevented(t *testing.T) {
	root := t.TempDir()

	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("SECRET"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/files",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/files/../../../"+filepath.Base(outsideFile), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

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
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
		CompressionConfig: alaye.Compression{
			Enabled: alaye.Active,
			Type:    "gzip",
			Level:   5,
		},
		Headers: alaye.Headers{
			Enabled: alaye.Active,
			Response: alaye.Header{
				Enabled: alaye.Active,
				Set: map[string]string{
					"X-Custom-Header": "TestValue",
					"Cache-Control":   "public, max-age=3600",
				},
			},
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

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
		prepare    func(t *testing.T, r *alaye.Route)
	}

	tests := []tc{
		{
			name: "valid proxy route",
			route: &alaye.Route{
				Enabled: alaye.Active,
				Path:    "/api",
				Backends: alaye.Backend{
					Enabled: alaye.Active,
					Servers: alaye.NewServers("http://127.0.0.1:59999"),
				},
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "valid web route",
			route: &alaye.Route{
				Enabled: alaye.Active,
				Path:    "/",
				Web:     alaye.Web{},
			},
			prepare: func(t *testing.T, r *alaye.Route) {
				t.Helper()

				root := t.TempDir()
				if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("OK"), woos.FilePerm); err != nil {
					t.Fatal(err)
				}

				r.Web.Root = alaye.WebRoot(root)
				r.Web.Index = "index.html"
				r.Web.Enabled = alaye.Active
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "invalid: both web and backends",
			route: &alaye.Route{
				Enabled: alaye.Active,
				Path:    "/",
				Backends: alaye.Backend{
					Enabled: alaye.Active,
					Servers: alaye.NewServers("http://localhost:3000"),
				},
				Web: alaye.Web{
					Enabled: alaye.Active,
					Root:    alaye.WebRoot("/tmp"),
				},
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "invalid: neither web nor backends",
			route:      &alaye.Route{Path: "/"},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "route with allowed IPs",
			route: &alaye.Route{
				Enabled:    alaye.Active,
				Path:       "/",
				AllowedIPs: []string{"127.0.0.1/32"},
				Web: alaye.Web{
					Enabled: alaye.Active,
				},
			},
			prepare: func(t *testing.T, r *alaye.Route) {
				root := t.TempDir()
				os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0644)
				r.Web.Root = alaye.WebRoot(root)
				r.Web.Index = "index.html"
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepare != nil {
				tt.prepare(t, tt.route)
			}

			cfg := Config{
				Global: global,
				Host:   testHost,
				Logger: testLogger,
				IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
			}
			h := NewRoute(cfg, tt.route)
			if h == nil {
				t.Fatal("handler must never be nil")
			}
			defer h.Close()

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestRouteHandler_WithJWTAuth(t *testing.T) {
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		JWTAuth: alaye.JWTAuth{
			Enabled: alaye.Active,
			Secret:  "test-secret",
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(t.TempDir()),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRouteHandler_WithBasicAuth(t *testing.T) {
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		BasicAuth: alaye.BasicAuth{
			Enabled: alaye.Active,
			Realm:   "test",
			Users:   []string{"user:pass"},
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(t.TempDir()),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRouteHandler_WithCache(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "test.txt"), []byte("cached content"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Cache: alaye.Cache{
			Enabled: alaye.Active,
			TTL:     5 * time.Minute,
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/test.txt", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if w.Header().Get("X-Cache") != "MISS" {
		t.Errorf("Expected X-Cache: MISS, got %q", w.Header().Get("X-Cache"))
	}
}

func TestRouteHandler_WithCORS(t *testing.T) {
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		CORS: alaye.CORS{
			Enabled:        alaye.Active,
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST"},
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(t.TempDir()),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 204 && w.Code != 200 {
		t.Errorf("Expected 204 No Content for preflight, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected CORS headers, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestRouteHandler_WithOAuth(t *testing.T) {
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		OAuth: alaye.OAuth{
			Enabled:      alaye.Active,
			Provider:     "google",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://example.com/callback  ",
			CookieSecret: "16-char-secret!!!",
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(t.TempDir()),
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect && w.Code != http.StatusFound {
		t.Errorf("Expected redirect (302/307), got %d", w.Code)
	}
}

func TestRouteHandler_WithForwardAuth(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0644)

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		ForwardAuth: alaye.ForwardAuth{
			Enabled: alaye.Active,
			URL:     authServer.URL,
			Request: alaye.ForwardAuthRequest{
				Enabled: alaye.Active,
			},
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
			Index:   "index.html",
		},
	}

	cfg := Config{
		Global: global,
		Host:   testHost,
		Logger: testLogger,
		IPMgr:  zulu.NewIPManager(global.Security.TrustedProxies),
	}
	h := NewRoute(cfg, route)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}
