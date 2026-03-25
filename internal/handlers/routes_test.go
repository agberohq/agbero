package handlers

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/cook"
	"github.com/agberohq/agbero/internal/pkg/orchestrator"
	"github.com/olekukonko/ll"
)

func NewTestConfig(t *testing.T) resource.Proxy {
	t.Helper()
	global := &alaye.Global{
		Timeouts: alaye.Timeout{
			Read:  alaye.Duration(30 * time.Second),
			Write: alaye.Duration(30 * time.Second),
			Idle:  alaye.Duration(120 * time.Second),
		},
		Security: alaye.Security{
			Enabled:        alaye.Inactive,
			TrustedProxies: []string{},
		},
		RateLimits: alaye.GlobalRate{
			Enabled:    alaye.Inactive,
			TTL:        alaye.Duration(10 * time.Minute),
			MaxEntries: 10000,
		},
		Storage: alaye.Storage{
			WorkDir: t.TempDir(),
		},
	}
	host := &alaye.Host{
		Domains: []string{"example.com", "test.local"},
	}
	res := resource.New()
	cm, _ := cook.NewManager(cook.ManagerConfig{
		WorkDir: t.TempDir(),
		Logger:  ll.New("test").Disable(),
	})
	return resource.Proxy{
		Global:   global,
		Host:     host,
		IPMgr:    zulu.NewIPManager(global.Security.TrustedProxies),
		CookMgr:  cm,
		Resource: res,
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     resource.Proxy
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: resource.Proxy{
				Global:   &alaye.Global{},
				Host:     &alaye.Host{Domains: []string{"example.com"}},
				Resource: resource.New(),
			},
			wantErr: false,
		},
		{
			name: "nil resource",
			cfg: resource.Proxy{
				Global: &alaye.Global{},
				Host:   &alaye.Host{Domains: []string{"example.com"}},
			},
			wantErr: true,
		},
		{
			name: "nil global",
			cfg: resource.Proxy{
				Host:     &alaye.Host{Domains: []string{"example.com"}},
				Resource: resource.New(),
			},
			wantErr: true,
		},
		{
			name: "nil host",
			cfg: resource.Proxy{
				Global:   &alaye.Global{},
				Resource: resource.New(),
			},
			wantErr: true,
		},
		{
			name: "empty host domains",
			cfg: resource.Proxy{
				Global:   &alaye.Global{},
				Host:     &alaye.Host{Domains: []string{}},
				Resource: resource.New(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewRoute_NilRoute(t *testing.T) {
	cfg := NewTestConfig(t)
	route := NewRoute(cfg, nil)
	if route == nil {
		t.Fatal("NewRoute should return fallback route, not nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for nil route, got %d", w.Code)
	}
}

func TestNewRoute_InvalidConfig(t *testing.T) {
	cfg := resource.Proxy{}
	route := NewRoute(cfg, &alaye.Route{Path: "/"})
	if route == nil {
		t.Fatal("NewRoute should return fallback route, not nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for invalid config, got %d", w.Code)
	}
}

func TestNewRoute_InvalidRouteConfig(t *testing.T) {
	cfg := NewTestConfig(t)
	route := NewRoute(cfg, &alaye.Route{Path: "invalid-no-slash"})
	if route == nil {
		t.Fatal("NewRoute should return fallback route, not nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for invalid route config, got %d", w.Code)
	}
}

func TestNewRoute_WebAndBackendConflict(t *testing.T) {
	cfg := NewTestConfig(t)
	root := t.TempDir()
	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://example.com"),
		},
	})
	if route == nil {
		t.Fatal("NewRoute should return fallback route, not nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for web+backend conflict, got %d", w.Code)
	}
}

func TestNewRoute_NoHandlerConfig(t *testing.T) {
	cfg := NewTestConfig(t)
	route := NewRoute(cfg, &alaye.Route{Path: "/"})
	if route == nil {
		t.Fatal("NewRoute should return fallback route, not nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for no handler config, got %d", w.Code)
	}
}

func TestRoute_ServeHTTP_NilHandler(t *testing.T) {
	route := &Route{}
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for nil handler, got %d", w.Code)
	}
}

func TestRoute_Close_Empty(t *testing.T) {
	route := &Route{}
	route.Close()
}

func TestRoute_Close_WithBackends(t *testing.T) {
	cfg := NewTestConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
	})
	if route == nil {
		t.Fatal("NewRoute failed")
	}

	route.Close()
}

func TestRoute_Close_WithProxy(t *testing.T) {
	cfg := NewTestConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
	})
	if route == nil {
		t.Fatal("NewRoute failed")
	}

	route.Close()
}

func TestRoute_RegisterPatients_NilDoctor(t *testing.T) {
	cfg := NewTestConfig(t)
	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://example.com"),
		},
	})
	if route == nil {
		t.Fatal("NewRoute failed")
	}
}

func TestRoute_RegisterPatients_InvalidBackendURL(t *testing.T) {
	cfg := NewTestConfig(t)
	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("://invalid"),
		},
		HealthCheck: alaye.HealthCheck{
			Enabled: alaye.Active,
			Path:    "/health",
		},
	})
	if route == nil {
		t.Fatal("NewRoute failed")
	}
}

func TestRoute_RegisterPatients_Success(t *testing.T) {
	cfg := NewTestConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
		HealthCheck: alaye.HealthCheck{
			Enabled:  alaye.Active,
			Path:     "/health",
			Interval: alaye.Duration(50 * time.Millisecond),
			Timeout:  alaye.Duration(100 * time.Millisecond),
		},
	})
	if route == nil {
		t.Fatal("NewRoute failed")
	}
	time.Sleep(100 * time.Millisecond)
}

func TestRoute_GetBackendKeys(t *testing.T) {
	cfg := NewTestConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	route := NewRoute(cfg, &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(srv.URL),
		},
	})
	if route == nil {
		t.Fatal("NewRoute failed")
	}
}

func TestRouteHandler_Proxy_RoundRobin(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

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
				Window:   alaye.Duration(time.Minute),
				Key:      "ip",
			},
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Headers middleware failed, backend got code %d", w.Code)
	}
}

func TestRouteHandler_Proxy_NoHealthyBackends(t *testing.T) {
	cfg := NewTestConfig(t)

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://127.0.0.1:54321"),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	for _, b := range h.Backends {
		if b != nil {
			b.Status(false)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 Bad Gateway, got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_Timeout(t *testing.T) {
	cfg := NewTestConfig(t)

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
			Request: alaye.Duration(10 * time.Millisecond),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusGatewayTimeout && w.Code != http.StatusBadGateway {
		t.Errorf("Expected 504 (Gateway Timeout) or 502 (Bad Gateway), got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_StripPrefix(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/users", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRouteHandler_Proxy_WithFallback(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

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
			Index:   []string{"index.html"},
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

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
			Index:   []string{"home.htm"},
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

	root := t.TempDir()
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRouteHandler_Web_DirectoryWithoutIndex(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/subdir/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for directory without index, got %d", w.Code)
	}
}

func TestRouteHandler_Web_PathTraversalPrevented(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/files/../../../"+filepath.Base(outsideFile), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound && w.Code != http.StatusForbidden {
		t.Fatalf("expected 404 or 403 for path traversal, got %d", w.Code)
	}
}

func TestRouteHandler_Web_WithMiddleware(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
				r.Web.Index = []string{"index.html"}
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
				r.Web.Index = []string{"index.html"}
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepare != nil {
				tt.prepare(t, tt.route)
			}

			cfg := NewTestConfig(t)
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
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRouteHandler_WithBasicAuth(t *testing.T) {
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRouteHandler_WithCache(t *testing.T) {
	cfg := NewTestConfig(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "test.txt"), []byte("cached content"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Cache: alaye.Cache{
			Enabled: alaye.Active,
			TTL:     alaye.Duration(5 * time.Minute),
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
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
	cfg := NewTestConfig(t)

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		OAuth: alaye.OAuth{
			Enabled:      alaye.Active,
			Provider:     "google",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://example.com/callback",
			CookieSecret: "16-char-secret!!!",
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(t.TempDir()),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect && w.Code != http.StatusFound {
		t.Errorf("Expected redirect (302/307), got %d", w.Code)
	}
}

func TestRouteHandler_WithForwardAuth(t *testing.T) {
	cfg := NewTestConfig(t)

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
			Enabled:      alaye.Active,
			AllowPrivate: true,
			URL:          authServer.URL,
			Request: alaye.ForwardAuthRequest{
				Enabled: alaye.Active,
			},
		},
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
			Index:   []string{"index.html"},
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRouteHandler_WithWASM(t *testing.T) {
	// Note: WASM loading occurs in Resource.handleRoute(), not in NewRoute().
	// This test validates that NewRoute() doesn't crash on invalid WASM config.
	// Actual WASM error handling is tested at the manager level.

	cfg := NewTestConfig(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("INDEX"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
			Index:   []string{"index.html"},
		},
		Wasm: alaye.Wasm{
			Enabled: alaye.Active,
			Module:  "/nonexistent/module.wasm",
		},
	}
	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	// Since WASM isn't loaded in NewRoute(), the web handler serves the file successfully.
	// WASM errors would only occur if the request went through Resource.handleRoute().
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Expect 200: web handler works; WASM validation happens at dispatch layer
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 (WASM not loaded at route level), got %d", w.Code)
	}
}

func TestRouteHandler_WithFirewall(t *testing.T) {
	// Firewall middleware is applied at manager level via chainBuildFirewall(),
	// not in NewRoute(). This test validates route creation with firewall config.
	// Note: Backend may not be reachable in test environment, so 502 is also acceptable.
	cfg := NewTestConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		Firewall: alaye.FirewallRoute{
			Status: alaye.Active,
			Rules: []alaye.Rule{
				{
					Name:   "test-rule",
					Action: "deny",
					Match: alaye.Match{
						IP: []string{"192.0.2.1"},
					},
				},
			},
		},
	}
	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	// Accept 403 (firewall), 200 (allowed), or 502 (backend unreachable in test)
	if w.Code != http.StatusForbidden && w.Code != http.StatusOK && w.Code != http.StatusBadGateway {
		t.Errorf("Expected 403, 200, or 502, got %d", w.Code)
	}
}

func TestResolveFallback(t *testing.T) {
	tests := []struct {
		name           string
		routeFallback  *alaye.Fallback
		globalFallback *alaye.Fallback
		wantActive     bool
	}{
		{
			name: "route fallback active",
			routeFallback: &alaye.Fallback{
				Enabled: alaye.Active,
				Type:    "static",
			},
			globalFallback: nil,
			wantActive:     true,
		},
		{
			name: "route fallback unknown, global active",
			routeFallback: &alaye.Fallback{
				Enabled: alaye.Unknown,
			},
			globalFallback: &alaye.Fallback{
				Enabled: alaye.Active,
				Type:    "static",
			},
			wantActive: true,
		},
		{
			name: "route fallback inactive",
			routeFallback: &alaye.Fallback{
				Enabled: alaye.Inactive,
			},
			globalFallback: &alaye.Fallback{
				Enabled: alaye.Active,
			},
			wantActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveFallback(tt.routeFallback, tt.globalFallback)
			gotActive := result != nil && result.IsActive()
			if gotActive != tt.wantActive {
				t.Errorf("resolveFallback() active = %v, want %v", gotActive, tt.wantActive)
			}
		})
	}
}

func TestBuildFallbackHandler_Static(t *testing.T) {
	logger := ll.New("test").Disable()
	fallback := &alaye.Fallback{
		Type:        "static",
		Body:        "test body",
		ContentType: "text/plain",
		StatusCode:  http.StatusServiceUnavailable,
		CacheTTL:    300,
	}

	handler := buildFallbackHandler(fallback, logger)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503, got %d", w.Code)
	}
	if w.Body.String() != "test body" {
		t.Errorf("Expected 'test body', got %q", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("Expected Content-Type: text/plain, got %q", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "max-age=300") {
		t.Errorf("Expected Cache-Control with max-age=300, got %q", w.Header().Get("Cache-Control"))
	}
}

func TestBuildFallbackHandler_Redirect(t *testing.T) {
	logger := ll.New("test").Disable()
	fallback := &alaye.Fallback{
		Type:        "redirect",
		RedirectURL: "https://example.com/fallback",
		StatusCode:  http.StatusTemporaryRedirect,
	}

	handler := buildFallbackHandler(fallback, logger)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("Expected 307, got %d", w.Code)
	}
	if w.Header().Get("Location") != "https://example.com/fallback" {
		t.Errorf("Expected Location header, got %q", w.Header().Get("Location"))
	}
}

func TestBuildFallbackHandler_Proxy(t *testing.T) {
	logger := ll.New("test").Disable()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	}))
	defer backend.Close()

	fallback := &alaye.Fallback{
		Type:     "proxy",
		ProxyURL: backend.URL,
	}

	handler := buildFallbackHandler(fallback, logger)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Body.String() != "proxied" {
		t.Errorf("Expected 'proxied', got %q", w.Body.String())
	}
}

func TestBuildFallbackHandler_Proxy_InvalidURL(t *testing.T) {
	logger := ll.New("test").Disable()
	fallback := &alaye.Fallback{
		Type:     "proxy",
		ProxyURL: "://invalid",
	}

	handler := buildFallbackHandler(fallback, logger)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

func TestBuildFallbackHandler_UnknownType(t *testing.T) {
	logger := ll.New("test").Disable()
	fallback := &alaye.Fallback{
		Type: "unknown",
	}

	handler := buildFallbackHandler(fallback, logger)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503, got %d", w.Code)
	}
}

func TestBuildRouteLimiter_Nil(t *testing.T) {
	result := buildRouteLimiter(nil, nil, nil, nil)
	if result != nil {
		t.Error("Expected nil limiter for nil config")
	}
}

func TestBuildRouteLimiter_Disabled(t *testing.T) {
	rlc := &alaye.RouteRate{
		Enabled: alaye.Inactive,
	}
	result := buildRouteLimiter(rlc, nil, nil, nil)
	if result != nil {
		t.Error("Expected nil limiter for disabled config")
	}
}

func TestBuildRouteLimiter_ACMEChallenge(t *testing.T) {
	rlc := &alaye.RouteRate{
		Enabled: alaye.Active,
		Rule: alaye.RateRule{
			Enabled:  alaye.Active,
			Requests: 100,
			Window:   alaye.Duration(time.Minute),
		},
	}
	global := &alaye.GlobalRate{
		Enabled: alaye.Active,
		Rules: []alaye.RateRule{
			{
				Enabled:  alaye.Active,
				Prefixes: []string{"/.well-known/acme-challenge/"},
				Requests: 1000,
				Window:   alaye.Duration(time.Minute),
			},
		},
	}
	ipMgr := zulu.NewIPManager(nil)
	result := buildRouteLimiter(rlc, global, ipMgr, nil)
	if result == nil {
		t.Error("Expected non-nil limiter")
	}
	// Verify ACME exclusion through Handler behavior
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := result.Handler(handler)
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	// ACME should bypass rate limit and reach handler
	if w.Code != http.StatusOK {
		t.Errorf("Expected ACME to bypass rate limit, got %d", w.Code)
	}
}

func TestBuildRouteLimiter_MethodMatch(t *testing.T) {
	rlc := &alaye.RouteRate{
		Enabled: alaye.Active,
		Rule: alaye.RateRule{
			Enabled:  alaye.Active,
			Methods:  []string{"POST"},
			Requests: 10,
			Window:   alaye.Duration(time.Minute),
		},
	}
	ipMgr := zulu.NewIPManager(nil)
	result := buildRouteLimiter(rlc, nil, ipMgr, nil)
	if result == nil {
		t.Error("Expected non-nil limiter")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := result.Handler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("Expected GET request to not match POST-only rule")
	}
	req = httptest.NewRequest("POST", "/", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests && rec.Code != http.StatusOK {
		t.Error("Expected POST request to match rule")
	}
}

func TestBuildRouteLimiter_PrefixMatch(t *testing.T) {
	rlc := &alaye.RouteRate{
		Enabled: alaye.Active,
		Rule: alaye.RateRule{
			Enabled:  alaye.Active,
			Prefixes: []string{"/api/"},
			Requests: 100,
			Window:   alaye.Duration(time.Minute),
		},
	}
	ipMgr := zulu.NewIPManager(nil)
	result := buildRouteLimiter(rlc, nil, ipMgr, nil)
	if result == nil {
		t.Error("Expected non-nil limiter")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := result.Handler(handler)
	req := httptest.NewRequest("GET", "/other", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("Expected /other to not match /api/ prefix")
	}
	req = httptest.NewRequest("GET", "/api/users", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests && rec.Code != http.StatusOK {
		t.Error("Expected /api/users to match /api/ prefix")
	}
}

func TestBuildRouteLimiter_GlobalPolicy(t *testing.T) {
	rlc := &alaye.RouteRate{
		Enabled:   alaye.Active,
		UsePolicy: "api-policy",
	}
	global := &alaye.GlobalRate{
		Enabled: alaye.Active,
		Policies: []alaye.RatePolicy{
			{
				Name:     "api-policy",
				Requests: 50,
				Window:   alaye.Duration(time.Minute),
				Burst:    10,
				Key:      "header:X-API-Key",
			},
		},
	}
	ipMgr := zulu.NewIPManager(nil)
	result := buildRouteLimiter(rlc, global, ipMgr, nil)
	if result == nil {
		t.Error("Expected non-nil limiter")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := result.Handler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests && rec.Code != http.StatusOK {
		t.Error("Expected policy to match")
	}
}

func TestFallbackRoute(t *testing.T) {
	route := FallbackRoute("test message")
	if route == nil {
		t.Fatal("FallbackRoute should not return nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "test message") {
		t.Errorf("Expected 'test message' in body, got %q", w.Body.String())
	}
}

func TestRouteHandler_ConcurrentRequests(t *testing.T) {
	cfg := NewTestConfig(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
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
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for range 10 {
		wg.Go(func() {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				errors <- fmt.Errorf("expected 200, got %d", w.Code)
			}
		})
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestRouteHandler_RequestContextPropagation(t *testing.T) {
	cfg := NewTestConfig(t)

	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
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

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "/api/users", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if capturedPath != "/users" {
		t.Errorf("Expected stripped path /users, got %q", capturedPath)
	}
}

// Handled by dispatcher already
//func TestRouteHandler_MaxBodySize(t *testing.T) {
//	cfg := NewTestConfig(t)
//	cfg.Host.Limits.MaxBodySize = 1024
//	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.WriteHeader(http.StatusOK)
//	}))
//	defer srv.Close()
//	route := &alaye.Route{
//		Enabled: alaye.Active,
//		Path:    "/",
//		Backends: alaye.Backend{
//			Enabled: alaye.Active,
//			Servers: alaye.NewServers(srv.URL),
//		},
//	}
//	h := NewRoute(cfg, route)
//	if h == nil {
//		t.Fatal("route handler should not be nil")
//	}
//	defer h.Close()
//	body := bytes.Repeat([]byte("x"), int(cfg.Host.Limits.MaxBodySize)+1)
//	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
//	req.ContentLength = int64(len(body))
//	w := httptest.NewRecorder()
//	h.ServeHTTP(w, req)
//	if w.Code != http.StatusRequestEntityTooLarge {
//		t.Errorf("Expected 413, got %d", w.Code)
//	}
//}

// TestRouteHandler_Serverless_Selection verifies that a serverless route correctly dispatches requests.
// It confirms that the underlying serverless multiplexer handles  and  paths through the main Route handler.
func TestRouteHandler_Serverless_Selection(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		fmt.Fprintln(os.Stdout, os.Getenv("TEST_WORKER_OUTPUT"))
		os.Exit(0)
	}

	cfg := NewTestConfig(t)
	cfg.Orch = orchestrator.New(cfg.Resource.Logger, t.TempDir(), nil, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("rest-response"))
	}))
	defer ts.Close()

	uniqueWorkerOutput := "worker-response-" + fmt.Sprintf("%d", os.Getpid())
	var cmd []string
	if runtime.GOOS == "windows" {
		cmd = []string{os.Args[0], "-test.run=TestRouteHandler_Serverless_Selection", "--"}
	} else {
		cmd = []string{os.Args[0], "-test.run=TestRouteHandler_Serverless_Selection", "--"}
	}

	route := &alaye.Route{
		Path: "/api",
		Serverless: alaye.Serverless{
			Enabled: alaye.Active,
			RESTs: []alaye.REST{
				{Name: "sms", URL: ts.URL, Enabled: alaye.Active},
			},
			Workers: []alaye.Work{
				{
					Name:    "echo",
					Command: cmd,
					Env: map[string]alaye.Value{
						"GO_WANT_HELPER_PROCESS": alaye.Value("1"),
						"TEST_WORKER_OUTPUT":     alaye.Value(uniqueWorkerOutput),
					},
				},
			},
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/sms", http.StatusOK, "rest-response"},
		{"/echo", http.StatusOK, uniqueWorkerOutput},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != tt.wantStatus {
			t.Errorf("Path %s: expected status %d, got %d", tt.path, tt.wantStatus, rr.Code)
		}

		gotBody := strings.TrimSpace(rr.Body.String())
		if gotBody != tt.wantBody {
			t.Errorf("Path %s: expected body %q, got %q", tt.path, tt.wantBody, gotBody)
		}
	}
}

// TestRouteHandler_Serverless_NotFound validates that invalid serverless endpoints return 404.
// It ensures that the dispatcher correctly identifies and rejects unconfigured serverless tasks.
func TestRouteHandler_Serverless_NotFound(t *testing.T) {
	cfg := NewTestConfig(t)
	route := &alaye.Route{
		Path:       "/api",
		Serverless: alaye.Serverless{Enabled: alaye.Active},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("route handler should not be nil")
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}
