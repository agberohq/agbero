package agbero

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("test")
)

func TestNewServer_Basic(t *testing.T) {
	s := NewServer()
	if s.servers == nil || s.h3Servers == nil {
		t.Error("Maps not initialized")
	}
}

func TestServer_Start_NoConfig(t *testing.T) {
	s := NewServer()
	err := s.Start(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "host manager is required") {
		t.Errorf("Expected host manager error, got %v", err)
	}
}

func TestServer_Start_NoGlobalConfig(t *testing.T) {
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := NewServer(WithHostManager(hm))
	err := s.Start(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "global config is required") {
		t.Errorf("Expected global config error, got %v", err)
	}
}

func TestServer_Start_Minimal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	global := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":0"}},
		Storage: alaye.Storage{
			HostsDir: "./hosts",
		},
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(testLogger),
	)

	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.hcl")

	err := s.Start(ctx, configPath)
	// The server will start and then be stopped by context timeout
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestServer_buildTLS(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		global: &alaye.Global{
			LetsEncrypt: alaye.LetsEncrypt{
				Email: "test@example.com",
			},
			Storage: alaye.Storage{
				CertsDir: tmpDir,
			},
		},

		logger:      testLogger,
		hostManager: discovery.NewHost("", discovery.WithLogger(nil)),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	cfg, handler, err := s.buildTLS(next)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cfg == nil {
		t.Error("TLS config not created")
	}
	if handler == nil {
		t.Error("Handler not created")
	}
}

func TestServer_buildTLS_NoEmail(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		global: &alaye.Global{
			Storage: alaye.Storage{
				HostsDir: tmpDir,
			},
		},
		logger:      testLogger,
		hostManager: discovery.NewHost("", discovery.WithLogger(nil)),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	cfg, handler, err := s.buildTLS(next)
	if err != nil {
		t.Errorf("Should handle missing email gracefully, got error: %v", err)
	}
	if handler == nil {
		t.Error("Handler should still be created")
	}
	_ = cfg
}

func TestServer_buildRateLimiterFromConfig(t *testing.T) {
	s := &Server{global: &alaye.Global{
		RateLimits: alaye.Rate{
			Enabled:    true,
			TTL:        time.Minute,
			MaxEntries: 100,
			// Global:     alaye.RatePolicy{Requests: 10, Window: time.Second},
			Rules: []alaye.RateRule{
				{
					Name:     "test_rule",
					Requests: 10,
					Window:   time.Second,
					Burst:    20,
					Key:      "ip",
					Prefixes: []string{"/test"},
					Methods:  []string{"GET"},
				},
			},
		},
	}}

	rl := s.buildRateLimiterFromConfig()
	if rl == nil {
		t.Error("RateLimiter not created")
	}
}

func TestServer_getOrBuildRouteHandler_CacheHit(t *testing.T) {
	s := &Server{logger: testLogger}
	route := &alaye.Route{Path: "/test", Backends: alaye.MakeBackend("http://localhost:8080")}
	key := route.Key()

	handler := handlers.NewRoute(route, testLogger)
	item := &woos.RouteCacheItem{
		Handler: handler,
	}
	item.LastAccessed.Store(time.Now().UnixNano())
	woos.RouteCache.Store(key, item)

	h := s.getOrBuildRouteHandler(route)
	if h != handler {
		t.Error("Cache miss unexpectedly")
	}

	handler.Close()
	woos.RouteCache.Delete(key)
}

func TestServer_getOrBuildRouteHandler_CacheMiss(t *testing.T) {
	s := &Server{logger: testLogger}
	route := &alaye.Route{
		Path:     "/test",
		Backends: alaye.MakeBackend("http://localhost:8080"),
	}

	woos.RouteCache.Delete(route.Key())

	h := s.getOrBuildRouteHandler(route)
	if h == nil {
		t.Error("Handler should be created on cache miss")
	}

	h.Close()
	woos.RouteCache.Delete(route.Key())
}

func TestServer_reapOldRoutes(t *testing.T) {
	s := &Server{logger: testLogger}
	key := "test-route-key"

	route := &alaye.Route{
		Path:     "/test",
		Backends: alaye.MakeBackend("http://localhost:8080"),
	}
	handler := handlers.NewRoute(route, testLogger)

	item := &woos.RouteCacheItem{
		Handler: handler,
	}
	item.LastAccessed.Store(time.Now().Add(-11 * time.Minute).UnixNano())
	woos.RouteCache.Store(key, item)

	s.reapOldRoutes()

	if _, ok := woos.RouteCache.Load(key); ok {
		t.Error("Old route not reaped")
	}
}

func TestServer_reapOldRoutes_Recent(t *testing.T) {
	s := &Server{logger: testLogger}
	key := "test-route-key-recent"

	route := &alaye.Route{
		Path:     "/test",
		Backends: alaye.MakeBackend("http://localhost:8080"),
	}
	handler := handlers.NewRoute(route, testLogger)

	item := &woos.RouteCacheItem{
		Handler: handler,
	}
	item.LastAccessed.Store(time.Now().UnixNano())
	woos.RouteCache.Store(key, item)

	s.reapOldRoutes()

	if _, ok := woos.RouteCache.Load(key); !ok {
		t.Error("Recent route should not be reaped")
	}

	handler.Close()
	woos.RouteCache.Delete(key)
}

func TestServer_StartAdminServer(t *testing.T) {
	// Corrected: Use Admin struct, not Metrics string
	global := &alaye.Global{
		Admin: &alaye.Admin{
			Address: ":0",
		},
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: hm,
	}

	// This starts a goroutine, we'll just verify it doesn't panic
	// Corrected: calling startAdminServer, not startMetricsServer
	s.startAdminServer()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
}

func TestServer_StartAdminServer_NoConfig(t *testing.T) {
	global := &alaye.Global{
		Admin: nil,
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: hm,
	}

	// Should not panic when no admin config
	s.startAdminServer()
}

func TestServer_HandleRequest_NoHost(t *testing.T) {
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		hostManager: hm,
		logger:      testLogger,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.com"
	w := httptest.NewRecorder()

	s.handleRequest(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for unknown host, got %d", w.Code)
	}
}

func TestServer_HandleRequest_WithHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	hm := discovery.NewHost("", discovery.WithLogger(testLogger))

	hm.UpdateGossipNode("test", "example.com", alaye.Route{
		Path:     "/",
		Backends: alaye.MakeBackend(backend.URL),
	})

	s := &Server{
		hostManager: hm,
		logger:      testLogger,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	s.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Body.String() != "backend response" {
		t.Errorf("Expected 'backend response', got %q", w.Body.String())
	}
}
