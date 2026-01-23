// server_test.go
package agbero

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tls2 "git.imaxinacion.net/aibox/agbero/internal/core/tls"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/ll"
	"github.com/quic-go/quic-go/http3"
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
		Bind:     alaye.Bind{HTTP: []string{":0"}},
		HostsDir: "./hosts",
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
	// Accept context timeout error
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestServer_ShutdownImpl(t *testing.T) {
	s := &Server{
		servers:   make(map[string]*http.Server),
		h3Servers: make(map[string]*http3.Server),
		logger:    testLogger,
		tlsManager: &tls2.TlsManager{ // Mock
			Watchers: make(map[string]*fsnotify.Watcher),
		},
		rateLimiter: ratelimit.NewRateLimiter(time.Minute, 100, nil),
	}

	// Create a real watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("Could not create watcher: %v", err)
	}
	s.tlsManager.Watchers["test"] = watcher

	// Mock TCP server
	srv := &http.Server{
		Addr:    ":0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	s.servers["http@:80"] = srv

	err = s.shutdownImpl()
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
	if len(s.tlsManager.Watchers) != 0 {
		t.Error("Watchers not closed")
	}
}

func TestServer_buildTLS(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		global: &alaye.Global{
			LEEmail:       "test@example.com",
			TLSStorageDir: tmpDir,
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
			TLSStorageDir: tmpDir,
		},
		logger:      testLogger,
		hostManager: discovery.NewHost("", discovery.WithLogger(nil)),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	cfg, handler, err := s.buildTLS(next)
	// Should still work, just with warning
	if err != nil {
		t.Errorf("Should handle missing email gracefully, got error: %v", err)
	}
	if handler == nil {
		t.Error("Handler should still be created")
	}
	// cfg might be nil when email is missing, that's OK
	_ = cfg // Mark as used
}

func TestServer_buildRateLimiterFromConfig(t *testing.T) {
	s := &Server{global: &alaye.Global{
		RateLimits: alaye.Rate{
			TTL:        time.Minute,
			MaxEntries: 100,
			Global:     alaye.RatePolicy{Requests: 10, Window: time.Second},
		},
	}}

	rl := s.buildRateLimiterFromConfig()
	if rl == nil {
		t.Error("RateLimiter not created")
	}
}

func TestServer_getOrBuildRouteHandler_CacheHit(t *testing.T) {
	s := &Server{logger: testLogger}
	route := &alaye.Route{Path: "/test", Backends: []string{"http://localhost:8080"}}
	key := route.Key()

	// Create a real handler to store in cache
	handler := handlers.NewRouteHandler(route, testLogger)
	item := &woos.RouteCacheItem{
		Handler: handler,
	}
	item.LastAccessed.Store(time.Now().UnixNano())
	woos.RouteCache.Store(key, item)

	h := s.getOrBuildRouteHandler(route)
	if h != handler {
		t.Error("Cache miss unexpectedly")
	}

	// Clean up
	handler.Close()
	woos.RouteCache.Delete(key)
}

func TestServer_getOrBuildRouteHandler_CacheMiss(t *testing.T) {
	s := &Server{logger: testLogger}
	route := &alaye.Route{
		Path:     "/test",
		Backends: []string{"http://localhost:8080"},
	}

	// Ensure cache is empty
	woos.RouteCache.Delete(route.Key())

	h := s.getOrBuildRouteHandler(route)
	if h == nil {
		t.Error("Handler should be created on cache miss")
	}

	// Clean up
	h.Close()
	woos.RouteCache.Delete(route.Key())
}

func TestServer_reapOldRoutes(t *testing.T) {
	s := &Server{logger: testLogger}
	key := "test-route-key"

	// Create a handler with Close method
	route := &alaye.Route{
		Path:     "/test",
		Backends: []string{"http://localhost:8080"},
	}
	handler := handlers.NewRouteHandler(route, testLogger)

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

	// Create a handler with Close method
	route := &alaye.Route{
		Path:     "/test",
		Backends: []string{"http://localhost:8080"},
	}
	handler := handlers.NewRouteHandler(route, testLogger)

	item := &woos.RouteCacheItem{
		Handler: handler,
	}
	item.LastAccessed.Store(time.Now().UnixNano()) // Recent access
	woos.RouteCache.Store(key, item)

	s.reapOldRoutes()

	if _, ok := woos.RouteCache.Load(key); !ok {
		t.Error("Recent route should not be reaped")
	}

	// Clean up
	handler.Close()
	woos.RouteCache.Delete(key)
}

func TestServer_StartMetricsServer(t *testing.T) {
	// Use a random port
	global := &alaye.Global{
		Bind: alaye.Bind{Metrics: ":0"},
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: hm,
	}

	// This starts a goroutine, we'll just verify it doesn't panic
	s.startMetricsServer()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
}

func TestServer_StartMetricsServer_NoPort(t *testing.T) {
	global := &alaye.Global{}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: hm,
	}

	// Should not panic when no metrics port
	s.startMetricsServer()
}

func TestServer_LogRequest(t *testing.T) {
	s := &Server{logger: testLogger}

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Host = "example.com"
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "test-agent")

	// This just logs, no assertions needed
	s.logRequest("example.com", req, time.Now())
}

func TestServer_HandleRequest_NoHost(t *testing.T) {
	// Create a minimal server for testing
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
	// Create a test server to proxy to
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create a minimal server for testing
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))

	// Add a test host with a route to our test backend
	hm.UpdateGossipNode("test", "example.com", alaye.Route{
		Path:     "/",
		Backends: []string{backend.URL},
	})

	s := &Server{
		hostManager: hm,
		logger:      testLogger,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	s.handleRequest(w, req)

	// Should proxy successfully to test backend
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Body.String() != "backend response" {
		t.Errorf("Expected 'backend response', got %q", w.Body.String())
	}
}
