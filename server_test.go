// server_test.go
package agbero

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	tls2 "git.imaxinacion.net/aibox/agbero/internal/core/tls"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	handlers2 "git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/ll"
	"github.com/quic-go/quic-go/http3"
)

func TestNewServer_Basic(t *testing.T) {
	s := NewServer()
	if s.servers == nil || s.h3Servers == nil {
		t.Error("Maps not initialized")
	}
}

func TestServer_Start_NoConfig(t *testing.T) {
	s := NewServer()
	err := s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "global config is required") {
		t.Errorf("Expected config error, got %v", err)
	}
}

func TestServer_Start_Minimal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	global := &woos.GlobalConfig{
		Bind: woos.BindConfig{HTTP: []string{":0"}},
	}
	hm := discovery.NewHost("", discovery.WithLogger(ll.New("test").Enable()))
	s := NewServer(WithGlobalConfig(global), WithHostManager(hm), WithLogger(ll.New("test").Enable()))

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := s.Start(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestServer_Shutdown(t *testing.T) {
	s := &Server{
		servers:   make(map[string]*http.Server),
		h3Servers: make(map[string]*http3.Server),
		logger:    ll.New("test").Enable(),
		tlsManager: &tls2.TlsManager{ // Mock
			Watchers: map[string]*fsnotify.Watcher{"test": fsnotify.NewWatcher()},
		},
		rateLimiter: ratelimit.NewRateLimiter(time.Minute, 100, nil),
	}

	// Mock TCP server
	s.servers["http@:80"] = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}

	// Mock H3
	s.h3Servers["h3@:443"] = &http3.Server{}

	err := s.Shutdown()
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
	if len(s.tlsManager.Watchers) != 0 {
		t.Error("Watchers not closed")
	}
}

func TestServer_buildTLS(t *testing.T) {
	s := &Server{
		global: &woos.GlobalConfig{
			LEEmail:       "test@example.com",
			TLSStorageDir: t.TempDir(),
		},
		logger:      ll.New("test").Enable(),
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

func TestServer_buildRateLimiterFromConfig(t *testing.T) {
	s := &Server{global: &woos.GlobalConfig{
		RateLimits: woos.RateLimitConfig{
			TTL:        time.Minute,
			MaxEntries: 100,
			Global:     woos.RatePolicyConfig{Requests: 10, Window: time.Second},
		},
	}}

	rl := s.buildRateLimiterFromConfig()
	if rl == nil {
		t.Error("RateLimiter not created")
	}
	if rl.Ttl() != time.Minute {
		t.Error("TTL not set")
	}
}

func TestServer_getOrBuildRouteHandler_CacheHit(t *testing.T) {
	s := &Server{logger: ll.New("test").Enable()}
	route := &woos.Route{Path: "/test"}
	key := route.Key()

	// Mock cache
	mockHandler := &handlers2.RouteHandler{}
	woos.RouteCache.Store(key, &woos.RouteCacheItem{Handler: mockHandler})

	h := s.getOrBuildRouteHandler(route)
	if h != mockHandler {
		t.Error("Cache miss unexpectedly")
	}
}

func TestServer_reapOldRoutes(t *testing.T) {
	s := &Server{}
	key := "test"
	oldItem := &woos.RouteCacheItem{
		Handler: &handlers2.RouteHandler{}, // Mock with Close()
	}
	oldItem.LastAccessed.Store(time.Now().Add(-11 * time.Minute).UnixNano())
	woos.RouteCache.Store(key, oldItem)

	s.reapOldRoutes()

	if _, ok := woos.RouteCache.Load(key); ok {
		t.Error("Old route not reaped")
	}
}
