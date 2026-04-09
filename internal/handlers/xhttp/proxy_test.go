package xhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/resource"
)

func TestProxy_Pick_ReturnsCorrectType(t *testing.T) {
	var backends []*Backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:   alaye.NewServer(server.URL),
		Route:    route,
		Domains:  []string{"example.com"},
		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	backends = append(backends, b1)

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, backends, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	picked := proxy.Pick(req)

	if picked == nil {
		t.Error("Pick should return a backend")
	}
	if picked != b1 {
		t.Error("Pick should return the correct backend instance")
	}
}

func TestProxy_Pick_NoHealthyBackends(t *testing.T) {
	var backends []*Backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	b1.Status(false)
	backends = append(backends, b1)

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, backends, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	picked := proxy.Pick(req)

	if picked != nil {
		t.Error("Pick should return nil when no healthy backends")
	}
}

func TestProxy_ServeHTTP_NoHealthyBackends(t *testing.T) {
	var backends []*Backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	b1.Status(false)
	backends = append(backends, b1)

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, backends, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 Bad Gateway, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_NoHealthyBackends_WithFallback(t *testing.T) {
	var backends []*Backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	fallbackHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("fallback"))
	})
	fallback := httptest.NewServer(fallbackHandler)
	defer fallback.Close()
	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}
	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()
	b1.Status(false)
	backends = append(backends, b1)
	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
		Fallback: fallbackHandler,
	}
	proxy := NewProxy(proxyCfg, backends, zulu.NewIPManager(nil))
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 from fallback, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_WebSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("Expected Upgrade: websocket header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{b1}, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  10 * time.Millisecond,
	}
	proxy := NewProxy(proxyCfg, []*Backend{b1}, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusGatewayTimeout && w.Code != http.StatusOK {
		t.Errorf("Expected timeout or success, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Adaptive(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server1.URL, server2.URL),
		},
	}

	cfg1 := ConfigBackend{
		Server:  alaye.NewServer(server1.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	cfg2 := ConfigBackend{
		Server:  alaye.NewServer(server2.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b2, err := NewBackend(cfg2)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b2.Stop()

	proxyCfg := ConfigProxy{
		Strategy: "adaptive",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{b1, b2}, zulu.NewIPManager(nil))

	for range 10 {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, req)
	}

	time.Sleep(50 * time.Millisecond)

	fasterPicked := 0
	for range 10 {
		picked := proxy.Pick(httptest.NewRequest("GET", "/", nil))
		if picked == b1 {
			fasterPicked++
		}
	}

	if fasterPicked < 5 {
		t.Errorf("Expected adaptive LB to prefer faster backend, got %d/10", fasterPicked)
	}
}

func TestProxy_ServeHTTP_Sticky(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	proxyCfg := ConfigProxy{
		Strategy: "sticky",
		Keys:     []string{"cookie:session_id"},
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{b1}, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestProxy_Update(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server1.URL),
		},
	}

	cfg1 := ConfigBackend{
		Server:  alaye.NewServer(server1.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg1)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	cfg2 := ConfigBackend{
		Server:  alaye.NewServer(server2.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b2, err := NewBackend(cfg2)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b2.Stop()

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{b1}, zulu.NewIPManager(nil))

	proxy.Update([]*Backend{b1, b2})

	req := httptest.NewRequest("GET", "/", nil)
	picked := proxy.Pick(req)
	if picked == nil {
		t.Error("Pick should return a backend after update")
	}
}

func TestProxy_Stop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Server:  alaye.NewServer(server.URL),
		Route:   route,
		Domains: []string{"example.com"},

		Resource: resource.New(),
	}
	b1, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{b1}, zulu.NewIPManager(nil))

	proxy.Stop()

	picked := proxy.Pick(httptest.NewRequest("GET", "/", nil))
	if picked != nil {
		t.Error("Pick should return nil after Stop()")
	}
}

func TestProxy_NilBackend(t *testing.T) {
	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{nil}, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	picked := proxy.Pick(req)

	if picked != nil {
		t.Error("Pick should return nil for nil backend")
	}
}

func TestProxy_EmptyBackends(t *testing.T) {
	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}
	proxy := NewProxy(proxyCfg, []*Backend{}, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	picked := proxy.Pick(req)

	if picked != nil {
		t.Error("Pick should return nil for empty backends")
	}
}
