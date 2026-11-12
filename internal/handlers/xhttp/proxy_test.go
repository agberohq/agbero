package xhttp

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestProxy_WebSocketEndToEndUpgrade(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_ = rw.Flush()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err == nil {
			_, _ = conn.Write([]byte("pong"))
		}
	}))
	defer backend.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(backend.URL),
		},
	}
	res := resource.New()
	defer res.Close()
	be, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(backend.URL),
		Route:    route,
		Domains:  []string{"ws.localhost"},
		Resource: res,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Stop()
	proxy := NewProxy(ConfigProxy{Strategy: "round_robin"}, []*Backend{be}, zulu.NewIPManager(nil))
	front := httptest.NewServer(proxy)
	defer front.Close()

	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: ws.localhost\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status = %q, want 101", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 4)
	if _, err := br.Read(pong); err != nil {
		t.Fatal(err)
	}
	if string(pong) != "pong" {
		t.Fatalf("tunneled bytes = %q, want pong", pong)
	}

	// A WebSocket tunnel is one HTTP upgrade, not one request per message.
	// The proxied messages are opaque bytes after the 101 response.
	_ = conn.Close()
	deadline := time.Now().Add(time.Second)
	for be.Activity.Requests.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := be.Activity.Requests.Load(); got != 1 {
		t.Fatalf("websocket handshake count = %d, want 1", got)
	}
	webDeadline := time.Now().Add(time.Second)
	for be.Activity.WebSockets.Load() != 0 && time.Now().Before(webDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := be.Activity.WebSockets.Load(); got != 0 {
		t.Fatalf("websocket active connections after close = %d, want 0", got)
	}
	if be.Activity.BytesIn.Load() == 0 || be.Activity.BytesOut.Load() == 0 {
		t.Fatalf("websocket tunnel bytes not counted: in=%d out=%d",
			be.Activity.BytesIn.Load(), be.Activity.BytesOut.Load())
	}
	if p99 := be.Activity.Latency.Snapshot().P99; p99 > 2_000_000 {
		t.Fatalf("websocket handshake latency polluted p99: %d us", p99)
	}
}
