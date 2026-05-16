package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/tunnel"
)

// setupBackend — shared helper used by both backend_tunnel_test.go and
// backend_cgi_test.go (which references it via the same package).

// Minimal in-process SOCKS5 proxy for testing

// startSOCKS5Server starts a minimal SOCKS5 proxy on a random loopback port.
// It counts every accepted connection and forwards the TCP stream transparently.
// The returned count increments each time a client connects to the proxy,
// which is the observable signal that traffic routed through it.
func startSOCKS5Server(t *testing.T) (addr string, connCount *atomic.Int64) {
	t.Helper()
	count := &atomic.Int64{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go handleSOCKS5Conn(client)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), count
}

// handleSOCKS5Conn implements SOCKS5 no-auth + CONNECT sufficient for testing.
func handleSOCKS5Conn(client net.Conn) {
	defer client.Close()

	// Greeting
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil || buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(client, make([]byte, nMethods)); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request header
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 { // VER=5, CMD=CONNECT
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetAddr string
	switch hdr[3] {
	case 0x01: // IPv4
		raw := make([]byte, 6)
		io.ReadFull(client, raw)
		targetAddr = net.JoinHostPort(net.IP(raw[:4]).String(), socks5Port(raw[4:6]))
	case 0x03: // domain
		nb := make([]byte, 1)
		io.ReadFull(client, nb)
		domain := make([]byte, nb[0])
		io.ReadFull(client, domain)
		port := make([]byte, 2)
		io.ReadFull(client, port)
		targetAddr = net.JoinHostPort(string(domain), socks5Port(port))
	case 0x04: // IPv6
		raw := make([]byte, 18)
		io.ReadFull(client, raw)
		targetAddr = net.JoinHostPort(net.IP(raw[:16]).String(), socks5Port(raw[16:18]))
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	upstream, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()

	// Success
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

func socks5Port(b []byte) string {
	n := int(b[0])<<8 | int(b[1])
	s := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestTunnelPool_New_ValidConfig(t *testing.T) {
	pool, err := tunnel.New(tunnel.Config{
		Name:    "tor",
		Servers: []string{"127.0.0.1:9050"},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if pool.Len() != 1 {
		t.Errorf("Len() = %d, want 1", pool.Len())
	}
	if pool.Name() != "tor" {
		t.Errorf("Name() = %q, want %q", pool.Name(), "tor")
	}
}

func TestTunnelPool_New_MultipleServers(t *testing.T) {
	pool, err := tunnel.New(tunnel.Config{
		Name:    "pool",
		Servers: []string{"127.0.0.1:9050", "127.0.0.1:9051", "127.0.0.1:9052"},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if pool.Len() != 3 {
		t.Errorf("Len() = %d, want 3", pool.Len())
	}
}

func TestTunnelPool_New_EmptyServers(t *testing.T) {
	_, err := tunnel.New(tunnel.Config{Name: "empty"})
	if err == nil {
		t.Fatal("expected error for empty Servers, got nil")
	}
}

func TestTunnelPool_New_WithAuth_CredentialsNotLeaked(t *testing.T) {
	pool, err := tunnel.New(tunnel.Config{
		Name:     "vpn",
		Servers:  []string{"vpn.example.com:1080"},
		Username: "myuser",
		Password: "supersecret",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	for _, addr := range pool.Addrs() {
		if containsStr(addr, "supersecret") {
			t.Errorf("Addrs() leaked password in %q", addr)
		}
		if !containsStr(addr, "myuser@") {
			t.Errorf("Addrs() should contain username in %q", addr)
		}
	}
}

func TestTunnelPool_NewFromURL_Valid(t *testing.T) {
	cases := []string{
		"socks5://127.0.0.1:9050",
		"socks5://user:pass@proxy.example.com:1080",
		"socks5://127.0.0.1:9051",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			pool, err := tunnel.NewFromURL(u)
			if err != nil {
				t.Fatalf("NewFromURL(%q): %v", u, err)
			}
			if pool.Len() != 1 {
				t.Errorf("Len() = %d, want 1", pool.Len())
			}
		})
	}
}

func TestTunnelPool_NewFromURL_WrongScheme(t *testing.T) {
	_, err := tunnel.NewFromURL("http://127.0.0.1:9050")
	if err == nil {
		t.Fatal("expected error for http:// scheme, got nil")
	}
}

func TestTunnelPool_NewFromURL_Malformed(t *testing.T) {
	_, err := tunnel.NewFromURL("://bad-url")
	if err == nil {
		t.Fatal("expected error for malformed URL, got nil")
	}
}

func TestTunnelPool_WrapTransport_SetsNilProxy(t *testing.T) {
	pool, _ := tunnel.New(tunnel.Config{Servers: []string{"127.0.0.1:9050"}})
	base := &http.Transport{MaxIdleConns: 99}
	wrapped := pool.WrapTransport(base)

	if wrapped == base {
		t.Error("WrapTransport must return a clone, not the original")
	}
	if wrapped.Proxy != nil {
		t.Error("WrapTransport must set Proxy = nil")
	}
	if wrapped.DialContext == nil {
		t.Error("WrapTransport must install DialContext")
	}
}

func TestTunnelPool_WrapTransport_PreservesSettings(t *testing.T) {
	pool, _ := tunnel.New(tunnel.Config{Servers: []string{"127.0.0.1:9050"}})
	base := &http.Transport{
		MaxIdleConns:    42,
		IdleConnTimeout: 30 * time.Second,
	}
	wrapped := pool.WrapTransport(base)

	if wrapped.MaxIdleConns != 42 {
		t.Errorf("MaxIdleConns: got %d, want 42", wrapped.MaxIdleConns)
	}
	if wrapped.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout: got %v, want 30s", wrapped.IdleConnTimeout)
	}
}

func TestTunnelPool_RoundRobin_DistributesAcrossAll(t *testing.T) {
	// Three SOCKS5 servers; round-robin must visit all three.
	addrs := make([]string, 3)
	counts := make([]*atomic.Int64, 3)
	for i := range 3 {
		addr, count := startSOCKS5Server(t)
		addrs[i] = addr
		counts[i] = count
	}

	pool, err := tunnel.New(tunnel.Config{
		Servers:  addrs,
		Strategy: "round_robin",
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	// 9 dials, 3 per server expected. Dial will fail after SOCKS5 handshake
	// (no real backend), but the proxy accepts the TCP connection first.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 9 {
		conn, err := pool.DialContext(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			conn.Close()
		}
	}

	for i, c := range counts {
		if c.Load() == 0 {
			t.Errorf("server[%d] received 0 connections — round-robin not distributing", i)
		}
	}
}

func TestTunnelPool_Random_AllServersReachable(t *testing.T) {
	addrs := make([]string, 3)
	counts := make([]*atomic.Int64, 3)
	for i := range 3 {
		addr, count := startSOCKS5Server(t)
		addrs[i] = addr
		counts[i] = count
	}

	pool, err := tunnel.New(tunnel.Config{
		Servers:  addrs,
		Strategy: "random",
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 30 {
		conn, err := pool.DialContext(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			conn.Close()
		}
	}

	for i, c := range counts {
		if c.Load() == 0 {
			t.Errorf("server[%d] received 0 connections in 30 random dials", i)
		}
	}
}

func TestTunnelPool_SingleServer_AllDialsToSameServer(t *testing.T) {
	addr, count := startSOCKS5Server(t)
	pool, _ := tunnel.New(tunnel.Config{Servers: []string{addr}})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for range 5 {
		conn, err := pool.DialContext(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			conn.Close()
		}
	}

	if count.Load() == 0 {
		t.Error("single-server pool: SOCKS5 server received 0 connections")
	}
}

func TestNewBackend_WithTunnelPool_TrafficRoutedThroughProxy(t *testing.T) {
	// Verify end-to-end: request → xhttp.Backend → SOCKS5 → backend server.
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("tunnel-ok"))
	}))
	defer backendSrv.Close()

	socks5Addr, connCount := startSOCKS5Server(t)

	pool, err := tunnel.New(tunnel.Config{
		Name:    "test",
		Servers: []string{socks5Addr},
	})
	if err != nil {
		t.Fatalf("tunnel.New: %v", err)
	}

	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:     alaye.NewServer(backendSrv.URL),
		Route:      &alaye.Route{Path: "/"},
		Domains:    []string{"example.com"},
		Resource:   res,
		TunnelPool: pool,
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Stop()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)

	if connCount.Load() == 0 {
		t.Error("request did not route through SOCKS5 tunnel — WrapTransport not applied")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 through tunnel, got %d", w.Code)
	}
	if w.Body.String() != "tunnel-ok" {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestNewBackend_WithoutTunnelPool_DirectConnection(t *testing.T) {
	// A nil TunnelPool must not use any proxy.
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendSrv.Close()

	_, connCount := startSOCKS5Server(t) // running but not wired in

	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:     alaye.NewServer(backendSrv.URL),
		Route:      &alaye.Route{Path: "/"},
		Domains:    []string{"example.com"},
		Resource:   res,
		TunnelPool: nil,
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Stop()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)

	if connCount.Load() != 0 {
		t.Errorf("nil TunnelPool still routed %d connections through SOCKS5", connCount.Load())
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for direct connection, got %d", w.Code)
	}
}

func TestNewBackend_NilTunnelPool_NoPanic(t *testing.T) {
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendSrv.Close()

	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:     alaye.NewServer(backendSrv.URL),
		Route:      &alaye.Route{Path: "/"},
		Resource:   res,
		TunnelPool: nil,
	})
	if err != nil {
		t.Fatalf("NewBackend with nil TunnelPool: %v", err)
	}
	b.Stop()
}

// DialContext — context cancellation

func TestTunnelPool_DialContext_RespectsDeadline(t *testing.T) {
	// Point at a port that never responds — context timeout must fire.
	pool, err := tunnel.New(tunnel.Config{
		Servers: []string{"127.0.0.1:1"}, // always connection-refused
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = pool.DialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected error when SOCKS5 proxy is unreachable, got nil")
	}
}

// Helpers

func containsStr(s, sub string) bool {
	if len(sub) == 0 || len(sub) > len(s) {
		return false
	}
	for i := range len(s) - len(sub) + 1 {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
