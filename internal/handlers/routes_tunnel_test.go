package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/tunnel"
	"github.com/olekukonko/ll"
)

func TestTunnel_Validate_Valid(t *testing.T) {
	cases := []struct {
		name string
		t    alaye.Tunnel
	}{
		{
			name: "minimal",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "socks5",
				Servers:  []string{"127.0.0.1:9050"},
			},
		},
		{
			name: "round_robin strategy",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "pool",
				Protocol: "socks5",
				Servers:  []string{"127.0.0.1:9050", "127.0.0.1:9051"},
				Strategy: "round_robin",
			},
		},
		{
			name: "random strategy",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "rand",
				Protocol: "socks5",
				Servers:  []string{"proxy.example.com:1080"},
				Strategy: "random",
			},
		},
		{
			name: "with credentials",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "vpn",
				Protocol: "socks5",
				Servers:  []string{"vpn.example.com:1080"},
				Username: "user",
				Password: "pass",
			},
		},
		{
			name: "disabled skips validation",
			t: alaye.Tunnel{
				Enabled:  expect.Inactive,
				Name:     "",  // would normally fail
				Protocol: "",  // would normally fail
				Servers:  nil, // would normally fail
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.t.Validate(); err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestTunnel_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		t    alaye.Tunnel
	}{
		{
			name: "missing name",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Protocol: "socks5",
				Servers:  []string{"127.0.0.1:9050"},
			},
		},
		{
			name: "missing protocol",
			t: alaye.Tunnel{
				Enabled: expect.Active,
				Name:    "tor",
				Servers: []string{"127.0.0.1:9050"},
			},
		},
		{
			name: "unsupported protocol",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "http",
				Servers:  []string{"127.0.0.1:9050"},
			},
		},
		{
			name: "no servers",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "socks5",
			},
		},
		{
			name: "invalid server address — no port",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "socks5",
				Servers:  []string{"127.0.0.1"},
			},
		},
		{
			name: "invalid server address — empty host",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "socks5",
				Servers:  []string{":9050"},
			},
		},
		{
			name: "unsupported strategy",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "socks5",
				Servers:  []string{"127.0.0.1:9050"},
				Strategy: "least_conn", // valid LB strategy but not for tunnels
			},
		},
		{
			name: "negative timeout",
			t: alaye.Tunnel{
				Enabled:  expect.Active,
				Name:     "tor",
				Protocol: "socks5",
				Servers:  []string{"127.0.0.1:9050"},
				Timeout:  -1,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.t.Validate(); err == nil {
				t.Errorf("Validate() expected error, got nil")
			}
		})
	}
}

func TestTunnel_IsZero(t *testing.T) {
	zero := alaye.Tunnel{}
	if !zero.IsZero() {
		t.Error("empty Tunnel.IsZero() should return true")
	}

	nonZero := alaye.Tunnel{Name: "tor"}
	if nonZero.IsZero() {
		t.Error("Tunnel with Name set IsZero() should return false")
	}
}

func TestTunnel_DisplayAddr_SingleServer(t *testing.T) {
	tun := alaye.Tunnel{
		Servers: []string{"127.0.0.1:9050"},
	}
	addr := tun.DisplayAddr()
	if addr != "socks5://127.0.0.1:9050" {
		t.Errorf("DisplayAddr() = %q, want socks5://127.0.0.1:9050", addr)
	}
}

func TestTunnel_DisplayAddr_WithUsername(t *testing.T) {
	tun := alaye.Tunnel{
		Servers:  []string{"proxy.example.com:1080"},
		Username: "myuser",
		Password: "secret",
	}
	addr := tun.DisplayAddr()
	if addr != "socks5://myuser@proxy.example.com:1080" {
		t.Errorf("DisplayAddr() = %q", addr)
	}
	// Password must never appear
	for _, tok := range []string{"secret"} {
		if containsTunnelStr(addr, tok) {
			t.Errorf("DisplayAddr() leaked credential %q in %q", tok, addr)
		}
	}
}

func TestTunnel_DisplayAddr_MultiServer(t *testing.T) {
	tun := alaye.Tunnel{
		Servers:  []string{"127.0.0.1:9050", "127.0.0.1:9051"},
		Strategy: "round_robin",
	}
	addr := tun.DisplayAddr()
	if !containsTunnelStr(addr, "2 servers") {
		t.Errorf("DisplayAddr() multi should mention server count, got %q", addr)
	}
}

func TestGlobal_Validate_TunnelDuplicateName(t *testing.T) {
	g := minimalGlobal()
	g.Tunnels = []alaye.Tunnel{
		{Enabled: expect.Active, Name: "tor", Protocol: "socks5", Servers: []string{"127.0.0.1:9050"}},
		{Enabled: expect.Active, Name: "tor", Protocol: "socks5", Servers: []string{"127.0.0.1:9051"}},
	}
	if err := g.Validate(); err == nil {
		t.Error("expected error for duplicate tunnel name, got nil")
	}
}

func TestGlobal_Validate_TunnelUnique(t *testing.T) {
	g := minimalGlobal()
	g.Tunnels = []alaye.Tunnel{
		{Enabled: expect.Active, Name: "tor", Protocol: "socks5", Servers: []string{"127.0.0.1:9050"}},
		{Enabled: expect.Active, Name: "vpn", Protocol: "socks5", Servers: []string{"vpn.example.com:1080"}},
	}
	if err := g.Validate(); err != nil {
		t.Errorf("Validate() unexpected error for distinct tunnel names: %v", err)
	}
}

func TestGlobal_Validate_DisabledTunnelNotValidated(t *testing.T) {
	g := minimalGlobal()
	g.Tunnels = []alaye.Tunnel{
		// Disabled — missing required fields, but Validate skips them
		{Enabled: expect.Inactive, Name: "", Protocol: "", Servers: nil},
	}
	if err := g.Validate(); err != nil {
		t.Errorf("Validate() should skip disabled tunnels, got: %v", err)
	}
}

func TestGlobal_Validate_NoTunnels(t *testing.T) {
	g := minimalGlobal()
	g.Tunnels = nil
	if err := g.Validate(); err != nil {
		t.Errorf("Validate() should pass with no tunnels: %v", err)
	}
}

func TestBackend_HasTunnel(t *testing.T) {
	cases := []struct {
		name string
		b    alaye.Backend
		want bool
	}{
		{"no tunnel", alaye.Backend{}, false},
		{"via set", alaye.Backend{Via: "tor"}, true},
		{"tunnel set", alaye.Backend{Tunnel: "socks5://127.0.0.1:9050"}, true},
		{"both set", alaye.Backend{Via: "tor", Tunnel: "socks5://127.0.0.1:9050"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.b.HasTunnel(); got != c.want {
				t.Errorf("HasTunnel() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBackend_IsZero_WithTunnelFields(t *testing.T) {
	via := alaye.Backend{Via: "tor"}
	if via.IsZero() {
		t.Error("Backend{Via:\"tor\"}.IsZero() should be false")
	}

	inline := alaye.Backend{Tunnel: "socks5://127.0.0.1:9050"}
	if inline.IsZero() {
		t.Error("Backend{Tunnel:...}.IsZero() should be false")
	}

	empty := alaye.Backend{}
	if !empty.IsZero() {
		t.Error("empty Backend.IsZero() should be true")
	}
}

func TestRoute_Validate_ViaAndTunnelMutuallyExclusive(t *testing.T) {
	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Via:     "tor",
			Tunnel:  "socks5://127.0.0.1:9050",
			Servers: alaye.NewServers("http://127.0.0.1:8080"),
		},
	}
	if err := route.Validate(); err == nil {
		t.Error("expected error when both via and tunnel are set, got nil")
	}
}

func TestRoute_Validate_TunnelInlineValid(t *testing.T) {
	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Tunnel:  "socks5://127.0.0.1:9050",
			Servers: alaye.NewServers("http://127.0.0.1:8080"),
		},
	}
	if err := route.Validate(); err != nil {
		t.Errorf("Validate() unexpected error for valid inline tunnel: %v", err)
	}
}

func TestRoute_Validate_TunnelInlineWrongScheme(t *testing.T) {
	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Tunnel:  "http://127.0.0.1:9050", // wrong scheme
			Servers: alaye.NewServers("http://127.0.0.1:8080"),
		},
	}
	if err := route.Validate(); err == nil {
		t.Error("expected error for non-socks5 tunnel scheme, got nil")
	}
}

func TestRoute_Validate_TunnelInlineNoPort(t *testing.T) {
	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Tunnel:  "socks5://127.0.0.1", // missing port
			Servers: alaye.NewServers("http://127.0.0.1:8080"),
		},
	}
	if err := route.Validate(); err == nil {
		t.Error("expected error for tunnel URI missing port, got nil")
	}
}

func TestRoute_Validate_ViaOnlyIsValid(t *testing.T) {
	// Via alone (no Tunnel) is valid at route level; name resolution is runtime.
	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Via:     "tor",
			Servers: alaye.NewServers("http://127.0.0.1:8080"),
		},
	}
	if err := route.Validate(); err != nil {
		t.Errorf("Validate() unexpected error for via-only: %v", err)
	}
}

// resolveTunnelPool — internal function tested via routes_test helpers

func TestResolveTunnelPool_NilPools_NoTunnel(t *testing.T) {
	b := alaye.Backend{}
	logger := ll.New("test").Disable()
	pool, err := resolveTunnelPool(b, nil, logger)
	if err != nil {
		t.Errorf("resolveTunnelPool() error = %v, want nil", err)
	}
	if pool != nil {
		t.Error("resolveTunnelPool() should return nil pool when no tunnel configured")
	}
}

func TestResolveTunnelPool_Via_Found(t *testing.T) {
	expected, _ := tunnel.New(tunnel.Config{Servers: []string{"127.0.0.1:9050"}})
	pools := map[string]*tunnel.Pool{"tor": expected}
	logger := ll.New("test").Disable()

	b := alaye.Backend{Via: "tor"}
	pool, err := resolveTunnelPool(b, pools, logger)
	if err != nil {
		t.Fatalf("resolveTunnelPool() error = %v", err)
	}
	if pool != expected {
		t.Error("resolveTunnelPool() should return the exact named pool")
	}
}

func TestResolveTunnelPool_Via_NotFound(t *testing.T) {
	pools := map[string]*tunnel.Pool{} // empty registry
	logger := ll.New("test").Disable()

	b := alaye.Backend{Via: "nonexistent"}
	_, err := resolveTunnelPool(b, pools, logger)
	if err == nil {
		t.Error("expected error for unknown tunnel name, got nil")
	}
}

func TestResolveTunnelPool_InlineTunnel_Valid(t *testing.T) {
	logger := ll.New("test").Disable()
	b := alaye.Backend{Tunnel: "socks5://127.0.0.1:9050"}
	pool, err := resolveTunnelPool(b, nil, logger)
	if err != nil {
		t.Fatalf("resolveTunnelPool() error = %v", err)
	}
	if pool == nil {
		t.Fatal("resolveTunnelPool() should return a non-nil pool for inline tunnel")
	}
	if pool.Len() != 1 {
		t.Errorf("inline pool Len() = %d, want 1", pool.Len())
	}
}

func TestResolveTunnelPool_InlineTunnel_WithAuth(t *testing.T) {
	logger := ll.New("test").Disable()
	b := alaye.Backend{Tunnel: "socks5://user:pass@proxy.example.com:1080"}
	pool, err := resolveTunnelPool(b, nil, logger)
	if err != nil {
		t.Fatalf("resolveTunnelPool() error = %v", err)
	}
	if pool == nil {
		t.Fatal("resolveTunnelPool() should return non-nil pool")
	}
	// Confirm credentials are not in display addresses
	for _, addr := range pool.Addrs() {
		if containsTunnelStr(addr, "pass") {
			t.Errorf("inline pool leaked password in Addrs(): %q", addr)
		}
	}
}

func TestResolveTunnelPool_InlineTunnel_Invalid(t *testing.T) {
	logger := ll.New("test").Disable()
	b := alaye.Backend{Tunnel: "http://127.0.0.1:9050"} // wrong scheme
	_, err := resolveTunnelPool(b, nil, logger)
	if err == nil {
		t.Error("expected error for invalid inline tunnel URI, got nil")
	}
}

func TestResolveTunnelPool_Via_TakesPrecedence(t *testing.T) {
	// Via is checked first; if it resolves, Tunnel is ignored.
	// (In practice route.Validate() prevents both being set, but
	// resolveTunnelPool itself should still behave correctly.)
	named, _ := tunnel.New(tunnel.Config{Servers: []string{"127.0.0.1:9050"}})
	pools := map[string]*tunnel.Pool{"tor": named}
	logger := ll.New("test").Disable()

	b := alaye.Backend{Via: "tor", Tunnel: "socks5://127.0.0.1:9051"}
	pool, err := resolveTunnelPool(b, pools, logger)
	if err != nil {
		t.Fatalf("resolveTunnelPool() error = %v", err)
	}
	if pool != named {
		t.Error("Via should take precedence and return the named pool")
	}
}

// NewRoute — tunnel integration (end-to-end at handler level)

func TestNewRoute_WithVia_NamedTunnelResolves(t *testing.T) {
	cfg := NewTestConfig(t)

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("named-tunnel-ok"))
	}))
	defer backendSrv.Close()

	// Build a pool and inject it into the test config
	pool, err := tunnel.New(tunnel.Config{
		Name:    "test-named",
		Servers: []string{"127.0.0.1:1"}, // unreachable proxy — enough to test wiring
	})
	if err != nil {
		t.Fatalf("tunnel.New: %v", err)
	}
	cfg.TunnelPools = map[string]*tunnel.Pool{"test-named": pool}

	route := &alaye.Route{
		Enabled: expect.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Via:     "test-named",
			Servers: alaye.NewServers(backendSrv.URL),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("NewRoute should not return nil")
	}
	defer h.Close()

	// The request will fail (SOCKS5 proxy unreachable) but it proves the
	// tunnel was wired — if wiring broke, we'd get a direct-connect 200.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// 502 = tried the tunnel (unreachable), did not connect directly
	// 200 = connected directly (tunnel not wired — failure)
	if w.Code == http.StatusOK {
		t.Error("got 200: request connected directly instead of routing through the tunnel — Via wiring broken")
	}
}

func TestNewRoute_WithInlineTunnel_Wired(t *testing.T) {
	cfg := NewTestConfig(t)

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendSrv.Close()

	route := &alaye.Route{
		Enabled: expect.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Tunnel:  "socks5://127.0.0.1:1", // unreachable proxy — wiring check only
			Servers: alaye.NewServers(backendSrv.URL),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("NewRoute should not return nil")
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Same reasoning as above: 200 means direct connect (tunnel not wired).
	if w.Code == http.StatusOK {
		t.Error("got 200: inline tunnel not applied — request connected directly")
	}
}

func TestNewRoute_WithVia_UnknownName_LogsAndFails(t *testing.T) {
	cfg := NewTestConfig(t)
	// TunnelPools is empty — "phantom" doesn't exist

	route := &alaye.Route{
		Enabled: expect.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Via:     "phantom",
			Servers: alaye.NewServers("http://127.0.0.1:8080"),
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("NewRoute should return a fallback route, not nil")
	}
	defer h.Close()

	// All backends failed to build — route falls back to 502
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for unknown via name, got %d", w.Code)
	}
}

func TestNewRoute_NoTunnel_DirectConnect(t *testing.T) {
	cfg := NewTestConfig(t)

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("direct"))
	}))
	defer backendSrv.Close()

	route := &alaye.Route{
		Enabled: expect.Active,
		Path:    "/",
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: alaye.NewServers(backendSrv.URL),
			// Via and Tunnel both empty — direct connection
		},
	}

	h := NewRoute(cfg, route)
	if h == nil {
		t.Fatal("NewRoute should not return nil")
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for direct connection, got %d", w.Code)
	}
	if w.Body.String() != "direct" {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

// Helpers

// minimalGlobal returns a Global with the minimum fields needed to pass
// Validate() so tunnel-specific tests can focus on tunnel validation only.
func minimalGlobal() alaye.Global {
	return alaye.Global{
		Version: 1,
		Bind: alaye.Bind{
			HTTP: []string{":8080"},
		},
		// Admin.Enabled is zero (Inactive) — Validate() skips all checks.
		// All other blocks default to disabled/zero — they pass validation.
	}
}

func containsTunnelStr(s, sub string) bool {
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
