package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/cook"
	discovery2 "github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

var (
	testLogger    = ll.New("test").Disable()
	testIPManager = zulu.NewIPManager(nil)
	testResource  = resource.New()
)

// testCookManager creates a cook manager for testing with proper config
func testCookManager(t *testing.T) *cook.Manager {
	t.Helper()

	pool := jack.NewPool(2)
	cfg := cook.ManagerConfig{
		WorkDir: expect.NewFolder(t.TempDir()),
		Pool:    pool,
		Logger:  testLogger,
	}

	m, err := cook.NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create cook manager: %v", err)
	}
	return m
}

// testTLSManager creates a TLS manager for testing
func testTLSManager(t *testing.T) *tlss.Manager {
	t.Helper()
	return tlss.NewManager(testLogger, nil, &alaye.Global{}, nil)
}

// testHostManagerWithHosts creates a host manager with pre-loaded hosts
func testHostManagerWithHosts(t *testing.T, hosts map[string]*alaye.Host) *discovery2.Host {
	t.Helper()

	hm := discovery2.NewHost(
		expect.NewFolder(t.TempDir()),
		discovery2.WithLogger(testLogger),
	)

	// Use LoadStatic to load multiple hosts at once (matches old code)
	hm.LoadStatic(hosts)

	return hm
}

// testManagerConfig creates a minimal ManagerConfig for testing
func testManagerConfig(t *testing.T) ManagerConfig {
	t.Helper()

	return ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery2.NewHost(expect.NewFolder(t.TempDir()), discovery2.WithLogger(testLogger)),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}
}

// Tests

func TestNewManager_NilConfig(t *testing.T) {
	_, err := NewManager(ManagerConfig{})
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

func TestNewManager_MinimalConfig(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	m.Close()
}

func TestManager_Firewall(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Security.Enabled = expect.Active
	cfg.Global.Security.Firewall.Status = expect.Active
	cfg.Global.Security.Firewall.Mode = "active"
	cfg.Global.Storage.DataDir = expect.NewFolder(t.TempDir())

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	fw := m.Firewall()
	if fw == nil {
		t.Error("Expected non-nil firewall")
	}
}

func TestManager_BuildListeners_NoGlobalBind(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listeners := m.BuildListeners()
	if len(listeners) != 0 {
		t.Errorf("Expected 0 listeners, got %d", len(listeners))
	}
}

func TestManager_BuildListeners_HTTP(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Bind.HTTP = []string{":8080"}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listeners := m.BuildListeners()
	if len(listeners) == 0 {
		t.Error("Expected at least 1 listener")
	}

	var httpFound bool
	for _, l := range listeners {
		if l.Kind() == "http" {
			httpFound = true
			break
		}
	}
	if !httpFound {
		t.Error("Expected HTTP listener")
	}
}

func TestManager_BuildListeners_HTTPS(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Bind.HTTPS = []string{":8443"}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listeners := m.BuildListeners()
	var httpsFound, h3Found bool
	for _, l := range listeners {
		switch l.Kind() {
		case "https":
			httpsFound = true
		case "h3":
			h3Found = true
		}
	}
	if !httpsFound {
		t.Error("Expected HTTPS listener")
	}
	if !h3Found {
		t.Error("Expected H3 listener")
	}
}

func TestManager_BuildListeners_HostBind(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"example.com"},
		Bind:    []string{"9090"},
		TLS: alaye.TLS{
			Mode: def.ModeLocalNone,
		},
	}

	// Create host manager with the host pre-loaded
	cfg := ManagerConfig{
		Global:      &alaye.Global{Bind: alaye.Bind{}},
		HostManager: testHostManagerWithHosts(t, map[string]*alaye.Host{"example.com": host}),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listeners := m.BuildListeners()
	if len(listeners) == 0 {
		t.Error("Expected at least 1 listener for host bind")
	}
}

func TestManager_BuildListeners_TCPProxy(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"example.com"},
		Proxies: []alaye.Proxy{
			{
				Enabled: expect.Active,
				Name:    "test-tcp",
				Listen:  ":9999",
				Backends: []alaye.Server{
					{Address: alaye.Address("tcp://127.0.0.1:6379")},
				},
			},
		},
	}

	// Create host manager with the host pre-loaded
	cfg := ManagerConfig{
		Global:      &alaye.Global{Bind: alaye.Bind{}},
		HostManager: testHostManagerWithHosts(t, map[string]*alaye.Host{"example.com": host}),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listeners := m.BuildListeners()
	var tcpFound bool
	for _, l := range listeners {
		if l.Kind() == "tcp" {
			tcpFound = true
			break
		}
	}
	if !tcpFound {
		t.Error("Expected TCP listener")
	}
}

func TestManager_chainBuild(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Logging.Prometheus.Enabled = expect.Active

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.chainBuild(baseHandler, true, "8080")
	if handler == nil {
		t.Fatal("chainBuild returned nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestManager_chainBuildFirewall_Nil(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.chainBuildFirewall(baseHandler)
	if handler == nil {
		t.Fatal("chainBuildFirewall returned nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestManager_handleRequest_Favicon(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	w := httptest.NewRecorder()
	m.handleRequest(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Errorf("Expected 200 or 404 for favicon, got %d", w.Code)
	}
}

func TestManager_handleRequest_ACMEChallenge(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil)
	w := httptest.NewRecorder()
	m.handleRequest(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for missing ACME challenge, got %d", w.Code)
	}
}

func TestManager_handleRequest_Webhook(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("POST", "/.well-known/agbero/webhook/route-key", nil)
	m.handleRequest(httptest.NewRecorder(), req)
}

func TestManager_handleRequest_HostNotFound(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "nonexistent.com"
	m.handleRequest(httptest.NewRecorder(), req)
}

func TestManager_handleRequest_MaxBodySize(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"example.com"},
		Limits: alaye.Limit{
			MaxBodySize: 100,
		},
	}

	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: testHostManagerWithHosts(t, map[string]*alaye.Host{"example.com": host}),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	body := bytes.Repeat([]byte("x"), 200)
	req := httptest.NewRequest("POST", "/", io.NopCloser(bytes.NewReader(body)))
	req.ContentLength = int64(len(body))
	req.Host = "example.com"

	w := httptest.NewRecorder()
	m.handleRequest(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413, got %d", w.Code)
	}
}

func TestManager_handleRequest_RouterNotFound(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"example.com"},
	}

	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: testHostManagerWithHosts(t, map[string]*alaye.Host{"example.com": host}),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"

	w := httptest.NewRecorder()
	m.handleRequest(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for missing router, got %d", w.Code)
	}
}

func TestManager_handleRoute_WASM_InvalidModule(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"example.com"},
	}

	root := t.TempDir()
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Enabled: expect.Active,
			Root:    alaye.WebRoot(root),
		},
		Wasm: alaye.Wasm{
			Enabled: expect.Active,
			Module:  "/nonexistent.wasm",
		},
	}

	cfg := ManagerConfig{
		Global: &alaye.Global{
			Timeouts: alaye.Timeout{
				Read:       expect.Duration(30 * time.Second),
				Write:      expect.Duration(30 * time.Second),
				Idle:       expect.Duration(120 * time.Second),
				ReadHeader: expect.Duration(5 * time.Second),
			},
			Security: alaye.Security{
				Enabled:        expect.Inactive,
				TrustedProxies: []string{},
			},
			RateLimits: alaye.RateGlobal{
				Enabled:    expect.Inactive,
				TTL:        expect.Duration(10 * time.Minute),
				MaxEntries: def.DefaultCacheMaxItems,
			},
			Storage: alaye.Storage{
				WorkDir: expect.NewFolder(t.TempDir()),
				DataDir: expect.NewFolder(t.TempDir()),
			},
			Bind: alaye.Bind{},
		},
		HostManager: testHostManagerWithHosts(t, map[string]*alaye.Host{"example.com": host}),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"

	m.handleRoute(w, req, route, host)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 for invalid WASM, got %d", w.Code)
	}
}

func TestManager_handleRoute_RateLimit_IgnoreGlobal(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"example.com"},
	}

	root := expect.NewFolder(t.TempDir())
	if err := root.Put("index.html", []byte("OK"), expect.FilePerm); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Enabled: expect.Active,
			Root:    alaye.WebRoot(root),
		},
		RateLimit: alaye.RateRoute{
			Enabled:      expect.Active,
			IgnoreGlobal: true,
		},
	}

	cfg := ManagerConfig{
		Global: &alaye.Global{
			RateLimits: alaye.RateGlobal{
				Enabled: expect.Active,
				Rules: []alaye.RateRule{
					{
						Enabled:  expect.Active,
						Requests: 1,
						Window:   expect.Duration(time.Second),
					},
				},
			},
		},
		HostManager: testHostManagerWithHosts(t, map[string]*alaye.Host{"example.com": host}),
		Resource:    testResource,
		IPMgr:       testIPManager,
		CookManager: testCookManager(t),
		TLSManager:  testTLSManager(t),
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"

	m.handleRoute(w, req, route, host)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 when ignoring global rate limit, got %d", w.Code)
	}
}

func TestManager_redirectToHTTPS(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Bind.HTTPS = []string{":443"}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/path?query=1", nil)
	req.Host = "example.com:80"

	w := httptest.NewRecorder()
	m.redirectToHTTPS(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301 redirect, got %d", w.Code)
	}
	if w.Header().Get("Location") != "https://example.com/path?query=1" {
		t.Errorf("Expected redirect to https://example.com/path?query=1, got %q", w.Header().Get("Location"))
	}
}

func TestManager_logRequest_SkipPath(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Logging.Enabled = expect.Active
	cfg.Global.Logging.Skip = []string{"/health"}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	m.logRequest("example.com", req, time.Now(), 200, 100)
}

func TestManager_logRequest_WithUserAgent(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Logging.Enabled = expect.Active

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")
	m.logRequest("example.com", req, time.Now(), 200, 100)
}

func TestManager_wasmManager_Cache(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	wasmCfg := &alaye.Wasm{
		Enabled: expect.Active,
		Module:  "/nonexistent.wasm",
	}

	mgr1, err := m.wasmManager(wasmCfg, "key1")
	if err == nil {
		t.Error("Expected error for nonexistent WASM module")
	}

	mgr2, err := m.wasmManager(wasmCfg, "key1")
	if mgr1 != mgr2 {
		t.Error("Expected cached manager to be returned")
	}
}

func TestManager_wasmCleanup(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	wasmCfg := &alaye.Wasm{
		Enabled: expect.Active,
		Module:  "/nonexistent.wasm",
	}
	_, _ = m.wasmManager(wasmCfg, "key1")
	m.wasmCleanup()
}

func TestManager_groupTCPRoutesByListen(t *testing.T) {
	hosts := map[string]*alaye.Host{
		"example.com": {
			Domains: []string{"example.com"},
			Proxies: []alaye.Proxy{
				{
					Name:   "route1",
					Listen: ":9999",
				},
				{
					Name:   "route2",
					Listen: ":9999",
				},
				{
					Name:   "route3",
					Listen: ":8888",
				},
			},
		},
	}

	groups := groupTCPRoutesByListen(hosts)
	if len(groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(groups))
	}
	if len(groups[":9999"]) != 2 {
		t.Errorf("Expected 2 routes for :9999, got %d", len(groups[":9999"]))
	}
	if len(groups[":8888"]) != 1 {
		t.Errorf("Expected 1 route for :8888, got %d", len(groups[":8888"]))
	}
}

func TestManager_buildGlobalRateLimiter_Nil(t *testing.T) {
	result := buildGlobalRateLimiter(nil, nil, nil)
	if result != nil {
		t.Error("Expected nil limiter for nil config")
	}
}

func TestManager_buildGlobalRateLimiter_Disabled(t *testing.T) {
	global := &alaye.Global{
		RateLimits: alaye.RateGlobal{
			Enabled: expect.Inactive,
		},
	}
	result := buildGlobalRateLimiter(global, nil, nil)
	if result != nil {
		t.Error("Expected nil limiter for disabled config")
	}
}

func TestManager_buildGlobalRateLimiter_ACMEExcluded(t *testing.T) {
	global := &alaye.Global{
		RateLimits: alaye.RateGlobal{
			Enabled: expect.Active,
			Rules: []alaye.RateRule{
				{
					Enabled:  expect.Active,
					Requests: 100,
					Window:   expect.Duration(time.Minute),
				},
			},
		},
	}

	result := buildGlobalRateLimiter(global, testIPManager, nil)
	if result == nil {
		t.Error("Expected non-nil limiter")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := result.Handler(handler)
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected ACME to bypass rate limit, got %d", w.Code)
	}
}

func TestManager_createHTTPListener_TLSConfig(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.Global.Timeouts.Read = expect.Duration(10 * time.Second)
	cfg.Global.Timeouts.Write = expect.Duration(30 * time.Second)
	cfg.Global.Timeouts.Idle = expect.Duration(120 * time.Second)
	cfg.Global.Timeouts.ReadHeader = expect.Duration(5 * time.Second)
	cfg.Global.General.MaxHeaderBytes = 1 << 20

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listener := m.createHTTPListener(":8443", "8443", true)
	if listener == nil {
		t.Fatal("createHTTPListener returned nil")
	}
	if listener.Kind() != "https" {
		t.Errorf("Expected kind 'https', got %q", listener.Kind())
	}
	if listener.Addr() != ":8443" {
		t.Errorf("Expected addr ':8443', got %q", listener.Addr())
	}
}

func TestManager_createH3Listener_NilTLS(t *testing.T) {
	cfg := testManagerConfig(t)
	cfg.TLSManager = nil

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listener := m.createH3Listener(":443", "443")
	if listener != nil {
		t.Error("Expected nil H3 listener for nil TLS config")
	}
}

func TestManager_createH3Listener_Success(t *testing.T) {
	cfg := testManagerConfig(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	listener := m.createH3Listener(":443", "443")
	if listener == nil {
		t.Fatal("createH3Listener returned nil")
	}
	if listener.Kind() != "h3" {
		t.Errorf("Expected kind 'h3', got %q", listener.Kind())
	}
}
