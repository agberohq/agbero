package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/cook"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/olekukonko/ll"
)

func TestNewManager_NilConfig(t *testing.T) {
	_, err := NewManager(ManagerConfig{})
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

func TestNewManager_MinimalConfig(t *testing.T) {
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	m.Close()
}

func TestManager_Close(t *testing.T) {
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Security: alaye.Security{
				Enabled: alaye.Active,
				Firewall: alaye.Firewall{
					Status: alaye.Active,
				},
			},
			RateLimits: alaye.GlobalRate{
				Enabled: alaye.Active,
				Rules: []alaye.RateRule{
					{
						Enabled:  alaye.Active,
						Requests: 100,
						Window:   time.Minute,
					},
				},
			},
			Storage: alaye.Storage{
				DataDir: t.TempDir(),
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	m.Close()
}

func TestManager_Firewall(t *testing.T) {
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Security: alaye.Security{
				Enabled: alaye.Active,
				Firewall: alaye.Firewall{
					Status: alaye.Active,
				},
			},
			Storage: alaye.Storage{
				DataDir: t.TempDir(),
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Bind: alaye.Bind{},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Bind: alaye.Bind{
				HTTP: []string{":8080"},
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Bind: alaye.Bind{
				HTTPS: []string{":8443"},
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
			Mode: alaye.ModeLocalNone,
		},
	}
	cfg := ManagerConfig{
		Global: &alaye.Global{Bind: alaye.Bind{}},
		HostManager: func() *discovery.Host {
			h := discovery.NewHost(woos.NewFolder(t.TempDir()), discovery.WithLogger(ll.New("test").Disable()))
			// Use LoadStatic to avoid HCL marshaling of custom types like alaye.TlsMode
			h.LoadStatic(map[string]*alaye.Host{"example.com": host})
			return h
		}(),
		Resource: resource.New(),
		IPMgr:    zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
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
				Enabled: alaye.Active,
				Name:    "test-tcp",
				Listen:  ":9999",
				Backends: []alaye.Server{
					{Address: "tcp://127.0.0.1:6379"},
				},
			},
		},
	}
	cfg := ManagerConfig{
		Global: &alaye.Global{Bind: alaye.Bind{}},
		HostManager: func() *discovery.Host {
			h := discovery.NewHost(woos.NewFolder(t.TempDir()), discovery.WithLogger(ll.New("test").Disable()))
			// Use LoadStatic to avoid HCL marshaling of custom types
			h.LoadStatic(map[string]*alaye.Host{"example.com": host})
			return h
		}(),
		Resource: resource.New(),
		IPMgr:    zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
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
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Logging: alaye.Logging{
				Prometheus: alaye.Prometheus{
					Enabled: alaye.Active,
				},
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()
	req := httptest.NewRequest("POST", "/.well-known/agbero/webhook/route-key", nil)
	m.handleRequest(httptest.NewRecorder(), req)
}

func TestManager_handleRequest_HostNotFound(t *testing.T) {
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
		Global: &alaye.Global{},
		HostManager: func() *discovery.Host {
			h := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable()))
			h.Set("example.com", host)
			return h
		}(),
		Resource: resource.New(),
		IPMgr:    zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
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
		Global: &alaye.Global{},
		HostManager: func() *discovery.Host {
			h := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable()))
			h.Set("example.com", host)
			return h
		}(),
		Resource: resource.New(),
		IPMgr:    zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
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
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(t.TempDir()),
		},
		Wasm: alaye.Wasm{
			Enabled: alaye.Active,
			Module:  "/nonexistent.wasm",
		},
	}
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Timeouts: alaye.Timeout{
				Read:       30 * time.Second,
				Write:      30 * time.Second,
				Idle:       120 * time.Second,
				ReadHeader: 5 * time.Second,
			},
			Security: alaye.Security{
				Enabled:        alaye.Inactive,
				TrustedProxies: []string{},
			},
			RateLimits: alaye.GlobalRate{
				Enabled:    alaye.Inactive,
				TTL:        10 * time.Minute,
				MaxEntries: 10000,
			},
			Storage: alaye.Storage{
				WorkDir: t.TempDir(),
				DataDir: t.TempDir(),
			},
			Bind: alaye.Bind{},
		},
		HostManager: func() *discovery.Host {
			h := discovery.NewHost(woos.NewFolder(t.TempDir()), discovery.WithLogger(ll.New("test").Disable()))
			h.Set("example.com", host)
			return h
		}(),
		Resource: resource.New(),
		IPMgr:    zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
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
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("OK"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(root),
		},
		RateLimit: alaye.RouteRate{
			Enabled:      alaye.Active,
			IgnoreGlobal: true,
		},
	}
	cfg := ManagerConfig{
		Global: &alaye.Global{
			RateLimits: alaye.GlobalRate{
				Enabled: alaye.Active,
				Rules: []alaye.RateRule{
					{
						Enabled:  alaye.Active,
						Requests: 1,
						Window:   time.Second,
					},
				},
			},
		},
		HostManager: func() *discovery.Host {
			h := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable()))
			h.Set("example.com", host)
			return h
		}(),
		Resource: resource.New(),
		IPMgr:    zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
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
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Bind: alaye.Bind{
				HTTPS: []string{":443"},
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Logging: alaye.Logging{
				Enabled: alaye.Active,
				Skip:    []string{"/health"},
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()
	req := httptest.NewRequest("GET", "/health", nil)
	m.logRequest("example.com", req, time.Now(), 200, 100)
}

func TestManager_logRequest_WithUserAgent(t *testing.T) {
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Logging: alaye.Logging{
				Enabled: alaye.Active,
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()
	wasmCfg := &alaye.Wasm{
		Enabled: alaye.Active,
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()
	wasmCfg := &alaye.Wasm{
		Enabled: alaye.Active,
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
		RateLimits: alaye.GlobalRate{
			Enabled: alaye.Inactive,
		},
	}
	result := buildGlobalRateLimiter(global, nil, nil)
	if result != nil {
		t.Error("Expected nil limiter for disabled config")
	}
}

func TestManager_buildGlobalRateLimiter_ACMEExcluded(t *testing.T) {
	global := &alaye.Global{
		RateLimits: alaye.GlobalRate{
			Enabled: alaye.Active,
			Rules: []alaye.RateRule{
				{
					Enabled:  alaye.Active,
					Requests: 100,
					Window:   time.Minute,
				},
			},
		},
	}
	ipMgr := zulu.NewIPManager(nil)
	result := buildGlobalRateLimiter(global, ipMgr, nil)
	if result == nil {
		t.Error("Expected non-nil limiter")
	}
	// Verify ACME exclusion through Handler behavior, not internal policy
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := result.Handler(handler)
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	// ACME should bypass rate limit and reach handler (200 OK)
	if w.Code != http.StatusOK {
		t.Errorf("Expected ACME to bypass rate limit, got %d", w.Code)
	}
}

func TestManager_createHTTPListener_TLSConfig(t *testing.T) {
	cfg := ManagerConfig{
		Global: &alaye.Global{
			Timeouts: alaye.Timeout{
				Read:       10 * time.Second,
				Write:      30 * time.Second,
				Idle:       120 * time.Second,
				ReadHeader: 5 * time.Second,
			},
			General: alaye.General{
				MaxHeaderBytes: 1 << 20,
			},
		},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: nil,
	}
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
	cfg := ManagerConfig{
		Global:      &alaye.Global{},
		HostManager: discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(ll.New("test").Disable())),
		Resource:    resource.New(),
		IPMgr:       zulu.NewIPManager(nil),
		CookManager: func() *cook.Manager {
			m, _ := cook.NewManager(t.TempDir(), nil, ll.New("test").Disable())
			return m
		}(),
		TLSManager: tlss.NewManager(ll.New("test").Disable(), nil, &alaye.Global{}),
	}
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
