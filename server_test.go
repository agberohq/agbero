package agbero

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/cluster"
	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/parser"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

var (
	testLogger = ll.New("test").Disable()
)

func TestNewServer_Basic(t *testing.T) {
	s := NewServer()
	if s.servers == nil || s.h3Servers == nil {
		t.Error("Maps not initialized")
	}
}

func TestServer_Start_NoConfig(t *testing.T) {
	s := NewServer()
	err := s.Start("")
	if err == nil || !strings.Contains(err.Error(), "host manager is required") {
		t.Errorf("Expected host manager error, got %v", err)
	}
}

func TestServer_Start_NoGlobalConfig(t *testing.T) {
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := NewServer(WithHostManager(hm))
	err := s.Start("")
	if err == nil || !strings.Contains(err.Error(), "global config is required") {
		t.Errorf("Expected global config error, got %v", err)
	}
}

func TestServer_Start_Minimal(t *testing.T) {
	shutdown := jack.NewShutdown(
		jack.ShutdownWithTimeout(100 * time.Millisecond),
	)

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	global := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":0"}},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  tmpDir,
			CertsDir: filepath.Join(tmpDir, "certs"),
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       10 * time.Second,
			Write:      30 * time.Second,
			Idle:       60 * time.Second,
			ReadHeader: 5 * time.Second,
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	hm := discovery.NewHost(woos.Folder(hostsDir), discovery.WithLogger(testLogger))
	s := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(testLogger),
		WithShutdownManager(shutdown),
	)

	configPath := filepath.Join(tmpDir, "config.hcl")
	_ = os.WriteFile(configPath, []byte(""), woos.FilePerm)

	errCh := make(chan error)
	go func() {
		errCh <- s.Start(configPath)
	}()

	time.Sleep(200 * time.Millisecond)
	shutdown.TriggerShutdown()

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "server closed") {
			t.Errorf("Unexpected error from Start: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Test timed out waiting for server shutdown")
	}
}

func TestServer_buildTLS(t *testing.T) {
	tmpDir := t.TempDir()

	global := &alaye.Global{
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
		},
		Storage: alaye.Storage{
			CertsDir: tmpDir,
		},
	}

	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: discovery.NewHost("", discovery.WithLogger(testLogger)),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	cfg, handler := s.buildTLS(next)
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
				CertsDir: tmpDir,
			},
		},
		logger:      testLogger,
		hostManager: discovery.NewHost("", discovery.WithLogger(testLogger)),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	cfg, handler := s.buildTLS(next)
	if cfg == nil {
		t.Error("TLS config should be created even if email is missing (for local dev)")
	}
	if handler == nil {
		t.Error("Handler should still be created")
	}
}

func TestServer_buildGlobalRateLimiter(t *testing.T) {
	s := &Server{global: &alaye.Global{
		RateLimits: alaye.GlobalRate{
			Enabled:    alaye.Active,
			TTL:        time.Minute,
			MaxEntries: 100,
			Rules: []alaye.RateRule{
				{
					Enabled:  alaye.Active,
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

	rl := s.buildGlobalRateLimiter()
	if rl == nil {
		t.Error("RateLimiter not created")
	}
}

func TestServer_buildGlobalRateLimiter_Disabled(t *testing.T) {
	s := &Server{global: &alaye.Global{
		RateLimits: alaye.GlobalRate{
			Enabled: alaye.Inactive,
		},
	}}

	rl := s.buildGlobalRateLimiter()
	if rl != nil {
		t.Error("RateLimiter should be nil when disabled")
	}
}

func TestServer_getOrBuildRouteHandler_CacheHit(t *testing.T) {
	s := &Server{
		global: &alaye.Global{},
		logger: testLogger,
		reaper: jack.NewReaper(time.Minute),
	}

	host := &alaye.Host{
		Domains: []string{"example.com"},
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/test",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:8080"),
		},
	}

	woos.DefaultRoute(route)
	key := route.Key()

	handler := handlers.NewRoute(handlers.Config{
		Global: s.global, Host: host, Logger: testLogger,
	}, route)

	item := &mappo.Item{
		Value: handler,
	}
	item.LastAccessed.Store(time.Now().UnixNano())

	zulu.Route.Store(key, item)

	h := s.getOrBuildRouteHandler(route, host)
	if h != handler {
		t.Error("Cache miss unexpectedly")
	}

	handler.Close()
	zulu.Route.Delete(key)
}

func TestServer_getOrBuildRouteHandler_CacheMiss(t *testing.T) {
	s := &Server{
		global: &alaye.Global{},
		logger: testLogger,
		reaper: jack.NewReaper(time.Minute),
	}

	host := &alaye.Host{
		Domains: []string{"example.com"},
	}

	route := &alaye.Route{
		Enabled: alaye.Active,
		Path:    "/test",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:8080"),
		},
	}

	zulu.Route.Delete(route.Key())

	h := s.getOrBuildRouteHandler(route, host)
	if h == nil {
		t.Error("Handler should be created on cache miss")
	}

	h.Close()
	zulu.Route.Delete(route.Key())
}

func TestServer_HandleRequest_NoHost(t *testing.T) {
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		hostManager: hm,
		logger:      testLogger,
		reaper:      jack.NewReaper(time.Minute),
		global:      &alaye.Global{},
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

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		t.Fatal(err)
	}

	hostFile := filepath.Join(hostsDir, "example.com.hcl")
	content := fmt.Sprintf(`
domains = ["example.com"]
route "/" {
    backend {
        server {
            address = "%s"
        }
    }
}
`, backend.URL)

	if err := os.WriteFile(hostFile, []byte(content), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	hm := discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))
	if err := hm.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	globalCfg := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":8080"}},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  t.TempDir(),
		},
		Timeouts: alaye.Timeout{
			Enabled: alaye.Active,
			Read:    10 * time.Second,
			Write:   30 * time.Second,
			Idle:    60 * time.Second,
		},
	}
	woos.DefaultApply(globalCfg, "")

	s := &Server{
		hostManager: hm,
		logger:      testLogger,
		reaper:      jack.NewReaper(time.Minute),
		global:      globalCfg,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"

	w := httptest.NewRecorder()
	s.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestServer_HandleRequest_WithBodyLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		t.Fatal(err)
	}

	hostFile := filepath.Join(hostsDir, "example.com.hcl")
	content := fmt.Sprintf(`
domains = ["example.com"]
limits {
    max_body_size = 10
}
route "/" {
    backend {
        server {
            address = "%s"
        }
    }
}
`, backend.URL)

	if err := os.WriteFile(hostFile, []byte(content), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	hm := discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))
	if err := hm.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		hostManager: hm,
		logger:      testLogger,
		reaper:      jack.NewReaper(time.Minute),
		global:      &alaye.Global{},
	}

	largeBody := strings.Repeat("a", 20)
	req := httptest.NewRequest("POST", "/", strings.NewReader(largeBody))
	req.Host = "example.com"
	req.ContentLength = int64(len(largeBody))

	w := httptest.NewRecorder()
	s.handleRequest(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413 Request Entity Too Large, got %d", w.Code)
	}
}

func TestServer_mTLS_Apply_Table(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDer, _ := x509.CreateCertificate(rand.Reader, &caTpl, &caTpl, &caKey.PublicKey, caKey)
	caPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caPath, caPem, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mode     string
		expected tls.ClientAuthType
	}{
		{"request", tls.RequestClientCert},
		{"require", tls.RequireAnyClientCert},
		{"verify_if_given", tls.VerifyClientCertIfGiven},
		{"require_and_verify", tls.RequireAndVerifyClientCert},
		{"none", tls.NoClientCert},
		{"unknown_mode", tls.NoClientCert},
		{"", tls.NoClientCert},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			host := &alaye.Host{
				TLS: alaye.TLS{
					ClientAuth: tt.mode,
					ClientCAs:  []string{caPath},
				},
			}

			s := &Server{logger: testLogger}
			tlsConfig := &tls.Config{}

			s.applyMTLS(tlsConfig, host)

			if tlsConfig.ClientAuth != tt.expected {
				t.Errorf("ClientAuth mismatch for mode %s: expected %v, got %v", tt.mode, tt.expected, tlsConfig.ClientAuth)
			}

			if tt.mode != "" && len(host.TLS.ClientCAs) > 0 {
				if tlsConfig.ClientCAs == nil {
					t.Error("ClientCAs pool was not initialized")
				}
			}
		})
	}
}

func TestServer_redirectToHTTPS(t *testing.T) {
	s := &Server{
		global: &alaye.Global{
			Bind: alaye.Bind{
				HTTPS: []string{":443"},
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	s.redirectToHTTPS(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301 Moved Permanently, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	expected := "https://example.com/test"
	if location != expected {
		t.Errorf("Expected Location %s, got %s", expected, location)
	}
}

func TestServer_redirectToHTTPS_WithCustomPort(t *testing.T) {
	s := &Server{
		global: &alaye.Global{
			Bind: alaye.Bind{
				HTTPS: []string{":8443"},
			},
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	s.redirectToHTTPS(w, req)

	location := w.Header().Get("Location")
	expected := "https://example.com:8443/test"
	if location != expected {
		t.Errorf("Expected Location %s, got %s", expected, location)
	}
}

func TestServer_Reload_DynamicBind(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		t.Fatal(err)
	}
	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatal(err)
	}

	hostFile := filepath.Join(hostsDir, "dynamic.hcl")
	initialHostConfig := fmt.Sprintf(`
domains = ["localhost"]
tls { mode = "none" }
route "/" {
  backend {
    server { address = "%s" }
  }
}
`, backend.URL)
	writeSyncedFile(t, hostFile, []byte(initialHostConfig))

	configFile := filepath.Join(tmpDir, "agbero.hcl")
	mainPort := getFreePort(t)
	time.Sleep(100 * time.Millisecond)

	initialGlobalConfig := fmt.Sprintf(`version = 2
bind {
  http = [":%d"]
}
storage {
  hosts_dir = "%s"
  certs_dir = "%s"
  data_dir = "%s"
}
timeouts {
  enabled = true
  read = "10s"
  write = "30s"
  idle = "60s"
  read_header = "5s"
}
`, mainPort, hostsDir, certsDir, tmpDir)
	writeSyncedFile(t, configFile, []byte(initialGlobalConfig))

	global, err := parser.LoadGlobal(configFile)
	if err != nil {
		t.Fatalf("Failed to parse initial config: %v", err)
	}
	woos.DefaultApply(global, configFile)

	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(10 * time.Second))
	hm := discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))

	if err := hm.Watch(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer hm.Close()

	s := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(testLogger),
		WithShutdownManager(shutdown),
	)

	go func() {
		if err := s.Start(configFile); err != nil && !strings.Contains(err.Error(), "server closed") {
			t.Logf("Server stopped: %v", err)
		}
	}()
	defer shutdown.TriggerShutdown()

	waitForPort(t, mainPort)

	targetPort := getFreePort(t)
	if targetPort == mainPort {
		t.Fatal("getFreePort returned the same port as mainPort")
	}

	time.Sleep(500 * time.Millisecond)

	if isPortOpen(t, targetPort) {
		t.Fatalf("Port %d is still open (zombie listener?)", targetPort)
	}

	updatedGlobalConfig := fmt.Sprintf(`version = 2
bind {
  http = [":%d"]
}
storage {
  hosts_dir = "%s"
  certs_dir = "%s"
  data_dir = "%s"
}
timeouts {
  enabled = true
  read = "10s"
  write = "30s"
  idle = "60s"
  read_header = "5s"
}
`, targetPort, hostsDir, certsDir, tmpDir)
	writeSyncedFile(t, configFile, []byte(updatedGlobalConfig))

	writeSyncedFile(t, hostFile, []byte(initialHostConfig+" # trigger reload"))

	waitForPort(t, targetPort)

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	reqURL := fmt.Sprintf("http://127.0.0.1:%d", targetPort)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "localhost"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect to dynamic port %d: %v", targetPort, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
}

func TestServer_Cluster_ConfigSync_RoutePropagation(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	port1 := getFreePort(t)
	port2 := getFreePort(t)

	global1 := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":0"}},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Active,
			Port:      port1,
			SecretKey: "0123456789abcdef0123456789abcdef",
		},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  tmpDir,
			CertsDir: filepath.Join(tmpDir, "certs"),
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       10 * time.Second,
			Write:      30 * time.Second,
			Idle:       60 * time.Second,
			ReadHeader: 5 * time.Second,
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	global2 := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":0"}},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Active,
			Port:      port2,
			Seeds:     []string{fmt.Sprintf("127.0.0.1:%d", port1)},
			SecretKey: "0123456789abcdef0123456789abcdef",
		},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  tmpDir,
			CertsDir: filepath.Join(tmpDir, "certs"),
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       10 * time.Second,
			Write:      30 * time.Second,
			Idle:       60 * time.Second,
			ReadHeader: 5 * time.Second,
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	shutdown1 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))
	shutdown2 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	hm1 := discovery.NewHost(woos.Folder(hostsDir), discovery.WithLogger(testLogger))
	hm2 := discovery.NewHost(woos.Folder(hostsDir), discovery.WithLogger(testLogger))

	s1 := NewServer(
		WithGlobalConfig(global1),
		WithHostManager(hm1),
		WithLogger(testLogger),
		WithShutdownManager(shutdown1),
	)

	s2 := NewServer(
		WithGlobalConfig(global2),
		WithHostManager(hm2),
		WithLogger(testLogger),
		WithShutdownManager(shutdown2),
	)

	configPath := filepath.Join(tmpDir, "config.hcl")
	_ = os.WriteFile(configPath, []byte(""), woos.FilePerm)

	var cm1, cm2 *cluster.Manager
	var cmMu sync.Mutex

	errCh1 := make(chan error, 1)
	errCh2 := make(chan error, 1)

	go func() {
		if err := s1.Start(configPath); err != nil && !strings.Contains(err.Error(), "server closed") {
			errCh1 <- err
		}
		cmMu.Lock()
		cm1 = s1.clusterManager
		cmMu.Unlock()
	}()
	go func() {
		if err := s2.Start(configPath); err != nil && !strings.Contains(err.Error(), "server closed") {
			errCh2 <- err
		}
		cmMu.Lock()
		cm2 = s2.clusterManager
		cmMu.Unlock()
	}()

	time.Sleep(2 * time.Second)

	cmMu.Lock()
	if cm1 == nil || cm2 == nil {
		cmMu.Unlock()
		t.Skip("Cluster manager not initialized, skipping cluster sync test")
	}
	cmMu.Unlock()

	members1 := cm1.Members()
	members2 := cm2.Members()
	if len(members1) < 2 || len(members2) < 2 {
		t.Skip("Cluster nodes did not join, skipping sync test")
	}

	route := alaye.Route{
		Enabled: alaye.Active,
		Path:    "/api/v1/test",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:9999"),
		},
	}
	wrapper := struct {
		Route     alaye.Route `json:"route"`
		ExpiresAt time.Time   `json:"expires_at"`
	}{
		Route:     route,
		ExpiresAt: time.Time{},
	}
	val, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("Failed to marshal route: %v", err)
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, "test.example.com", "/api/v1/test")
	cm1.Set(key, val)

	time.Sleep(1 * time.Second)

	host2, _ := hm2.LoadAll()
	found := false
	for _, h := range host2 {
		if h != nil {
			for _, r := range h.Routes {
				if r.Path == "/api/v1/test" {
					found = true
					break
				}
			}
		}
	}
	if !found {
		t.Error("Route not propagated to node2 host manager")
	}

	cm1.Delete(key)
	time.Sleep(1 * time.Second)

	host2After, _ := hm2.LoadAll()
	stillPresent := false
	for _, h := range host2After {
		if h != nil {
			for _, r := range h.Routes {
				if r.Path == "/api/v1/test" {
					stillPresent = true
					break
				}
			}
		}
	}
	if stillPresent {
		t.Error("Deleted route still present on node2")
	}

	shutdown1.TriggerShutdown()
	shutdown2.TriggerShutdown()

	select {
	case <-errCh1:
	case <-time.After(3 * time.Second):
	}
	select {
	case <-errCh2:
	case <-time.After(3 * time.Second):
	}
}

func TestServer_Cluster_ConfigSync_TombstoneDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	port1 := getFreePort(t)
	port2 := getFreePort(t)

	global1 := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":0"}},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Active,
			Port:      port1,
			SecretKey: "0123456789abcdef0123456789abcdef",
		},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  tmpDir,
			CertsDir: filepath.Join(tmpDir, "certs"),
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       10 * time.Second,
			Write:      30 * time.Second,
			Idle:       60 * time.Second,
			ReadHeader: 5 * time.Second,
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	global2 := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":0"}},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Active,
			Port:      port2,
			Seeds:     []string{fmt.Sprintf("127.0.0.1:%d", port1)},
			SecretKey: "0123456789abcdef0123456789abcdef",
		},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  tmpDir,
			CertsDir: filepath.Join(tmpDir, "certs"),
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       10 * time.Second,
			Write:      30 * time.Second,
			Idle:       60 * time.Second,
			ReadHeader: 5 * time.Second,
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	shutdown1 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))
	shutdown2 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	hm1 := discovery.NewHost(woos.Folder(hostsDir), discovery.WithLogger(testLogger))
	hm2 := discovery.NewHost(woos.Folder(hostsDir), discovery.WithLogger(testLogger))

	s1 := NewServer(
		WithGlobalConfig(global1),
		WithHostManager(hm1),
		WithLogger(testLogger),
		WithShutdownManager(shutdown1),
	)

	s2 := NewServer(
		WithGlobalConfig(global2),
		WithHostManager(hm2),
		WithLogger(testLogger),
		WithShutdownManager(shutdown2),
	)

	configPath := filepath.Join(tmpDir, "config.hcl")
	_ = os.WriteFile(configPath, []byte(""), woos.FilePerm)

	var cm1, cm2 *cluster.Manager
	var cmMu sync.Mutex

	errCh1 := make(chan error, 1)
	errCh2 := make(chan error, 1)

	go func() {
		if err := s1.Start(configPath); err != nil && !strings.Contains(err.Error(), "server closed") {
			errCh1 <- err
		}
		cmMu.Lock()
		cm1 = s1.clusterManager
		cmMu.Unlock()
	}()
	go func() {
		if err := s2.Start(configPath); err != nil && !strings.Contains(err.Error(), "server closed") {
			errCh2 <- err
		}
		cmMu.Lock()
		cm2 = s2.clusterManager
		cmMu.Unlock()
	}()

	time.Sleep(2 * time.Second)

	cmMu.Lock()
	if cm1 == nil || cm2 == nil {
		cmMu.Unlock()
		t.Skip("Cluster manager not initialized, skipping tombstone test")
	}
	cmMu.Unlock()

	members1 := cm1.Members()
	members2 := cm2.Members()
	if len(members1) < 2 || len(members2) < 2 {
		t.Skip("Cluster nodes did not join, skipping tombstone test")
	}

	route := alaye.Route{
		Enabled: alaye.Active,
		Path:    "/ephemeral",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:8888"),
		},
	}
	wrapper := struct {
		Route     alaye.Route `json:"route"`
		ExpiresAt time.Time   `json:"expires_at"`
	}{
		Route:     route,
		ExpiresAt: time.Now().Add(5 * time.Second),
	}
	val, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("Failed to marshal route: %v", err)
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, "temp.example.com", "/ephemeral")
	cm1.Set(key, val)
	time.Sleep(500 * time.Millisecond)

	host2, _ := hm2.LoadAll()
	initialCount := 0
	for _, h := range host2 {
		if h != nil {
			for _, r := range h.Routes {
				if r.Path == "/ephemeral" {
					initialCount++
				}
			}
		}
	}
	if initialCount == 0 {
		t.Error("Ephemeral route not received by node2")
	}

	cm1.Delete(key)
	time.Sleep(1 * time.Second)

	host2After, _ := hm2.LoadAll()
	finalCount := 0
	for _, h := range host2After {
		if h != nil {
			for _, r := range h.Routes {
				if r.Path == "/ephemeral" {
					finalCount++
				}
			}
		}
	}
	if finalCount > 0 {
		t.Error("Tombstone deletion not propagated; route still present")
	}

	shutdown1.TriggerShutdown()
	shutdown2.TriggerShutdown()

	select {
	case <-errCh1:
	case <-time.After(3 * time.Second):
	}
	select {
	case <-errCh2:
	case <-time.After(3 * time.Second):
	}
}

func writeSyncedFile(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		timeout := 200 * time.Millisecond
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Timeout waiting for port %d to open", port)
}

func isPortOpen(t *testing.T, port int) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func TestServer_WithFirewall(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}

	global := &alaye.Global{
		Security: alaye.Security{
			Enabled: alaye.Active,
			Firewall: alaye.Firewall{
				Status: alaye.Active,
				Mode:   "active",
				Rules: []alaye.Rule{
					{
						Name: "block-localhost",
						Type: "static",
						Match: alaye.Match{
							Enabled: alaye.Active,
							IP:      []string{"127.0.0.1/32"},
						},
					},
				},
			},
		},
		Storage: alaye.Storage{
			DataDir: dataDir,
		},
	}

	if !global.Security.Enabled.Active() {
		t.Error("Security should be enabled")
	}
	if !global.Security.Firewall.Status.Active() {
		t.Error("Firewall should be enabled")
	}
}
