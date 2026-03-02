package agbero

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
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
		},
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
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

	time.Sleep(50 * time.Millisecond)
	shutdown.TriggerShutdown()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Unexpected error from Start: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Test timed out waiting for server shutdown")
	}
}

func TestServer_buildTLS(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		global: &alaye.Global{
			LetsEncrypt: alaye.LetsEncrypt{
				Enabled: alaye.Active,
				Email:   "test@example.com",
			},
			Storage: alaye.Storage{
				CertsDir: tmpDir,
			},
		},
		logger:      testLogger,
		hostManager: discovery.NewHost("", discovery.WithLogger(nil)),
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
		hostManager: discovery.NewHost("", discovery.WithLogger(nil)),
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

func TestServer_getOrBuildRouteHandler_CacheHit(t *testing.T) {
	s := &Server{
		global: &alaye.Global{},
		logger: testLogger,
		reaper: jack.NewReaper(time.Minute),
	}

	route := &alaye.Route{
		Enabled:  alaye.Active,
		Path:     "/test",
		Backends: alaye.Backend{Servers: alaye.NewServers("http://localhost:8080")},
	}
	key := route.Key()

	// Pass nil domains
	handler := handlers.NewRoute(&alaye.Global{}, route, nil, testLogger)

	item := &mappo.Item{
		Value: handler,
	}
	item.LastAccessed.Store(time.Now().UnixNano())

	zulu.Route.Store(key, item)

	// Pass nil domains
	h := s.getOrBuildRouteHandler(route, key, nil)
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

	route := &alaye.Route{
		Enabled:  alaye.Active,
		Path:     "/test",
		Backends: alaye.Backend{Servers: alaye.NewServers("http://localhost:8080")},
	}

	zulu.Route.Delete(route.Key())

	// Pass nil domains
	h := s.getOrBuildRouteHandler(route, route.Key(), nil)
	if h == nil {
		t.Error("Handler should be created on cache miss")
	}

	h.Close()
	zulu.Route.Delete(route.Key())
}

func TestServer_StartAdminServer(t *testing.T) {
	global := &alaye.Global{
		Admin: alaye.Admin{
			Address: ":0",
		},
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: hm,
	}

	s.startAdminServer()
	time.Sleep(50 * time.Millisecond)
}

func TestServer_StartAdminServer_NoConfig(t *testing.T) {
	global := &alaye.Global{
		Admin: alaye.Admin{},
	}
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		global:      global,
		logger:      testLogger,
		hostManager: hm,
	}

	s.startAdminServer()
}

func TestServer_HandleRequest_NoHost(t *testing.T) {
	hm := discovery.NewHost("", discovery.WithLogger(testLogger))
	s := &Server{
		hostManager: hm,
		logger:      testLogger,
		reaper:      jack.NewReaper(time.Minute),
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.com"
	w := httptest.NewRecorder()

	s.handleRequest(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for unknown host, got %d", w.Code)
	}
}

func TestServer_HandleRequest_WithHost_And_XForwardedPort(t *testing.T) {
	mockPort := "9999"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if port := r.Header.Get("X-Forwarded-Port"); port != mockPort {
			t.Errorf("Expected X-Forwarded-Port %s, got %s", mockPort, port)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	hostFile := filepath.Join(hostsDir, "example.com.hcl")
	content := `
domains = ["example.com"]
route "/" {
    backend {
        server {
            address = "` + backend.URL + `"
        }
    }
}
`
	if err := os.WriteFile(hostFile, []byte(content), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	if err := hm.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	globalCfg := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{":" + mockPort}},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  t.TempDir(),
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

	ctx := context.WithValue(req.Context(), woos.CtxPort, mockPort)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	s.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
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
			tlsConfig := &zapTLSConfig{}

			s.applyMTLS(&tlsConfig.Config, host)

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

type zapTLSConfig struct {
	tls.Config
}

func TestServer_Reload_DynamicBind(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	os.MkdirAll(hostsDir, 0755)

	hostFile := filepath.Join(hostsDir, "dynamic.hcl")
	// TLS mode "none" to simplify testing (avoids CA generation)
	initialConfig := fmt.Sprintf(`
domains = ["localhost"]
tls { mode = "none" }
route "/" {
  backend {
    server { address = "%s" }
  }
}
`, backend.URL)
	os.WriteFile(hostFile, []byte(initialConfig), 0644)

	configFile := filepath.Join(tmpDir, "agbero.hcl")
	mainPort := getFreePort(t)
	// Give OS time to release mainPort from TIME_WAIT
	time.Sleep(500 * time.Millisecond)

	// Ensure version = 2 is present for parser validation
	globalContent := fmt.Sprintf(`version = 2
bind {
  http = [":%d"]
}
storage {
  hosts_dir = "%s"
  data_dir = "%s"
}
`, mainPort, hostsDir, tmpDir)
	os.WriteFile(configFile, []byte(globalContent), 0644)

	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))
	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))

	// Pre-load hosts to establish initial state
	hm.ReloadFull()

	s := NewServer(
		WithHostManager(hm),
		WithLogger(ll.New("test").Enable()),
		WithShutdownManager(shutdown),
	)

	go s.Start(configFile)
	defer shutdown.TriggerShutdown()

	waitForPort(t, mainPort)

	targetPort := getFreePort(t)
	// Ensure the new target port is actually free before we try to use it
	// If it's still open (race condition), wait a bit
	if isPortOpen(t, targetPort) {
		time.Sleep(500 * time.Millisecond)
		if isPortOpen(t, targetPort) {
			t.Fatalf("Port %d is stuck open", targetPort)
		}
	} else {
		// Even if closed, wait for TIME_WAIT state to clear
		time.Sleep(500 * time.Millisecond)
	}

	// Update host config with new bind.
	// We use just the number here, relying on Server.Start/Reload to handle normalization.
	updatedConfig := fmt.Sprintf(`
domains = ["localhost"]
bind = ["%d"]
tls { mode = "none" }
route "/" {
  backend {
    server { address = "%s" }
  }
}
`, targetPort, backend.URL)
	os.WriteFile(hostFile, []byte(updatedConfig), 0644)

	s.Reload()

	waitForPort(t, targetPort)

	// Use standard HTTP client since we disabled TLS
	client := &http.Client{}

	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("Failed to connect to dynamic port: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
}

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int) {
	// Increased deadline for slower environments/TLS gen
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Timeout waiting for port %d", port)
}

func isPortOpen(t *testing.T, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}
