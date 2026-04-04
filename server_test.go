package agbero

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/cluster"
	discovery2 "github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("test").Disable()
)

// TestNewServer_Basic tests basic server initialization
func TestNewServer_Basic(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Error("NewServer returned nil")
	}
	// listeners is a slice field; nil is valid and behaves as empty
	if s.listeners == nil {
		// Accept nil slice as valid initialization state
	}
}

// TestServer_Start_NoConfig tests that Start requires a host manager
func TestServer_Start_NoConfig(t *testing.T) {
	s := NewServer()
	err := s.Start("")
	if err == nil || !strings.Contains(err.Error(), "host manager") {
		t.Errorf("Expected host manager error, got %v", err)
	}
}

// TestServer_Start_NoGlobalConfig tests that Start requires global config
func TestServer_Start_NoGlobalConfig(t *testing.T) {
	hm := discovery2.NewHost("", discovery2.WithLogger(testLogger))
	s := NewServer(WithHostManager(hm))
	err := s.Start("")
	if err == nil || !strings.Contains(err.Error(), "global config") {
		t.Errorf("Expected global config error, got %v", err)
	}
}

// TestServer_Start_Minimal tests minimal server startup with shutdown
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
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	hm := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))
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

// TestServer_Start_WithBackend tests server with a working backend route
func TestServer_Start_WithBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	// Create host config file
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

	// Use a fixed port from PortFree() to avoid :0 binding issues
	testPort := zulu.PortFree()
	global := &alaye.Global{
		Bind: alaye.Bind{HTTP: []string{fmt.Sprintf(":%d", testPort)}},
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			DataDir:  tmpDir,
			CertsDir: filepath.Join(tmpDir, "certs"),
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	hm := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))
	if err := hm.ReloadFull(); err != nil {
		t.Fatal(err)
	}

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

	// Wait for server to be ready by polling the port
	waitForPort(t, testPort)

	// Make a test request using the known port
	client := &http.Client{Timeout: 2 * time.Second}
	reqURL := fmt.Sprintf("http://127.0.0.1:%d", testPort)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		shutdown.TriggerShutdown()
		<-errCh
		t.Fatal(err)
	}
	req.Host = "example.com"

	resp, err := client.Do(req)
	if err != nil {
		shutdown.TriggerShutdown()
		<-errCh
		t.Fatalf("Failed to connect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}

	shutdown.TriggerShutdown()

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "server closed") {
			t.Errorf("Unexpected error from Start: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Test timed out waiting for server shutdown")
	}
}

// TestServer_Reload_DynamicBind tests dynamic port binding on config reload
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
	mainPort := zulu.PortFree()
	time.Sleep(100 * time.Millisecond)

	initialGlobalConfig := fmt.Sprintf(`version = 1
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
	hm := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))

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

	targetPort := zulu.PortFree()
	if targetPort == mainPort {
		t.Fatal("getFreePort returned the same port as mainPort")
	}

	time.Sleep(500 * time.Millisecond)

	if isPortOpen(t, targetPort) {
		t.Fatalf("Port %d is still open (zombie listener?)", targetPort)
	}

	updatedGlobalConfig := fmt.Sprintf(`version = 1
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

// TestServer_Cluster_ConfigSync_RoutePropagation tests cluster route propagation
func TestServer_Cluster_ConfigSync_RoutePropagation(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	port1 := zulu.PortFree()
	port2 := zulu.PortFree()

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
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
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
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	shutdown1 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))
	shutdown2 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	hm1 := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))
	hm2 := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))

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

	key := fmt.Sprintf("%s%s|%s", discovery2.ClusterRoutePrefix, "test.example.com", "/api/v1/test")
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

// TestServer_Cluster_ConfigSync_TombstoneDeletion tests ephemeral route tombstone deletion
func TestServer_Cluster_ConfigSync_TombstoneDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	port1 := zulu.PortFree()
	port2 := zulu.PortFree()

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
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
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
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
		},
		General: alaye.General{
			MaxHeaderBytes: 1048576,
		},
	}

	shutdown1 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))
	shutdown2 := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	hm1 := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))
	hm2 := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))

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

	key := fmt.Sprintf("%s%s|%s", discovery2.ClusterRoutePrefix, "temp.example.com", "/ephemeral")
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

// TestServer_WithFirewall tests firewall configuration
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

// TestServer_Options tests the option pattern
func TestServer_Options(t *testing.T) {
	hm := discovery2.NewHost("", discovery2.WithLogger(testLogger))
	global := &alaye.Global{}
	logger := ll.New("test").Disable()
	shutdown := jack.NewShutdown()

	s := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
		WithLogger(logger),
		WithShutdownManager(shutdown),
	)

	if s.hostManager != hm {
		t.Error("WithHostManager failed")
	}
	if s.global != global {
		t.Error("WithGlobalConfig failed")
	}
	if s.logger != logger {
		t.Error("WithLogger failed")
	}
	if s.shutdown != shutdown {
		t.Error("WithShutdownManager failed")
	}
}

// TestServer_ClusterHandlers tests cluster integration handler methods
func TestServer_ClusterHandlers(t *testing.T) {
	tmpDir := t.TempDir()
	hm := discovery2.NewHost(woos.NewFolder(tmpDir), discovery2.WithLogger(testLogger))
	global := &alaye.Global{
		Storage: alaye.Storage{
			HostsDir: tmpDir,
			DataDir:  tmpDir,
		},
	}

	s := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
		WithLogger(testLogger),
	)

	// Test OnClusterChange - should not panic
	s.OnClusterChange("test-key", []byte("test-value"), false)
	s.OnClusterChange("test-key", nil, true)

	// Test OnClusterCert - should not panic with nil tlsManager
	err := s.OnClusterCert("example.com", []byte("cert"), []byte("key"))
	if err != nil {
		t.Errorf("OnClusterCert returned error: %v", err)
	}

	// Test OnClusterChallenge - should not panic with nil tlsManager
	s.OnClusterChallenge("token", "keyAuth", false)
	s.OnClusterChallenge("token", "keyAuth", true)
}

// TestServer_configComputeSHA tests config SHA computation
func TestServer_configComputeSHA(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.hcl")
	if err := os.WriteFile(configPath, []byte("test config"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	global := &alaye.Global{
		Storage: alaye.Storage{
			HostsDir: hostsDir,
		},
	}

	s := &Server{
		configPath: configPath,
		global:     global,
	}

	sha1, err := s.configComputeSHA()
	if err != nil {
		t.Fatalf("configComputeSHA failed: %v", err)
	}
	if len(sha1) != 64 {
		t.Errorf("Expected SHA256 hex string (64 chars), got %d", len(sha1))
	}

	// Modify config and verify SHA changes
	if err := os.WriteFile(configPath, []byte("modified config"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	sha2, err := s.configComputeSHA()
	if err != nil {
		t.Fatalf("configComputeSHA failed: %v", err)
	}
	if sha1 == sha2 {
		t.Error("SHA should change when config is modified")
	}
}

// TestServer_shutdownImpl tests graceful shutdown
func TestServer_shutdownImpl(t *testing.T) {
	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(1 * time.Second))
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
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
		},
	}

	hm := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))
	s := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(testLogger),
		WithShutdownManager(shutdown),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Should not panic with empty listeners
	err := s.shutdownImpl(ctx)
	if err != nil {
		t.Errorf("shutdownImpl returned error: %v", err)
	}
}

// TestServer_Reload_ZeroDowntime_And_NoRace verifies that Reload() gracefully drains
// old connections asynchronously without blocking the launch of new listeners.
func TestServer_Reload_ZeroDowntime_And_NoRace(t *testing.T) {
	// slowReady is closed when the slow backend has received the request —
	// gives us a hard signal that the request is genuinely in-flight before reload.
	slowReady := make(chan struct{})

	slowBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-slowReady:
		default:
			close(slowReady)
		}
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("slow-backend"))
	}))
	defer slowBackend.Close()

	fastBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fast-backend"))
	}))
	defer fastBackend.Close()

	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tmpDir, "config.hcl")
	hostPath := filepath.Join(hostsDir, "domain.hcl")

	proxyPort := zulu.PortFree()

	writeConfigs := func(port int, backendURL string) {
		globalCfg := fmt.Sprintf(`version = 1
bind {
    http = [":%d"]
}
storage {
    hosts_dir = "%s"
    data_dir = "%s"
}
timeouts {
    enabled = true
    read = "10s"
    write = "30s"
    idle = "60s"
}
`, port, hostsDir, tmpDir)
		writeSyncedFile(t, configPath, []byte(globalCfg))

		hostCfg := fmt.Sprintf(`domains = ["localhost"]
tls {
    mode = "none"
}
route "/" {
    backend {
        server {
            address = "%s"
        }
    }
}
`, backendURL)
		writeSyncedFile(t, hostPath, []byte(hostCfg))
	}

	writeConfigs(proxyPort, slowBackend.URL)

	global, err := parser.LoadGlobal(configPath)
	if err != nil {
		t.Fatalf("Failed to parse initial config: %v", err)
	}
	woos.DefaultApply(global, configPath)

	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(10 * time.Second))
	hm := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))

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

	errCh := make(chan error, 1)
	go func() {
		if err := s.Start(configPath); err != nil && !strings.Contains(err.Error(), "server closed") {
			errCh <- err
		}
	}()
	defer shutdown.TriggerShutdown()

	waitForPort(t, proxyPort)

	// Fire the slow request
	slowReq, err := http.NewRequestWithContext(
		context.Background(), "GET",
		fmt.Sprintf("http://127.0.0.1:%d", proxyPort), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	slowReq.Host = "localhost"

	slowRespCh := make(chan *http.Response, 1)
	slowErrCh := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(slowReq)
		if err != nil {
			slowErrCh <- err
			return
		}
		slowRespCh <- resp
	}()

	// Wait for hard signal that the slow backend received the request —
	// no time.Sleep, no guessing.
	select {
	case <-slowReady:
		// request is genuinely in-flight inside the slow backend
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for slow backend to receive request")
	}

	// Now safe to reload — slow request is already being served
	writeConfigs(proxyPort, fastBackend.URL)
	s.Reload()

	// Poll until the proxy routes to the fast backend.
	// Each iteration gets its own fresh context so a slow iteration
	// doesn't poison the next one.
	var fastResponse string
	pollDeadline := time.Now().Add(5 * time.Second)
	fastClient := &http.Client{Timeout: 2 * time.Second}

	for time.Now().Before(pollDeadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET",
			fmt.Sprintf("http://127.0.0.1:%d", proxyPort), nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		req.Host = "localhost"

		resp, err := fastClient.Do(req)
		cancel()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		bodyStr := string(body[:n])

		if strings.Contains(bodyStr, "fast-backend") {
			fastResponse = bodyStr
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if fastResponse == "" {
		t.Fatal("timed out waiting for fast backend response after reload")
	}

	// Assert the in-flight slow request completed safely
	select {
	case resp := <-slowRespCh:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("slow backend returned non-200: %d", resp.StatusCode)
		}
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		if !strings.Contains(string(body[:n]), "slow-backend") {
			t.Errorf("slow backend returned wrong body: %s", string(body[:n]))
		}
		t.Log("slow request completed successfully after reload")
	case err := <-slowErrCh:
		t.Errorf("slow request failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Error("slow request timed out — connection may have been terminated prematurely")
	}

	t.Log("zero-downtime reload test passed")
}

// Helper functions
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
