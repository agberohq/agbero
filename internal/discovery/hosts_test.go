package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("hosts/test").Disable()
)

func validHCL(domain string) []byte {
	return []byte(`
domains = ["` + domain + `"]
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
`)
}

func waitChanged(t *testing.T, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
		return
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for Changed()")
	}
}

func assertNoChanged(t *testing.T, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected Changed() signal")
	case <-time.After(timeout):
		return
	}
}

func TestNewHost_Basic(t *testing.T) {
	h := NewHost(woos.NewFolder("/tmp"))
	if h.hosts == nil || h.lookupMap.Load() == nil || h.clusterRoutes == nil {
		t.Fatal("maps not initialized")
	}
	if h.logger == nil {
		t.Fatal("logger not set")
	}
}

func TestOnClusterChange_Add(t *testing.T) {
	h := NewHost(woos.NewFolder("/tmp"), WithLogger(testLogger))
	defer h.Close()

	route := alaye.Route{
		Path: "/api",
		Backends: alaye.Backend{
			Enabled:  alaye.Active,
			Strategy: alaye.StrategyRandom,
			Servers: []alaye.Server{
				{Address: "http://127.0.0.1:8080", Weight: 1},
			},
		},
	}

	wrapper := ClusterRouteWrapper{Route: route}
	val, _ := json.Marshal(wrapper)

	key := ClusterRoutePrefix + "example.com"
	h.OnClusterChange(key, val, false)

	// Wait for debounced rebuild
	waitChanged(t, h.Changed(), 3*time.Second)

	// Poll for route to be available
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.RouteExists("example.com", "/api") {
			return // Success
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("route not found after deadline")
}

func TestOnClusterChange_Remove(t *testing.T) {
	h := NewHost(woos.NewFolder("/tmp"), WithLogger(testLogger))

	route := alaye.Route{
		Path: "/api",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: []alaye.Server{
				{Address: "http://127.0.0.1:8080"},
			},
		},
	}

	wrapper := ClusterRouteWrapper{Route: route}
	val, _ := json.Marshal(wrapper)
	key := ClusterRoutePrefix + "example.com"

	h.OnClusterChange(key, val, false)
	waitChanged(t, h.Changed(), time.Second)

	h.OnClusterChange(key, nil, true)
	waitChanged(t, h.Changed(), time.Second)

	hosts, _ := h.LoadAll()
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts after remove, got %d", len(hosts))
	}
}

func TestRouteExists(t *testing.T) {
	hm := NewHost(woos.NewFolder(""), WithLogger(testLogger))

	route := alaye.Route{
		Path: "/api",
		Backends: alaye.Backend{
			Servers: []alaye.Server{{Address: "http://10.0.0.1:80"}},
		},
	}
	wrapper := ClusterRouteWrapper{Route: route}
	val, _ := json.Marshal(wrapper)

	hm.OnClusterChange(ClusterRoutePrefix+"example.com", val, false)

	waitChanged(t, hm.Changed(), 2*time.Second)

	if !hm.RouteExists("example.com", "/api") {
		t.Error("route not found")
	}
}

func TestHost_RouteExpiration(t *testing.T) {
	hm := NewHost(woos.Folder("."), WithLogger(testLogger))
	defer hm.Close()

	route := alaye.Route{Path: "/expire", Enabled: alaye.Active}
	// Use longer TTL to ensure route exists after debounced rebuild
	expiry := time.Now().Add(2 * time.Second)

	wrapper := ClusterRouteWrapper{
		Route:     route,
		ExpiresAt: expiry,
	}
	data, _ := json.Marshal(wrapper)

	key := ClusterRoutePrefix + "example.com|/expire"

	hm.OnClusterChange(key, data, false)
	waitChanged(t, hm.Changed(), 3*time.Second)

	if !hm.RouteExists("example.com", "/expire") {
		t.Fatal("route should exist immediately after update")
	}

	// Wait for expiration
	time.Sleep(2500 * time.Millisecond)
	waitChanged(t, hm.Changed(), 3*time.Second)

	if hm.RouteExists("example.com", "/expire") {
		t.Fatal("route should have expired")
	}
}

func TestWatch_FileChange(t *testing.T) {
	tmpDir := t.TempDir()
	hclFile := filepath.Join(tmpDir, "test.hcl")

	if err := os.WriteFile(hclFile, validHCL("example.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	h := NewHost(woos.NewFolder(tmpDir), WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.Get("example.com") == nil {
		t.Fatal("initial load failed")
	}

	if err := os.WriteFile(hclFile, validHCL("updated.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	waitChanged(t, h.Changed(), 5*time.Second)

	if cfg := h.Get("updated.com"); cfg == nil {
		t.Fatal("config not reloaded: updated.com not found")
	}
	if cfg := h.Get("example.com"); cfg != nil {
		t.Fatal("old domain still present after reload")
	}
}

func TestWatch_SubdirFileChange(t *testing.T) {
	tmpDir := t.TempDir()

	sub := filepath.Join(tmpDir, "host.d")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	hclFile := filepath.Join(sub, "agbero.hcl")
	if err := os.WriteFile(hclFile, validHCL("a.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	h := NewHost(woos.NewFolder(tmpDir), WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.Get("a.com") == nil {
		t.Fatal("initial subdir load failed")
	}

	// Give the OS-level watcher a few milliseconds to fully register the directory
	time.Sleep(150 * time.Millisecond)

	// Drain any delayed initial reload events to prevent the test from jumping the gun
	select {
	case <-h.Changed():
	default:
	}

	if err := os.WriteFile(hclFile, validHCL("b.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	waitChanged(t, h.Changed(), 5*time.Second)

	if h.Get("b.com") == nil {
		t.Fatal("subdir change not reloaded: b.com not found")
	}
}

func TestWatch_AtomicReplace(t *testing.T) {
	tmpDir := t.TempDir()
	hclFile := filepath.Join(tmpDir, "test.hcl")

	if err := os.WriteFile(hclFile, validHCL("one.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	h := NewHost(woos.NewFolder(tmpDir), WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.Get("one.com") == nil {
		t.Fatal("initial load failed")
	}

	tmp := filepath.Join(tmpDir, "test.hcl.tmp")
	if err := os.WriteFile(tmp, validHCL("two.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, hclFile); err != nil {
		t.Fatal(err)
	}

	waitChanged(t, h.Changed(), 3*time.Second)

	if h.Get("two.com") == nil {
		t.Fatal("atomic replace not reloaded: two.com not found")
	}
}

func TestWatch_NonHCL_DoesNotTriggerChanged(t *testing.T) {
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "ignore.txt")

	if err := os.WriteFile(txtFile, []byte("test"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	h := NewHost(woos.NewFolder(tmpDir), WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if err := os.WriteFile(txtFile, []byte("updated"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	assertNoChanged(t, h.Changed(), 1200*time.Millisecond)
}

func TestRebuildLookupLocked_MergeFileAndDynamicSamePath(t *testing.T) {
	h := NewHost(woos.NewFolder("/tmp"))
	h.mu.Lock()

	h.hosts["file"] = &alaye.Host{
		Domains: []string{"example.com"},
		Routes: []alaye.Route{
			{
				Path: "/api",
				Backends: alaye.Backend{
					Strategy: alaye.StrategyRoundRobin,
					Servers: []alaye.Server{
						{Address: "http://127.0.0.1:7000", Weight: 1},
					},
				},
			},
		},
	}

	h.clusterRoutes["example.com"] = alaye.Route{
		Path: "/api",
		Backends: alaye.Backend{
			Strategy: alaye.StrategyRandom,
			Servers: []alaye.Server{
				{Address: "http://127.0.0.1:8000", Weight: 1},
			},
		},
	}

	h.rebuildLookupLocked()
	h.mu.Unlock()

	cfg := h.Get("example.com")
	if cfg == nil {
		t.Fatal("expected example.com to exist")
	}

	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes (1 from file, 1 from cluster), got %d", len(cfg.Routes))
	}
}

func TestSortRoutes(t *testing.T) {
	routes := []alaye.Route{
		{Path: "/api"},
		{Path: "/api/v1/users"},
		{Path: "/"},
	}
	hm := NewHost(woos.NewFolder("/tmp"))
	hm.sortRoutes(routes)
	if routes[0].Path != "/api/v1/users" || routes[1].Path != "/api" || routes[2].Path != "/" {
		t.Fatal("routes not sorted by length desc")
	}
}

func TestGet_WildcardResolution(t *testing.T) {
	hm := NewHost(woos.NewFolder("/tmp"))

	wildcardDomain := "*.localhost"

	m := make(map[string]*alaye.Host)
	m[wildcardDomain] = &alaye.Host{
		Domains: []string{wildcardDomain},
	}

	hm.lookupMap.Store(m)

	tests := []struct {
		name      string
		input     string
		shouldHit bool
	}{
		{
			name:      "Exact Wildcard Match",
			input:     "*.localhost",
			shouldHit: true,
		},
		{
			name:      "Subdomain Match 1",
			input:     "api.localhost",
			shouldHit: true,
		},
		{
			name:      "Subdomain Match 2",
			input:     "app.service.localhost",
			shouldHit: true,
		},
		{
			name:      "Non-matching Domain",
			input:     "api.otherhost",
			shouldHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hm.Get(tt.input)
			if tt.shouldHit && got == nil {
				t.Fatalf("Expected to find host for '%s' via wildcard '%s', but got nil", tt.input, wildcardDomain)
			}
			if !tt.shouldHit && got != nil {
				t.Fatalf("Expected nil for '%s', but got a host", tt.input)
			}
		})
	}
}

func TestHost_OnClusterChange_RoutePropagation(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	logger := ll.New("test").Disable()
	hm := NewHost(woos.NewFolder(hostsDir), WithLogger(logger))

	route := alaye.Route{
		Enabled: alaye.Active,
		Path:    "/api/test",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:9000"),
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

	key := fmt.Sprintf("%s%s|%s", ClusterRoutePrefix, "test.example.com", "/api/test")
	hm.OnClusterChange(key, val, false)

	waitChanged(t, hm.Changed(), 2*time.Second)

	host := hm.Get("test.example.com")
	if host == nil {
		t.Fatal("Host not created after cluster route update")
	}

	found := false
	for _, r := range host.Routes {
		if r.Path == "/api/test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Route not added to host after OnClusterChange")
	}
}

func TestHost_OnClusterChange_Deletion(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	logger := ll.New("test").Disable()
	hm := NewHost(woos.NewFolder(hostsDir), WithLogger(logger))

	route := alaye.Route{
		Enabled: alaye.Active,
		Path:    "/to-delete",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:9001"),
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

	key := fmt.Sprintf("%s%s|%s", ClusterRoutePrefix, "delete.example.com", "/to-delete")
	hm.OnClusterChange(key, val, false)
	waitChanged(t, hm.Changed(), 2*time.Second)

	host := hm.Get("delete.example.com")
	if host == nil {
		t.Fatal("Host not created")
	}

	hm.OnClusterChange(key, nil, true)
	waitChanged(t, hm.Changed(), 2*time.Second)

	hostAfter := hm.Get("delete.example.com")
	if hostAfter != nil {
		for _, r := range hostAfter.Routes {
			if r.Path == "/to-delete" {
				t.Error("Route still present after deletion")
			}
		}
	}
}

func TestCluster_ConfigDeletionPropagation(t *testing.T) {
	logger := ll.New("test").Disable()

	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	port1 := zulu.PortFree()
	port2 := zulu.PortFree()

	// Node 1
	h1 := NewHost(woos.NewFolder(tmpDir1), WithLogger(logger))
	cm1, _ := cluster.NewManager(cluster.Config{
		Name:     "node1",
		BindAddr: "127.0.0.1",
		BindPort: port1,
		HostsDir: tmpDir1,
	}, h1, logger)
	defer cm1.Shutdown()
	h1.clusterMgr = cm1
	h1.configSync = NewConfigSync(h1.logger, cm1)

	// Node 2
	h2 := NewHost(woos.NewFolder(tmpDir2), WithLogger(logger))
	cm2, _ := cluster.NewManager(cluster.Config{
		Name:     "node2",
		BindAddr: "127.0.0.1",
		BindPort: port2,
		Seeds:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
		HostsDir: tmpDir2,
	}, h2, logger)
	defer cm2.Shutdown()
	h2.clusterMgr = cm2
	h2.configSync = NewConfigSync(h2.logger, cm2)

	time.Sleep(2 * time.Second)

	// Create and broadcast config
	domain := "delete-me.com"
	content := validHCL(domain)
	configPath := filepath.Join(tmpDir1, domain+".hcl")
	os.WriteFile(configPath, content, woos.FilePerm)
	cm1.BroadcastConfig(domain, content, false)

	time.Sleep(2 * time.Second)

	// Verify both nodes have the config
	if _, err := os.Stat(filepath.Join(tmpDir2, domain+".hcl")); os.IsNotExist(err) {
		t.Fatal("node2 should have config before deletion")
	}

	// Delete config on node 1
	os.Remove(configPath)
	cm1.BroadcastConfig(domain, nil, true)

	time.Sleep(2 * time.Second)

	// Verify node 2 also deleted the config
	if _, err := os.Stat(filepath.Join(tmpDir2, domain+".hcl")); !os.IsNotExist(err) {
		t.Error("node2 should have deleted config after cluster broadcast")
	}
}

func TestHost_OnClusterChange_WithTTL(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	logger := ll.New("test").Disable()
	hm := NewHost(woos.NewFolder(hostsDir), WithLogger(logger))
	defer hm.Close()

	route := alaye.Route{
		Enabled: alaye.Active,
		Path:    "/ephemeral",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers("http://localhost:9002"),
		},
	}

	// TTL must be > debounce delay (500ms) + margin for rebuild
	wrapper := struct {
		Route     alaye.Route `json:"route"`
		ExpiresAt time.Time   `json:"expires_at"`
	}{
		Route:     route,
		ExpiresAt: time.Now().Add(1500 * time.Millisecond),
	}
	val, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("Failed to marshal route: %v", err)
	}

	key := fmt.Sprintf("%s%s|%s", ClusterRoutePrefix, "ttl.example.com", "/ephemeral")
	hm.OnClusterChange(key, val, false)

	// Wait for initial add
	waitChanged(t, hm.Changed(), 2*time.Second)

	if !hm.RouteExists("ttl.example.com", "/ephemeral") {
		t.Fatal("Route should exist after add")
	}

	// Poll for expiration with timeout
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !hm.RouteExists("ttl.example.com", "/ephemeral") {
			return // Success - route expired
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("TTL route still present after expiration deadline")
}

func TestCluster_3NodeDataPropagation(t *testing.T) {
	logger := ll.New("test").Disable()

	// Create 3 temp directories for 3 nodes
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()
	tmpDir3 := t.TempDir()

	// Get free ports
	port1 := zulu.PortFree()
	port2 := zulu.PortFree()
	port3 := zulu.PortFree()

	t.Logf("Node1 port: %d, Node2 port: %d, Node3 port: %d", port1, port2, port3)

	// Create node 1 (seed)
	h1 := NewHost(woos.NewFolder(tmpDir1), WithLogger(logger))
	cm1, err := cluster.NewManager(cluster.Config{
		Name:     "node1",
		BindAddr: "127.0.0.1",
		BindPort: port1,
		HostsDir: tmpDir1,
	}, h1, logger)
	if err != nil {
		t.Fatalf("failed to create cluster manager 1: %v", err)
	}
	defer cm1.Shutdown()
	h1.clusterMgr = cm1
	h1.configSync = NewConfigSync(h1.logger, cm1)

	// Create node 2 (joins node 1)
	h2 := NewHost(woos.NewFolder(tmpDir2), WithLogger(logger))
	cm2, err := cluster.NewManager(cluster.Config{
		Name:     "node2",
		BindAddr: "127.0.0.1",
		BindPort: port2,
		Seeds:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
		HostsDir: tmpDir2,
	}, h2, logger)
	if err != nil {
		t.Fatalf("failed to create cluster manager 2: %v", err)
	}
	defer cm2.Shutdown()
	h2.clusterMgr = cm2
	h2.configSync = NewConfigSync(h2.logger, cm2)

	// Create node 3 (joins node 1)
	h3 := NewHost(woos.NewFolder(tmpDir3), WithLogger(logger))
	cm3, err := cluster.NewManager(cluster.Config{
		Name:     "node3",
		BindAddr: "127.0.0.1",
		BindPort: port3,
		Seeds:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
		HostsDir: tmpDir3,
	}, h3, logger)
	if err != nil {
		t.Fatalf("failed to create cluster manager 3: %v", err)
	}
	defer cm3.Shutdown()
	h3.clusterMgr = cm3
	h3.configSync = NewConfigSync(h3.logger, cm3)

	// Wait for cluster to form with timeout
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(cm1.Members()) == 3 && len(cm2.Members()) == 3 && len(cm3.Members()) == 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("Cluster formed: node1=%d, node2=%d, node3=%d members", len(cm1.Members()), len(cm2.Members()), len(cm3.Members()))

	// Verify all nodes see each other
	if len(cm1.Members()) != 3 {
		t.Fatalf("node1 expected 3 members, got %d", len(cm1.Members()))
	}

	// Create a config file on node 1
	domain := "shared.com"
	content := validHCL(domain)
	configPath := filepath.Join(tmpDir1, domain+".hcl")
	if err := os.WriteFile(configPath, content, woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	t.Logf("Created config on node1, broadcasting...")

	// Trigger broadcast from node 1
	if h1.configSync.ShouldBroadcast(domain, content) {
		if err := cm1.BroadcastConfig(domain, content, false); err != nil {
			t.Fatalf("broadcast failed: %v", err)
		}
		t.Logf("Broadcast sent from node1")
	} else {
		t.Logf("ShouldBroadcast returned false - checksum already exists")
	}

	// Wait for gossip propagation with timeout
	propagationDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(propagationDeadline) {
		configPath2 := filepath.Join(tmpDir2, domain+".hcl")
		configPath3 := filepath.Join(tmpDir3, domain+".hcl")
		_, err2 := os.Stat(configPath2)
		_, err3 := os.Stat(configPath3)
		if err2 == nil && err3 == nil {
			t.Logf("Both Node2 and Node3 received config")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Verify node 2 received the config
	configPath2 := filepath.Join(tmpDir2, domain+".hcl")
	if _, err := os.Stat(configPath2); os.IsNotExist(err) {
		t.Error("node2 did not receive config from cluster")
	} else {
		// Verify content matches
		data, _ := os.ReadFile(configPath2)
		if !bytes.Equal(data, content) {
			t.Error("node2 config content mismatch")
		} else {
			t.Logf("Node2 config verified")
		}
	}

	// Verify node 3 received the config
	configPath3 := filepath.Join(tmpDir3, domain+".hcl")
	if _, err := os.Stat(configPath3); os.IsNotExist(err) {
		t.Error("node3 did not receive config from cluster")
	} else {
		data, _ := os.ReadFile(configPath3)
		if !bytes.Equal(data, content) {
			t.Error("node3 config content mismatch")
		} else {
			t.Logf("Node3 config verified")
		}
	}
}
