package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
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

	wrapper := routeWrapper{Route: route}
	val, _ := json.Marshal(wrapper)

	key := ClusterRoutePrefix + "example.com"
	h.OnClusterChange(key, val, false)

	waitChanged(t, h.Changed(), time.Second)

	hosts, _ := h.LoadAll()
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host in snapshot, got %d", len(hosts))
	}

	if cfg := h.Get("example.com"); cfg == nil || len(cfg.Routes) != 1 {
		t.Fatal("route not added")
	}

	if cfg := h.Get("example.com"); cfg != nil {
		if got := len(cfg.Routes[0].Backends.Servers); got != 1 {
			t.Fatalf("expected 1 backend server, got %d", got)
		}
	}
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

	wrapper := routeWrapper{Route: route}
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
	wrapper := routeWrapper{Route: route}
	val, _ := json.Marshal(wrapper)

	hm.OnClusterChange(ClusterRoutePrefix+"example.com", val, false)

	waitChanged(t, hm.Changed(), 2*time.Second)

	if !hm.RouteExists("example.com", "/api") {
		t.Error("route not found")
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

	if err := os.WriteFile(hclFile, validHCL("b.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	waitChanged(t, h.Changed(), 3*time.Second)

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

func TestHost_RouteExpiration(t *testing.T) {
	hm := NewHost(woos.Folder("."), WithLogger(testLogger))
	defer hm.Close()

	route := alaye.Route{Path: "/expire", Enabled: alaye.Active}
	// Use longer TTL to ensure route exists after debounced rebuild
	expiry := time.Now().Add(2 * time.Second)

	wrapper := routeWrapper{
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
