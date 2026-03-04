package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("hosts/test").Disable()
)

// Helper to write valid HCL content
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
		time.Sleep(20 * time.Millisecond)
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

	// Simulate cluster update: route:example.com|/api
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

	h.OnClusterChange(key, nil, true) // Delete
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

	// Dynamic overwrite
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

	// With the new logic, file + dynamic with same path might append or override based on sort.
	// Since we append both to domainToRoutes and then sort, we should see both backends if merged
	// or distinct routes if logic differs.
	// In rebuildLookupLocked:
	// 1. File routes added.
	// 2. Cluster routes added.
	// 3. Merged.

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

	// Create map matching atomic structure
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
