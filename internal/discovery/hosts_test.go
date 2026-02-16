package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
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
		// Debouncer fires the action in a goroutine, then notifies.
		// A tiny sleep ensures the map swap is fully visible to the test reader.
		time.Sleep(10 * time.Millisecond)
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
	h := NewHost("/tmp")
	if h.hosts == nil || h.lookupMap == nil || h.dynamicRoutes == nil || h.nodeIndex == nil || h.nodeFailures == nil {
		t.Fatal("maps not initialized")
	}
	if h.logger == nil {
		t.Fatal("logger not set")
	}
}

func TestUpdateGossipNode(t *testing.T) {
	h := NewHost("/tmp", WithLogger(testLogger))

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

	h.UpdateGossipNode("node1", "example.com", route)

	// FIX: Wait for async rebuild
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

func TestRemoveGossipNode(t *testing.T) {
	h := NewHost("/tmp", WithLogger(testLogger))

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

	h.UpdateGossipNode("node1", "example.com", route)
	waitChanged(t, h.Changed(), time.Second)

	h.RemoveGossipNode("node1")
	waitChanged(t, h.Changed(), time.Second)

	hosts, _ := h.LoadAll()
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts after remove, got %d", len(hosts))
	}
}

func TestRouteExists(t *testing.T) {
	hm := NewHost("", WithLogger(testLogger))

	hm.UpdateGossipNode("node1", "example.com", alaye.Route{
		Path: "/api",
		Backends: alaye.Backend{
			Servers: []alaye.Server{{Address: "http://10.0.0.1:80"}},
		},
	})

	waitChanged(t, hm.Changed(), 2*time.Second)

	if !hm.RouteExists("example.com", "/api") {
		t.Error("route not found")
	}
}

func TestResetNodeFailures(t *testing.T) {
	h := NewHost("/tmp")
	h.mu.Lock()
	h.nodeFailures["node1"] = 5
	h.mu.Unlock()

	h.ResetNodeFailures("node1")

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.nodeFailures["node1"] != 0 {
		t.Fatal("failures not reset")
	}
}

func TestWatch_FileChange(t *testing.T) {
	tmpDir := t.TempDir()
	hclFile := filepath.Join(tmpDir, "test.hcl")

	if err := os.WriteFile(hclFile, validHCL("example.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	h := NewHost(tmpDir, WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.Get("example.com") == nil {
		t.Fatal("initial load failed")
	}

	// Trigger change
	if err := os.WriteFile(hclFile, validHCL("updated.com"), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	waitChanged(t, h.Changed(), 3*time.Second)

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

	h := NewHost(tmpDir, WithLogger(testLogger))
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

	h := NewHost(tmpDir, WithLogger(testLogger))
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

	h := NewHost(tmpDir, WithLogger(testLogger))
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
	h := NewHost("/tmp")
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

	rk := routeKey{host: "example.com", path: "/api"}
	h.dynamicRoutes[rk] = &routeEntry{
		base: alaye.Route{
			Path: "/api",
			Backends: alaye.Backend{
				Enabled:  alaye.Active,
				Strategy: alaye.StrategyRandom,
			},
			HealthCheck: alaye.HealthCheck{
				Enabled: alaye.Active,
				Path:    "/",
			},
		},
		backends: map[string][]alaye.Server{
			"node1": {
				{Address: "http://127.0.0.1:8000", Weight: 1},
			},
		},
		lastWrite: time.Now(),
	}

	h.rebuildLookupLocked()
	h.mu.Unlock()

	cfg := h.Get("example.com")
	if cfg == nil {
		t.Fatal("expected example.com to exist")
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(cfg.Routes))
	}
	// The file backend + dynamic backend = 2 servers
	if got := len(cfg.Routes[0].Backends.Servers); got != 2 {
		t.Fatalf("expected merged 2 backend servers, got %d", got)
	}
}

func TestSortRoutes(t *testing.T) {
	routes := []alaye.Route{
		{Path: "/api"},
		{Path: "/api/v1/users"},
		{Path: "/"},
	}
	hm := NewHost("/tmp")
	hm.sortRoutes(routes)
	if routes[0].Path != "/api/v1/users" || routes[1].Path != "/api" || routes[2].Path != "/" {
		t.Fatal("routes not sorted by length desc")
	}
}

func TestGet_WildcardResolution(t *testing.T) {
	hm := NewHost("/tmp")

	wildcardDomain := "*.localhost"
	hm.mu.Lock()
	hm.lookupMap[wildcardDomain] = &alaye.Host{
		Domains: []string{wildcardDomain},
	}
	hm.mu.Unlock()

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
