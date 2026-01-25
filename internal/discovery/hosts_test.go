package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("hosts/test")
)

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
	h := NewHost("/tmp")
	if h.hosts == nil || h.lookupMap == nil || h.gossipRoutes == nil || h.nodeFailures == nil {
		t.Fatal("maps not initialized")
	}
	if h.logger == nil {
		t.Fatal("logger not set")
	}
}

func TestUpdateGossipNode(t *testing.T) {
	h := NewHost("/tmp", WithLogger(testLogger))
	route := alaye.Route{Path: "/api"}
	h.UpdateGossipNode("node1", "example.com", route)

	hosts, _ := h.LoadAll()
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host in snapshot, got %d", len(hosts))
	}
	if cfg := h.Get("example.com"); cfg == nil || len(cfg.Routes) != 1 {
		t.Fatal("route not added")
	}
}

func TestRemoveGossipNode(t *testing.T) {
	h := NewHost("/tmp")
	route := alaye.Route{Path: "/api"}
	h.UpdateGossipNode("node1", "example.com", route)
	h.RemoveGossipNode("node1")

	hosts, _ := h.LoadAll()
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts after remove, got %d", len(hosts))
	}
}

func TestRouteExists(t *testing.T) {
	h := NewHost("/tmp")
	route := alaye.Route{Path: "/api"}
	h.UpdateGossipNode("node1", "example.com", route)

	if !h.RouteExists("example.com", "/api") {
		t.Fatal("route not found")
	}
	if h.RouteExists("example.com", "/other") {
		t.Fatal("unexpected route found")
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

	if err := os.WriteFile(hclFile, []byte(`domains = ["example.com"]`), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost(tmpDir, WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Trigger change
	if err := os.WriteFile(hclFile, []byte(`domains = ["updated.com"]`), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce (500ms) + fsnotify jitter.
	waitChanged(t, h.Changed(), 3*time.Second)

	// IMPORTANT: lookup is by domain, not by filename.
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
	if err := os.WriteFile(hclFile, []byte(`domains = ["a.com"]`), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost(tmpDir, WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if err := os.WriteFile(hclFile, []byte(`domains = ["b.com"]`), 0644); err != nil {
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

	if err := os.WriteFile(hclFile, []byte(`domains = ["one.com"]`), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost(tmpDir, WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Simulate editor "atomic save": write temp then rename over original.
	tmp := filepath.Join(tmpDir, "test.hcl.tmp")
	if err := os.WriteFile(tmp, []byte(`domains = ["two.com"]`), 0644); err != nil {
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

	if err := os.WriteFile(txtFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	h := NewHost(tmpDir, WithLogger(testLogger))
	if err := h.Watch(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Change non-HCL: should not trigger Changed() at all.
	if err := os.WriteFile(txtFile, []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}

	// Give some time for fsnotify to emit events if it would.
	assertNoChanged(t, h.Changed(), 1200*time.Millisecond)
}

func TestRebuildLookupLocked_DedupFileGossip(t *testing.T) {
	h := NewHost("/tmp")
	h.mu.Lock()

	// File host
	h.hosts["file"] = &alaye.Host{
		Domains: []string{"example.com"},
		Routes:  []alaye.Route{{Path: "/api"}},
	}

	// Gossip same
	h.gossipRoutes["node1"] = DynamicRouteItem{
		Host:  "example.com",
		Route: alaye.Route{Path: "/api"},
	}

	h.rebuildLookupLocked()
	h.mu.Unlock()

	cfg := h.Get("example.com")
	if cfg == nil {
		t.Fatal("expected example.com to exist")
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 route (deduplicated), got %d", len(cfg.Routes))
	}
}

func TestSortRoutes(t *testing.T) {
	routes := []alaye.Route{
		{Path: "/api"},
		{Path: "/api/v1/users"},
		{Path: "/"},
	}
	sortRoutes(routes)
	if routes[0].Path != "/api/v1/users" || routes[1].Path != "/api" || routes[2].Path != "/" {
		t.Fatal("routes not sorted by length desc")
	}
}
