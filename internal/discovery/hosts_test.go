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

func TestNewHost_Basic(t *testing.T) {
	h := NewHost("/tmp")
	if h.hosts == nil || h.lookupMap == nil || h.gossipRoutes == nil || h.nodeFailures == nil {
		t.Error("Maps not initialized")
	}
	if h.logger == nil {
		t.Error("Logger not set")
	}
}

func TestUpdateGossipNode(t *testing.T) {
	h := NewHost("/tmp", WithLogger(testLogger))
	route := alaye.Route{Path: "/api"}
	h.UpdateGossipNode("node1", "example.com", route)

	hosts, _ := h.LoadAll()
	if len(hosts) != 1 {
		t.Error("Host not added")
	}
	if cfg := h.Get("example.com"); cfg == nil || len(cfg.Routes) != 1 {
		t.Error("Route not added")
	}
}

func TestRemoveGossipNode(t *testing.T) {
	h := NewHost("/tmp")
	route := alaye.Route{Path: "/api"}
	h.UpdateGossipNode("node1", "example.com", route)
	h.RemoveGossipNode("node1")

	hosts, _ := h.LoadAll()
	if len(hosts) != 0 {
		t.Error("Host not removed")
	}
}

func TestRouteExists(t *testing.T) {
	h := NewHost("/tmp")
	route := alaye.Route{Path: "/api"}
	h.UpdateGossipNode("node1", "example.com", route)

	if !h.RouteExists("example.com", "/api") {
		t.Error("Route not found")
	}
	if h.RouteExists("example.com", "/other") {
		t.Error("Unexpected route found")
	}
}

func TestResetNodeFailures(t *testing.T) {
	h := NewHost("/tmp")
	h.mu.Lock()
	h.nodeFailures["node1"] = 5
	h.mu.Unlock()

	h.ResetNodeFailures("node1")

	h.mu.RLock()
	if h.nodeFailures["node1"] != 0 {
		t.Error("Failures not reset")
	}
	h.mu.RUnlock()
}

func TestWatch_FileChange(t *testing.T) {
	tmpDir := t.TempDir()
	hclFile := filepath.Join(tmpDir, "test.hcl")
	os.WriteFile(hclFile, []byte(`domains = ["example.com"]`), 0644)

	h := NewHost(tmpDir, WithLogger(testLogger))
	err := h.Watch()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Trigger change
	os.WriteFile(hclFile, []byte(`domains = ["updated.com"]`), 0644)

	// Wait for debounce (500ms) + buffer. Increased to 1500ms for slow runners.
	time.Sleep(1500 * time.Millisecond)

	hosts, _ := h.LoadAll()
	if _, ok := hosts["updated.com"]; !ok {
		t.Error("Config not reloaded")
	}
}

func TestWatch_NonHCL(t *testing.T) {
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "ignore.txt")
	os.WriteFile(txtFile, []byte("test"), 0644)

	h := NewHost(tmpDir)
	h.Watch()
	defer h.Close()

	// Change non-HCL
	os.WriteFile(txtFile, []byte("updated"), 0644)
	time.Sleep(600 * time.Millisecond)

	hosts, _ := h.LoadAll()
	if len(hosts) != 0 {
		t.Error("Non-HCL triggered reload")
	}
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
	if len(cfg.Routes) != 1 {
		t.Errorf("Expected 1 route (deduplicated), got %d", len(cfg.Routes))
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
		t.Error("Routes not sorted by length desc")
	}
}
