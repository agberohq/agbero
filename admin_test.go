package agbero

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
)

// Mock host manager to simulate loaded hosts
func mockHostManager(t *testing.T) *discovery.Host {
	hm := discovery.NewHost("")

	// Create a dummy host config
	host := alaye.NewStaticHost("test.local", "http://backend:8080", true)
	host.Routes[0].Path = "/api"

	// Manually inject into host manager
	// Note: In real usage we use LoadStatic, but for this test we'll rely on
	// LoadAll returning the internal map which LoadStatic populates.
	hostsMap := map[string]*alaye.Host{
		"test.local": host,
	}
	hm.LoadStatic(hostsMap)

	return hm
}

func TestAdminConfigDumpStructure(t *testing.T) {
	// Setup server dependencies
	hm := mockHostManager(t)
	global := alaye.NewEphemeralGlobal(8080, false)

	// Create server instance
	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
	)

	// Create request
	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	// Call the handler directly
	srv.handleAdminConfigDump(w, req)

	// Validate response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify Global structure
	if _, ok := data["global"]; !ok {
		t.Error("Missing 'global' key in config dump")
	}

	// Verify Hosts structure (critical for graph visualization)
	hostsRaw, ok := data["hosts"]
	if !ok {
		t.Fatal("Missing 'hosts' key in config dump")
	}

	hosts, ok := hostsRaw.(map[string]interface{})
	if !ok {
		t.Fatal("'hosts' is not a map")
	}

	testHost, ok := hosts["test.local"]
	if !ok {
		t.Fatal("Expected host 'test.local' missing")
	}

	hostMap, ok := testHost.(map[string]interface{})
	if !ok {
		t.Fatal("Host entry is not a map")
	}

	// Check routes array exists
	routesRaw, ok := hostMap["routes"]
	if !ok {
		t.Fatal("Host missing 'routes' array")
	}

	routes, ok := routesRaw.([]interface{})
	if !ok {
		t.Fatal("'routes' is not an array")
	}

	if len(routes) == 0 {
		t.Fatal("Expected at least one route")
	}

	// Check backend structure
	routeMap := routes[0].(map[string]interface{})
	if path, ok := routeMap["path"]; !ok || path != "/api" {
		t.Errorf("Expected route path '/api', got %v", path)
	}
}

func TestClusterInfoExposure(t *testing.T) {
	// This test ensures that even if cluster manager is nil (default),
	// the JSON output structure remains valid (or omits it cleanly)
	// and doesn't panic.

	hm := discovery.NewHost("")
	global := alaye.NewEphemeralGlobal(8080, false)

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
		// No cluster manager provided
	)

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	srv.handleAdminConfigDump(w, req)

	var data map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Cluster key might be missing or empty if not enabled, which is fine
	// just ensure it didn't crash.
	if cluster, ok := data["cluster"]; ok {
		if cluster != nil {
			// If present, verify structure
			cMap, ok := cluster.(map[string]interface{})
			if !ok {
				t.Error("Cluster info is not a map")
			}
			if _, ok := cMap["members"]; !ok {
				t.Error("Cluster map missing members key")
			}
		}
	}
}
