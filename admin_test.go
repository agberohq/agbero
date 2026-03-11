package agbero

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/discovery"
)

func mockHostManager(t *testing.T) *discovery.Host {
	hm := discovery.NewHost("")

	host := alaye.NewStaticHost("test.local", "http://backend:8080", true)
	host.Routes[0].Path = "/api"

	hostsMap := map[string]*alaye.Host{
		"test.local": host,
	}
	hm.LoadStatic(hostsMap)

	return hm
}

func TestAdminConfigDumpStructure(t *testing.T) {
	hm := mockHostManager(t)
	global := alaye.NewEphemeralGlobal(8080, false)

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
	)

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	srv.handleConfigDump(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, ok := data["global"]; !ok {
		t.Error("Missing 'global' key in config dump")
	}

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

	routeMap := routes[0].(map[string]interface{})
	if path, ok := routeMap["path"]; !ok || path != "/api" {
		t.Errorf("Expected route path '/api', got %v", path)
	}
}

func TestClusterInfoExposure(t *testing.T) {
	hm := discovery.NewHost("")
	global := alaye.NewEphemeralGlobal(8080, false)

	srv := NewServer(
		WithHostManager(hm),
		WithGlobalConfig(global),
	)

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	srv.handleConfigDump(w, req)

	var data map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if cluster, ok := data["cluster"]; ok {
		if cluster != nil {
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
