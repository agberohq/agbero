package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/cluster"
	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

type mockHandler struct {
	kv map[string][]byte
}

func (m *mockHandler) OnClusterChange(key string, value []byte, deleted bool) {
	if deleted {
		delete(m.kv, key)
	} else {
		m.kv[key] = value
	}
}

func TestRouteAPI(t *testing.T) {
	logger := ll.New("test").Enable()
	handler := &mockHandler{kv: make(map[string][]byte)}

	// Create cluster (standalone)
	cMgr, err := cluster.NewManager(cluster.Config{
		BindAddr: "127.0.0.1",
		BindPort: 0,
		Name:     "test-node",
	}, handler, logger)
	if err != nil {
		t.Fatalf("cluster init failed: %v", err)
	}
	defer cMgr.Shutdown()

	router := NewRouter(cMgr, logger)
	ts := httptest.NewServer(router)
	defer ts.Close()

	// 1. ADD ROUTE
	route := alaye.Route{
		Path: "/api",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: []alaye.Server{{Address: "http://localhost:3000"}},
		},
	}
	payload := routePayload{
		Host:  "example.com",
		Route: route,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/routes", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http post failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// Verify it reached handler
	expectedKey := "route:example.com|/api"
	// give cluster chan a moment (though local delegate applies immediately)
	if _, ok := handler.kv[expectedKey]; !ok {
		t.Error("route not found in cluster state")
	}

	// 2. DELETE ROUTE
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/routes?host=example.com&path=/api", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http delete failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	if _, ok := handler.kv[expectedKey]; ok {
		t.Error("route should have been deleted from cluster state")
	}
}
