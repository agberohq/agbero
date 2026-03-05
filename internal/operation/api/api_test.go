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
	logger := ll.New("test").Disable()
	handler := &mockHandler{kv: make(map[string][]byte)}

	cMgr, err := cluster.NewManager(cluster.Config{
		BindAddr: "127.0.0.1",
		BindPort: 0,
		Name:     "test-node",
	}, handler, logger)
	if err != nil {
		t.Fatalf("cluster init failed: %v", err)
	}
	defer cMgr.Shutdown()

	noopMiddleware := func(h http.Handler) http.Handler {
		return h
	}

	router := NewRouter(cMgr, logger, noopMiddleware)
	ts := httptest.NewServer(router)
	defer ts.Close()

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

	expectedKey := "route:example.com|/api"
	// API operations on cluster are eventual, but local delegate is applied immediately in mock
	// However, the Manager.Set is async. We might need a small wait in a real integration test,
	// but here we are checking the mockHandler which relies on the Manager's delegate.
	// Since Manager.Set calls delegate.set which locks and calls handler, it should be visible.

	// Wait for async propagation if necessary (memberlist might be async internally)
	// But local set usually applies directly.
	// Let's verify against the handler's map.

	_, exists := handler.kv[expectedKey]
	if !exists {
		// Manager.Set is async/gossip based in some implementations, but Set() calls delegate.set() directly in this implementation.
		// Check implementation details: Manager.Set -> delegate.set -> apply -> handler.OnClusterChange.
		// It should be synchronous for the local node.
		t.Error("route not found in cluster state")
	}

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
