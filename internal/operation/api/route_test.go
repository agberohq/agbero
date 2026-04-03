package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/cluster"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// mockHandler records cluster changes so tests can assert on gossip state
// without a real cluster network.
type mockHandler struct {
	kv         map[string][]byte
	certs      map[string]bool
	challenges map[string]string
}

func (m *mockHandler) OnClusterChange(key string, value []byte, deleted bool) {
	if deleted {
		delete(m.kv, key)
	} else {
		m.kv[key] = value
	}
}

func (m *mockHandler) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	if m.certs == nil {
		m.certs = make(map[string]bool)
	}
	m.certs[domain] = true
	return nil
}

func (m *mockHandler) OnClusterChallenge(token, keyAuth string, deleted bool) {
	if m.challenges == nil {
		m.challenges = make(map[string]string)
	}
	if deleted {
		delete(m.challenges, token)
	} else {
		m.challenges[token] = keyAuth
	}
}

func TestRouteAPI(t *testing.T) {
	logger := ll.New("test").Disable()
	handler := &mockHandler{
		kv:         make(map[string][]byte),
		certs:      make(map[string]bool),
		challenges: make(map[string]string),
	}

	port := zulu.PortFree()
	cMgr, err := cluster.NewManager(cluster.Config{
		BindAddr: "127.0.0.1",
		BindPort: port,
		Name:     "test-node",
		Seeds:    []string{},
	}, handler, logger)
	if err != nil {
		t.Fatalf("cluster init failed: %v", err)
	}
	defer cMgr.Shutdown()

	time.Sleep(500 * time.Millisecond)

	shared := &Shared{
		Cluster: cMgr,
		Logger:  logger,
	}

	r := chi.NewRouter()
	RouterHandler(shared, r)

	t.Log("Registered routes:")
	chi.Walk(r, func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		t.Logf("  %s %s", method, route)
		return nil
	})

	ts := httptest.NewServer(r)
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

	resp, err := http.Post(ts.URL+"/route", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http post failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	expectedKey := "route:example.com|/api"
	time.Sleep(500 * time.Millisecond)

	if _, exists := handler.kv[expectedKey]; !exists {
		t.Error("route not found in cluster state")
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/route?host=example.com&path=/api", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http delete failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 200 OK, got %d: %s", resp2.StatusCode, string(bodyBytes))
	}

	time.Sleep(500 * time.Millisecond)

	if _, ok := handler.kv[expectedKey]; ok {
		t.Error("route should have been deleted from cluster state")
	}
}
