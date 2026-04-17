package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/cluster"
	"github.com/go-chi/chi/v5"
)

// setupAutoCluster spins up a single-node cluster for auto route tests
// and returns a Shared and a mockHandler so tests can assert on gossip state.
func setupAutoCluster(t *testing.T) (*Shared, *mockHandler, func()) {
	t.Helper()
	handler := &mockHandler{
		kv:         make(map[string][]byte),
		certs:      make(map[string]bool),
		challenges: make(map[string]string),
	}
	port := zulu.PortFree()
	cMgr, err := cluster.NewManager(cluster.Config{
		BindAddr: "127.0.0.1",
		BindPort: port,
		Name:     "auto-test-node",
		Seeds:    []string{},
	}, handler, testLogger)
	if err != nil {
		t.Fatalf("cluster init failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	shared := &Shared{
		Cluster: cMgr,
		Logger:  testLogger,
	}
	return shared, handler, func() { cMgr.Shutdown() }
}

// requestWithService builds a test request with the X-Agbero-Service header
// pre-set, simulating what auth.Internal would inject after token verification.
func requestWithService(method, url string, body []byte, service string) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	req.Header.Set(def.HeaderXAgberoService, service)
	return req
}

func TestAutoHandler_Ping(t *testing.T) {
	shared, _, cleanup := setupAutoCluster(t)
	defer cleanup()

	r := chi.NewRouter()
	AutoHandler(shared, r)

	req := requestWithService(http.MethodGet, "/auto/v1/ping", nil, "my-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 from ping, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode ping response: %v", err)
	}
	if resp["service"] != "my-service" {
		t.Errorf("expected service=my-service in ping response, got %q", resp["service"])
	}
}

func TestAutoHandler_Register(t *testing.T) {
	shared, handler, cleanup := setupAutoCluster(t)
	defer cleanup()

	r := chi.NewRouter()
	AutoHandler(shared, r)

	payload, _ := json.Marshal(routePayload{
		Host: "my-service-node1.cluster.internal",
		Route: alaye.Route{
			Path:     "/*",
			Backends: alaye.Backend{Servers: []alaye.Server{{Address: "http://10.0.0.1:8080"}}},
		},
		TTLSeconds: 30,
	})

	req := requestWithService(http.MethodPost, "/auto/v1/route", payload, "my-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	time.Sleep(200 * time.Millisecond)

	key := "route:my-service-node1.cluster.internal|/*"
	if _, ok := handler.kv[key]; !ok {
		t.Errorf("route not found in cluster state under key %q", key)
	}
}

func TestAutoHandler_Deregister(t *testing.T) {
	shared, handler, cleanup := setupAutoCluster(t)
	defer cleanup()

	r := chi.NewRouter()
	AutoHandler(shared, r)

	// Register first
	payload, _ := json.Marshal(routePayload{
		Host: "my-service-node2.cluster.internal",
		Route: alaye.Route{
			Path:     "/",
			Backends: alaye.Backend{Servers: []alaye.Server{{Address: "http://10.0.0.2:8080"}}},
		},
		TTLSeconds: 30,
	})
	req := requestWithService(http.MethodPost, "/auto/v1/route", payload, "my-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register failed: %d — %s", w.Code, w.Body.String())
	}
	time.Sleep(200 * time.Millisecond)

	// Deregister
	req = requestWithService(http.MethodDelete,
		"/auto/v1/route?host=my-service-node2.cluster.internal&path=/", nil, "my-service")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("deregister failed: %d — %s", w.Code, w.Body.String())
	}
	time.Sleep(200 * time.Millisecond)

	key := "route:my-service-node2.cluster.internal|/"
	if _, ok := handler.kv[key]; ok {
		t.Error("route still present in cluster state after deregister")
	}
}

// TestAutoHandler_ScopeEnforcement_Register ensures a service cannot register
// a host outside its own identity namespace.
func TestAutoHandler_ScopeEnforcement_Register(t *testing.T) {
	shared, _, cleanup := setupAutoCluster(t)
	defer cleanup()

	r := chi.NewRouter()
	AutoHandler(shared, r)

	payload, _ := json.Marshal(routePayload{
		Host: "other-service.cluster.internal", // valid domain but does not start with "my-service"
		Route: alaye.Route{
			Path:     "/",
			Backends: alaye.Backend{Servers: []alaye.Server{{Address: "http://10.0.0.3:8080"}}},
		},
	})

	req := requestWithService(http.MethodPost, "/auto/v1/route", payload, "my-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for out-of-scope host, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestAutoHandler_ScopeEnforcement_Deregister ensures a service cannot
// deregister routes belonging to a different service.
func TestAutoHandler_ScopeEnforcement_Deregister(t *testing.T) {
	shared, _, cleanup := setupAutoCluster(t)
	defer cleanup()

	r := chi.NewRouter()
	AutoHandler(shared, r)

	req := requestWithService(http.MethodDelete,
		"/auto/v1/route?host=other-service.cluster.internal&path=/", nil, "my-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for out-of-scope deregister, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestAutoHandler_NoCluster ensures graceful 503 when cluster is not configured.
func TestAutoHandler_NoCluster(t *testing.T) {
	shared := &Shared{Logger: testLogger} // no cluster

	r := chi.NewRouter()
	AutoHandler(shared, r)

	payload, _ := json.Marshal(routePayload{
		Host:  "my-service-x.cluster.internal",
		Route: alaye.Route{Path: "/"},
	})
	req := requestWithService(http.MethodPost, "/auto/v1/route", payload, "my-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 with no cluster, got %d", w.Code)
	}
}

// TestAutoHandler_MissingServiceHeader ensures requests with no service
// identity header are rejected — this catches misconfigured middleware.
func TestAutoHandler_MissingServiceHeader(t *testing.T) {
	shared, _, cleanup := setupAutoCluster(t)
	defer cleanup()

	r := chi.NewRouter()
	AutoHandler(shared, r)

	payload, _ := json.Marshal(routePayload{
		Host: "my-service-y.cluster.internal",
		Route: alaye.Route{
			Path:     "/",
			Backends: alaye.Backend{Servers: []alaye.Server{{Address: "http://10.0.0.4:8080"}}},
		},
	})
	// No X-Agbero-Service header — scope check sees empty service name
	req := httptest.NewRequest(http.MethodPost, "/auto/v1/route", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with no service header, got %d — body: %s", w.Code, w.Body.String())
	}
}
