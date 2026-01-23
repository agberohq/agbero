package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("test").Enable()

func TestRouteHandler_RoundRobin(t *testing.T) {
	// 1. Create 2 dummy backends
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend1"))
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend2"))
	}))
	defer srv2.Close()

	// 2. Config
	route := &woos.Route{
		Path:       "/",
		Backends:   []string{srv1.URL, srv2.URL},
		LBStrategy: woos.StrategyRoundRobin,
	}

	// 3. Init Handler
	h := NewRouteHandler(route, testLogger)
	defer h.Close()

	// 4. Test Round Robin (Should oscillate)
	// Note: The atomic counter increment order depends on implementation details,
	// but it should distribute.
	hits := make(map[string]int)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		body, _ := io.ReadAll(w.Result().Body)
		hits[string(body)]++
	}

	if hits["backend1"] < 4 || hits["backend2"] < 4 {
		t.Errorf("Round robin distribution uneven: %v", hits)
	}
}

func TestRouteHandler_HeadersMiddleware(t *testing.T) {
	// Backend checks for header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "Added" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	route := &woos.Route{
		Path:     "/",
		Backends: []string{srv.URL},
		Headers: &woos.HeadersConfig{
			Request: &woos.HeaderOperations{
				Set: map[string]string{"X-Test": "Added"},
			},
		},
	}

	h := NewRouteHandler(route, testLogger)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Headers middleware failed, backend got code %d", w.Code)
	}
}

func TestRouteHandler_NoHealthyBackends(t *testing.T) {
	// Point to closed port
	route := &woos.Route{
		Path:     "/",
		Backends: []string{"http://127.0.0.1:54321"},
	}

	h := NewRouteHandler(route, testLogger)
	defer h.Close()

	// Manually mark dead for test immediate response
	// (Real world relies on health check or dial failure, but middleware might just error)
	for _, b := range h.Backends {
		b.Alive.Store(false)
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 Bad Gateway, got %d", w.Code)
	}
}

func TestRouteHandler_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("slow"))
	}))
	defer srv.Close()

	route := &woos.Route{
		Path:     "/",
		Backends: []string{srv.URL},
		Timeouts: &woos.RouteTimeouts{
			Request: 10 * time.Millisecond, // Very short
		},
	}

	h := NewRouteHandler(route, testLogger)
	defer h.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// backend proxy usually returns 502 on context cancel/timeout
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 (Timeout), got %d", w.Code)
	}
}

func TestRouteHandler_StripPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users" {
			t.Errorf("Expected path /users, got %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	route := &woos.Route{
		Path:     "/api",
		Backends: []string{srv.URL},
		// Note: The RouteHandler struct doesn't perform stripping logic itself anymore,
		// it relies on the `handleRoute` in `handle.go` (Server) to do the stripping BEFORE
		// calling the handler.
		// However, standard Go `httputil.ReverseProxy` (inside Backend) forwards the path "as is"
		// unless modified.
		// If testing pure RouteHandler, we check simple forwarding.
	}

	h := NewRouteHandler(route, testLogger)
	defer h.Close()

	// Manually simulate what `handleRoute` does: modify request before ServeHTTP
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.URL.Path = "/users" // Simulate strip

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
}
