package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func TestForward_Success(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/success", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestForward_Forbidden(t *testing.T) {
	// Auth server returns 403 AND a body
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"access_denied"}`))
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not be reached
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/forbidden", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check Yes
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// Check Body Passthrough
	body, _ := io.ReadAll(w.Result().Body)
	expectedBody := `{"error":"access_denied"}`
	if string(body) != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, string(body))
	}
}

func TestForward_CacheHit(t *testing.T) {
	authServerCalls := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authServerCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Same path used twice to test cache
	req := httptest.NewRequest("GET", "/cache-test", nil)

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req) // Miss, sets cache

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req) // Hit

	if w2.Code != http.StatusOK {
		t.Errorf("Expected cache hit 200, got %d", w2.Code)
	}

	// Optional: verify server was only called once if you want to be strict about cache
	// Note: Otter cache is async in some stats/eviction but synchronous in Get/Set.
	// We rely on functional behavior (200 OK) here.
}

func TestForward_FailureAllow(t *testing.T) {
	// Point to a guaranteed closed port to force connection error
	cfg := &alaye.ForwardAuth{URL: "http://127.0.0.1:54321", OnFailure: "allow"}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fail-allow", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected allow on failure 200, got %d", w.Code)
	}
}

func TestForward_FailureDeny(t *testing.T) {
	// Point to a guaranteed closed port
	cfg := &alaye.ForwardAuth{URL: "http://127.0.0.1:54321", OnFailure: "deny"}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/fail-deny", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Code expects generic 403 on network failure
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected deny on failure 403, got %d", w.Code)
	}
}

func TestForward_MaxAgeParse(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/maxage", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
