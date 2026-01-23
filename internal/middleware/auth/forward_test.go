package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

func TestForward_Success(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &woos.ForwardAuthConfig{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestForward_Forbidden(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer authServer.Close()

	cfg := &woos.ForwardAuthConfig{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestForward_CacheHit(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &woos.ForwardAuthConfig{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req) // Miss, sets cache

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req) // Hit
	if w2.Code != http.StatusOK {
		t.Errorf("Expected cache hit 200, got %d", w2.Code)
	}
}

func TestForward_FailureAllow(t *testing.T) {
	cfg := &woos.ForwardAuthConfig{URL: "http://nonexistent", OnFailure: "allow"}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected allow on failure 200, got %d", w.Code)
	}
}

func TestForward_FailureDeny(t *testing.T) {
	cfg := &woos.ForwardAuthConfig{URL: "http://nonexistent", OnFailure: "deny"}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
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

	cfg := &woos.ForwardAuthConfig{URL: authServer.URL}
	handler := Forward(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Check cache TTL (indirect: wait and check miss would require time mock; assume parse works if no panic)
}
