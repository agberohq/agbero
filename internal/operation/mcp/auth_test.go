package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthMiddleware(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	raw, _, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var seen *Claims
	h := AuthMiddleware(store, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if seen == nil || seen.Subject != "alice" {
		t.Fatalf("claims = %+v", seen)
	}

	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddlewareRevoked(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	raw, _, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h := AuthMiddleware(store, func(string) bool { return true })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("revoked token reached the handler")
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status = %d, want 401", rr.Code)
	}
}
