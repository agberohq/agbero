package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/revoke"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

var (
	logger = ll.New("test").Disable()
)

func TestRevokeHandler(t *testing.T) {

	t.Run("revoke store not configured", func(t *testing.T) {
		shared := &Shared{
			Logger:      logger,
			RevokeStore: nil, // Not configured
		}

		r := chi.NewRouter()
		RevokeHandler(shared, r)

		req := revokeRequest(t, "test-jti-123", "test-service", time.Now().Add(time.Hour))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotImplemented {
			t.Errorf("expected 501, got %d", w.Code)
		}
	})

	t.Run("missing jti", func(t *testing.T) {
		tmpDir := expect.NewFolder(t.TempDir())
		store, err := revoke.New(tmpDir, logger)
		if err != nil {
			t.Fatal(err)
		}

		shared := &Shared{
			Logger:      logger,
			RevokeStore: store,
		}

		r := chi.NewRouter()
		RevokeHandler(shared, r)

		body := map[string]any{
			"service":    "test-service",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		}
		req := jsonRequest(t, http.MethodPost, "/auto/revoke", body)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing jti, got %d", w.Code)
		}
	})

	t.Run("missing expires_at", func(t *testing.T) {
		tmpDir := expect.NewFolder(t.TempDir())
		store, err := revoke.New(tmpDir, logger)
		if err != nil {
			t.Fatal(err)
		}

		shared := &Shared{
			Logger:      logger,
			RevokeStore: store,
		}

		r := chi.NewRouter()
		RevokeHandler(shared, r)

		body := map[string]any{
			"jti":     "test-jti-123",
			"service": "test-service",
		}
		req := jsonRequest(t, http.MethodPost, "/auto/revoke", body)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing expires_at, got %d", w.Code)
		}
	})

	t.Run("already expired token", func(t *testing.T) {
		tmpDir := expect.NewFolder(t.TempDir())
		store, err := revoke.New(tmpDir, logger)
		if err != nil {
			t.Fatal(err)
		}

		shared := &Shared{
			Logger:      logger,
			RevokeStore: store,
		}

		r := chi.NewRouter()
		RevokeHandler(shared, r)

		// Token expired 1 hour ago
		req := revokeRequest(t, "expired-jti", "test-service", time.Now().Add(-time.Hour))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for already expired, got %d", w.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp["status"] != "ok" {
			t.Errorf("expected status ok, got %s", resp["status"])
		}
	})

	t.Run("successful revoke", func(t *testing.T) {
		tmpDir := expect.NewFolder(t.TempDir())
		store, err := revoke.New(tmpDir, logger)
		if err != nil {
			t.Fatal(err)
		}

		shared := &Shared{
			Logger:      logger,
			RevokeStore: store,
		}

		r := chi.NewRouter()
		RevokeHandler(shared, r)

		expiresAt := time.Now().Add(time.Hour)
		req := revokeRequest(t, "valid-jti-123", "test-service", expiresAt)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp["status"] != "ok" {
			t.Errorf("expected status ok, got %s", resp["status"])
		}
		if resp["jti"] != "valid-jti-123" {
			t.Errorf("expected jti valid-jti-123, got %s", resp["jti"])
		}

		if !store.IsRevoked("valid-jti-123") {
			t.Error("expected jti to be revoked in store")
		}
	})

	t.Run("store error", func(t *testing.T) {
		// Oshodi opens a lock file next to the database. A directory in place
		// of the database makes New fail before a handler can be constructed.
		tmpDir := t.TempDir()
		if err := os.Mkdir(filepath.Join(tmpDir, def.DefaultRevokedDBName), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := revoke.New(expect.NewFolder(tmpDir), logger); err == nil {
			t.Fatal("expected revoke.New to fail for an invalid database path")
		}
	})
}

// Helper functions

func revokeRequest(t *testing.T, jti, service string, expiresAt time.Time) *http.Request {
	t.Helper()
	body := map[string]any{
		"jti":        jti,
		"service":    service,
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	return jsonRequest(t, http.MethodPost, "/auto/revoke", body)
}

func jsonRequest(t *testing.T, method, path string, body map[string]any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	return req
}
