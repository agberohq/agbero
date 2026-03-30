package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

func TestKVHandler(t *testing.T) {
	logger := ll.New("").Disable()
	shared := &Shared{Logger: logger}

	r := chi.NewRouter()
	KVHandler(shared, r)

	t.Run("set and get", func(t *testing.T) {
		// Set
		body := `{"value":{"foo":"bar"},"ttl_seconds":60}`
		req := httptest.NewRequest(http.MethodPost, "/kv/test-key", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("set failed: %d - %s", w.Code, w.Body.String())
		}

		// Get
		req = httptest.NewRequest(http.MethodGet, "/kv/test-key", nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("get failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp["key"] != "test-key" {
			t.Errorf("expected key test-key, got %v", resp["key"])
		}
	})

	t.Run("get missing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/missing-key", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	t.Run("delete", func(t *testing.T) {
		// Set first
		body := `{"value":"to-delete"}`
		req := httptest.NewRequest(http.MethodPost, "/kv/delete-me", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Delete
		req = httptest.NewRequest(http.MethodDelete, "/kv/delete-me", nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("delete failed: %d", w.Code)
		}

		// Verify gone
		req = httptest.NewRequest(http.MethodGet, "/kv/delete-me", nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 after delete, got %d", w.Code)
		}
	})

	t.Run("ttl expiration", func(t *testing.T) {
		// Set with 1 second TTL
		body := `{"value":"expires","ttl_seconds":1}`
		req := httptest.NewRequest(http.MethodPost, "/kv/ttl-test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Should exist immediately
		req = httptest.NewRequest(http.MethodGet, "/kv/ttl-test", nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 immediately, got %d", w.Code)
		}

		// Wait for expiration
		time.Sleep(2 * time.Second)

		// Should be gone
		req = httptest.NewRequest(http.MethodGet, "/kv/ttl-test", nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 after TTL, got %d", w.Code)
		}
	})
}
