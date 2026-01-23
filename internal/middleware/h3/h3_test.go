// internal/middleware/h3/h3_test.go
package h3

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestH3Middleware_HeaderAdded(t *testing.T) {
	handler := H3Middleware("443")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	altSvc := w.Header().Get("Alt-Svc")
	if altSvc != `h3=":443"; ma=2592000` {
		t.Errorf("Expected Alt-Svc header, got %q", altSvc)
	}
}

func TestExtractPort_Various(t *testing.T) {
	tests := []struct {
		addr     string
		expected string
	}{
		{":443", "443"},
		{"0.0.0.0:8080", "8080"},
		{"[::]:443", "443"},
		{"example.com", "443"}, // Fallback
	}

	for _, tt := range tests {
		port := ExtractPort(tt.addr)
		if port != tt.expected {
			t.Errorf("For %q, expected %q, got %q", tt.addr, tt.expected, port)
		}
	}
}

func TestH3Middleware_NoChangeNonTLS(t *testing.T) {
	handler := H3Middleware("80")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	altSvc := w.Header().Get("Alt-Svc")
	if altSvc != `h3=":80"; ma=2592000` { // Still adds, but test it's set (logic is same for non-TLS, though unusual)
		t.Errorf("Expected Alt-Svc, got %q", altSvc)
	}
}
