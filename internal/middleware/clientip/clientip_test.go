package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPMiddleware_ClientIP_FromTrustedXFFChain(t *testing.T) {
	m := NewIPMiddleware([]string{"127.0.0.1/32", "10.0.0.0/8"})

	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.2, 127.0.0.1")

	rr := httptest.NewRecorder()

	var got string
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
		w.WriteHeader(200)
	}))

	h.ServeHTTP(rr, req)

	if got != "1.1.1.1" {
		t.Fatalf("expected client 1.1.1.1, got %q", got)
	}
}

func TestIPMiddleware_UntrustedPeer_IgnoresXFF(t *testing.T) {
	m := NewIPMiddleware([]string{"127.0.0.1/32"})

	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	rr := httptest.NewRecorder()

	var got string
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
		w.WriteHeader(200)
	}))

	h.ServeHTTP(rr, req)

	if got != "203.0.113.9" {
		t.Fatalf("expected 203.0.113.9, got %q", got)
	}
}
