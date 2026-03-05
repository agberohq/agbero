package lb

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		ip := ClientIP(nil)
		if ip != "" {
			t.Errorf("expected empty string for nil request, got %s", ip)
		}
	})

	t.Run("X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
		req.RemoteAddr = "10.0.0.1:12345"

		ip := ClientIP(req)
		if ip != "203.0.113.195" {
			t.Errorf("expected 203.0.113.195, got %s", ip)
		}
	})

	t.Run("X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "192.168.1.50")

		ip := ClientIP(req)
		if ip != "192.168.1.50" {
			t.Errorf("expected 192.168.1.50, got %s", ip)
		}
	})

	t.Run("Forwarded header RFC 7239", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Forwarded", "for=192.0.2.43, for=\"[2001:db8:cafe::17]\"")

		ip := ClientIP(req)
		if ip != "192.0.2.43" {
			t.Errorf("expected 192.0.2.43, got %s", ip)
		}
	})

	t.Run("RemoteAddr fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		ip := ClientIP(req)
		if ip != "192.168.1.1" {
			t.Errorf("expected 192.168.1.1, got %s", ip)
		}
	})
}
