package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedIPs(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("lan allowlist", func(t *testing.T) {
		h := AllowedIPs([]string{"192.168.0.0/16"}, nil, nil)(ok)
		req := httptest.NewRequest(http.MethodPost, "/mcp/v1", nil)
		req.RemoteAddr = "192.168.1.25:54321"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("LAN client blocked: %d", rr.Code)
		}

		req.RemoteAddr = "10.0.0.5:54321"
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("non-allowlisted client status = %d, want 403", rr.Code)
		}
	})

	t.Run("localhost expands to loopback", func(t *testing.T) {
		h := AllowedIPs([]string{"localhost"}, nil, nil)(ok)
		req := httptest.NewRequest(http.MethodPost, "/mcp/v1", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("localhost allowlist blocked loopback: %d", rr.Code)
		}
	})

	t.Run("empty means loopback", func(t *testing.T) {
		h := AllowedIPs(nil, nil, nil)(ok)
		req := httptest.NewRequest(http.MethodPost, "/mcp/v1", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("loopback client blocked: %d", rr.Code)
		}

		req.RemoteAddr = "8.8.8.8:54321"
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("public client status = %d, want 403", rr.Code)
		}
	})
}
