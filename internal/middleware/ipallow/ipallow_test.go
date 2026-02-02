package ipallow

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/olekukonko/ll"
)

func TestNew(t *testing.T) {
	// Mock Logger (discard output)
	logger := ll.New("test")

	tests := []struct {
		name           string
		allowed        []string
		clientIP       string
		expectedStatus int
	}{
		{
			name:           "No rules configured (allow all)",
			allowed:        []string{},
			clientIP:       "1.2.3.4",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Exact IP Match (Allow)",
			allowed:        []string{"192.168.1.5", "10.0.0.1"},
			clientIP:       "192.168.1.5",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Exact IP Mismatch (Deny)",
			allowed:        []string{"192.168.1.5"},
			clientIP:       "192.168.1.6",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "CIDR Match (Allow)",
			allowed:        []string{"10.0.0.0/24"},
			clientIP:       "10.0.0.42",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "CIDR Mismatch (Deny)",
			allowed:        []string{"10.0.0.0/24"},
			clientIP:       "10.0.1.42",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Mixed IP and CIDR (Allow IP)",
			allowed:        []string{"10.0.0.0/24", "1.1.1.1"},
			clientIP:       "1.1.1.1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Mixed IP and CIDR (Allow CIDR)",
			allowed:        []string{"10.0.0.0/24", "1.1.1.1"},
			clientIP:       "10.0.0.5",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "IPv6 Exact Match",
			allowed:        []string{"::1"},
			clientIP:       "::1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "IPv6 CIDR Match",
			allowed:        []string{"2001:db8::/32"},
			clientIP:       "2001:db8:ffff::1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid Client IP parsing",
			allowed:        []string{"127.0.0.1"},
			clientIP:       "invalid-ip",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Malformed Allowed config ignored",
			allowed:        []string{"not-an-ip", "127.0.0.1"},
			clientIP:       "127.0.0.1",
			expectedStatus: http.StatusOK, // Should match the valid one
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create Middleware
			mw := New(tt.allowed, logger)

			// Create a dummy handler that returns 200 OK
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap handler
			handler := mw(nextHandler)

			// Create Request
			req := httptest.NewRequest("GET", "/", nil)

			// Handle IPv6 Bracket formatting for RemoteAddr
			// net.SplitHostPort expects "[::1]:1234", not "::1:1234"
			if strings.Contains(tt.clientIP, ":") {
				req.RemoteAddr = "[" + tt.clientIP + "]:1234"
			} else {
				req.RemoteAddr = tt.clientIP + ":1234"
			}

			// Special case for invalid IP test
			if tt.clientIP == "invalid-ip" {
				req.RemoteAddr = "invalid-ip:1234"
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("status code got = %v, want %v", rec.Code, tt.expectedStatus)
			}
		})
	}
}
