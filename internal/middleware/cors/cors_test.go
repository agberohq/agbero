package cors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func TestCORS(t *testing.T) {
	tests := []struct {
		name           string
		config         alaye.CORS
		reqMethod      string
		reqHeaders     map[string]string
		wantStatus     int
		wantHeaders    map[string]string
		dontWantHeader []string
	}{
		{
			name: "Disabled",
			config: alaye.CORS{
				Enabled: alaye.Inactive,
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://example.com"},
			wantStatus: http.StatusOK,
			dontWantHeader: []string{
				"Access-Control-Allow-Origin",
				"Vary",
			},
		},
		{
			name: "No Origin Header",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"*"},
			},
			reqMethod:  "GET",
			wantStatus: http.StatusOK,
			dontWantHeader: []string{
				"Access-Control-Allow-Origin",
				"Vary",
			},
		},
		{
			name: "Origin Not Allowed",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://good.com"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://evil.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Vary": "Origin",
			},
			dontWantHeader: []string{
				"Access-Control-Allow-Origin",
			},
		},
		{
			name: "Origin Allowed Exact",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://good.com"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://good.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://good.com",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Wildcard Origin",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"*"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://any.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Wildcard With Credentials",
			config: alaye.CORS{
				Enabled:          alaye.Active,
				AllowedOrigins:   []string{"*"},
				AllowCredentials: true,
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://auth.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "https://auth.com",
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
		},
		{
			name: "Allow Credentials",
			config: alaye.CORS{
				Enabled:          alaye.Active,
				AllowedOrigins:   []string{"https://auth.com"},
				AllowCredentials: true,
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://auth.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "https://auth.com",
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
		},
		{
			name: "Preflight (OPTIONS) - Valid",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://api.com"},
				AllowedMethods: []string{"GET", "POST", "PUT"},
				AllowedHeaders: []string{"X-Custom", "Content-Type"},
				MaxAge:         3600,
			},
			reqMethod: "OPTIONS",
			reqHeaders: map[string]string{
				"Origin":                        "https://api.com",
				"Access-Control-Request-Method": "POST",
			},
			wantStatus: http.StatusNoContent,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "https://api.com",
				"Access-Control-Allow-Methods": "GET, POST, PUT",
				"Access-Control-Allow-Headers": "X-Custom, Content-Type",
				"Access-Control-Max-Age":       "3600",
				"Vary":                         "Origin",
			},
		},
		{
			name: "Preflight (OPTIONS) - Missing Request Method",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://api.com"},
				AllowedMethods: []string{"GET", "POST"},
			},
			reqMethod: "OPTIONS",
			reqHeaders: map[string]string{
				"Origin": "https://api.com",
				// Missing Access-Control-Request-Method
			},
			wantStatus: http.StatusOK, // Not a preflight, passes through
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://api.com",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Preflight (OPTIONS) - Origin Not Allowed",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://allowed.com"},
				AllowedMethods: []string{"GET", "POST"},
			},
			reqMethod: "OPTIONS",
			reqHeaders: map[string]string{
				"Origin":                        "https://evil.com",
				"Access-Control-Request-Method": "POST",
			},
			wantStatus: http.StatusOK, // Origin not allowed, passes through without CORS headers
			wantHeaders: map[string]string{
				"Vary": "Origin",
			},
			dontWantHeader: []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Methods",
			},
		},
		{
			name: "Exposed Headers",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://api.com"},
				ExposedHeaders: []string{"X-Trace-ID", "X-Request-ID"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://api.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":   "https://api.com",
				"Access-Control-Expose-Headers": "X-Trace-ID, X-Request-ID",
				"Vary":                          "Origin",
			},
		},
		{
			name: "Multiple Allowed Origins",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://site1.com", "https://site2.com", "https://site3.com"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://site2.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://site2.com",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Case Insensitive Origin Matching",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://Example.com"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://example.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://example.com",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Wildcard Subdomain Match",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://*.localhost"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://ui.localhost"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://ui.localhost",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Wildcard Subdomain Multiple Levels Match",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://*.example.com"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://api.dev.example.com"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://api.dev.example.com",
				"Vary":                        "Origin",
			},
		},
		{
			name: "Wildcard Subdomain Mismatch (Wrong Base Domain)",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://*.localhost"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "https://ui.local"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Vary": "Origin",
			},
			dontWantHeader: []string{
				"Access-Control-Allow-Origin",
			},
		},
		{
			name: "Wildcard Subdomain Mismatch (Wrong Protocol)",
			config: alaye.CORS{
				Enabled:        alaye.Active,
				AllowedOrigins: []string{"https://*.localhost"},
			},
			reqMethod:  "GET",
			reqHeaders: map[string]string{"Origin": "http://ui.localhost"},
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Vary": "Origin",
			},
			dontWantHeader: []string{
				"Access-Control-Allow-Origin",
			},
		},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := New(&tt.config)(nextHandler)

			req := httptest.NewRequest(tt.reqMethod, "/", nil)
			for k, v := range tt.reqHeaders {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d", rec.Code, tt.wantStatus)
			}

			for k, v := range tt.wantHeaders {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("header %s = %q, want %q", k, got, v)
				}
			}

			for _, k := range tt.dontWantHeader {
				if got := rec.Header().Get(k); got != "" {
					t.Errorf("header %s should not be present, got %q", k, got)
				}
			}
		})
	}
}

func TestCORSVaryHeader(t *testing.T) {
	config := &alaye.CORS{
		Enabled:        alaye.Active,
		AllowedOrigins: []string{"https://example.com"},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := New(config)(nextHandler)

	tests := []struct {
		name       string
		origin     string
		wantVary   bool
		varyValues []string
	}{
		{
			name:       "With Origin Header",
			origin:     "https://example.com",
			wantVary:   true,
			varyValues: []string{"Origin"},
		},
		{
			name:     "Without Origin Header",
			origin:   "",
			wantVary: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			vary := rec.Header().Get("Vary")
			if tt.wantVary {
				if vary == "" {
					t.Error("Vary header should be present")
				}
				for _, v := range tt.varyValues {
					if !contains(vary, v) {
						t.Errorf("Vary header should contain %q, got %q", v, vary)
					}
				}
			} else {
				if vary != "" {
					t.Errorf("Vary header should not be present, got %q", vary)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return s != "" && (s == substr ||
		strings.Contains(s, substr+", ") ||
		strings.Contains(s, ", "+substr))
}
