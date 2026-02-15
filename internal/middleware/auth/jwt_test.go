package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWT(t *testing.T) {
	secret := alaye.Value("test-secret-key-12345")

	// Helper to generate a valid token
	genToken := func(claims jwt.MapClaims, signingSecret string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		s, _ := token.SignedString([]byte(signingSecret))
		return s
	}

	tests := []struct {
		name           string
		cfg            *alaye.JWTAuth
		authHeader     string
		wantStatus     int
		wantHeaderKeys map[string]string // Key -> Expected Value
	}{
		{
			name:       "Missing Authorization Header",
			cfg:        &alaye.JWTAuth{Secret: secret},
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid Token Format",
			cfg:        &alaye.JWTAuth{Secret: secret},
			authHeader: "Bearer invalid.token.string",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid Token, Unknown Headers Mapped",
			cfg:  &alaye.JWTAuth{Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
				"exp": time.Now().Add(time.Hour).Unix(),
			}, secret.String()),
			wantStatus: http.StatusOK,
		},
		{
			name: "Valid Token, Wrong Secret",
			cfg:  &alaye.JWTAuth{Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
			}, "wrong-secret"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Claims Mapping",
			cfg: &alaye.JWTAuth{
				Secret: secret,
				ClaimMap: map[string]string{
					"sub":  "X-User-ID",
					"role": "X-User-Role",
				},
			},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub":  "user_888",
				"role": "admin",
				"exp":  time.Now().Add(time.Hour).Unix(),
			}, secret.String()),
			wantStatus: http.StatusOK,
			wantHeaderKeys: map[string]string{
				"X-User-ID":   "user_888",
				"X-User-Role": "admin",
			},
		},
		{
			name: "Issuer Validation Active",
			cfg: &alaye.JWTAuth{
				Secret: secret,
				Issuer: "auth.agbero.com",
			},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
				"iss": "auth.agbero.com",
			}, secret.String()),
			wantStatus: http.StatusOK,
		},
		{
			name: "Issuer Validation Unknown",
			cfg: &alaye.JWTAuth{
				Secret: secret,
				Issuer: "auth.agbero.com",
			},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
				"iss": "evil.com",
			}, secret.String()),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock Next Handler
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check headers if we expect specific mappings
				for k, v := range tt.wantHeaderKeys {
					got := r.Header.Get(k)
					if got != v {
						t.Errorf("Header %q = %q, want %q", k, got, v)
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			// Create Middleware
			middleware := JWT(tt.cfg)
			handler := middleware(nextHandler)

			// Execute Request
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Active = %d, want %d Body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}
