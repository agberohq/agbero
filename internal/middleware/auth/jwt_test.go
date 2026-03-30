package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWT(t *testing.T) {
	secret := alaye.Value("test-secret-key-12345")

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
		wantHeaderKeys map[string]string
	}{
		{
			name:       "Missing Authorization Header",
			cfg:        &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid Token Format",
			cfg:        &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "Bearer invalid.token.string",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid Token, Unknown Headers Mapped",
			cfg:  &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
				"exp": time.Now().Add(time.Hour).Unix(),
			}, secret.String()),
			wantStatus: http.StatusOK,
		},
		{
			name: "Valid Token, Wrong Secret",
			cfg:  &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
			}, "wrong-secret"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Claims Mapping",
			cfg: &alaye.JWTAuth{
				Enabled: alaye.Active,
				Secret:  secret,
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
				Enabled: alaye.Active,
				Secret:  secret,
				Issuer:  "auth.agbero.com",
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
				Enabled: alaye.Active,
				Secret:  secret,
				Issuer:  "auth.agbero.com",
			},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
				"iss": "evil.com",
			}, secret.String()),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Challenge Token Rejected - scope=challenge",
			cfg:  &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub":   "user123",
				"scope": "challenge",
				"exp":   time.Now().Add(time.Hour).Unix(),
			}, secret.String()),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Full Token Accepted - scope=full",
			cfg:  &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub":   "user123",
				"scope": "full",
				"exp":   time.Now().Add(time.Hour).Unix(),
			}, secret.String()),
			wantStatus: http.StatusOK,
		},
		{
			name: "Token Without Scope Accepted",
			cfg:  &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret},
			authHeader: "Bearer " + genToken(jwt.MapClaims{
				"sub": "user123",
				"exp": time.Now().Add(time.Hour).Unix(),
			}, secret.String()),
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.wantHeaderKeys {
					got := r.Header.Get(k)
					if got != v {
						t.Errorf("Header %q = %q, want %q", k, got, v)
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			middleware := JWT(tt.cfg)
			handler := middleware(nextHandler)

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

func TestJWTWithRevocation(t *testing.T) {
	secret := alaye.Value("test-secret-key-12345")

	genToken := func(jti string, scope string) string {
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
			"jti": jti,
		}
		if scope != "" {
			claims["scope"] = scope
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		s, _ := token.SignedString([]byte(secret.String()))
		return s
	}

	cfg := &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret}

	t.Run("Valid token not revoked", func(t *testing.T) {
		isRevoked := func(jti string) bool { return false }

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken("jti-abc", ""))
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("Valid token that is revoked", func(t *testing.T) {
		revokedJTI := "jti-revoked-123"
		isRevoked := func(jti string) bool { return jti == revokedJTI }

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken(revokedJTI, ""))
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("Challenge token rejected even if not revoked", func(t *testing.T) {
		isRevoked := func(jti string) bool { return false }

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken("jti-xyz", "challenge"))
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for challenge token, got %d", rec.Code)
		}
	})

	t.Run("Full scope token accepted with revocation check", func(t *testing.T) {
		isRevoked := func(jti string) bool { return false }

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken("jti-full", "full"))
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("Token without jti is not rejected by revocation check", func(t *testing.T) {
		isRevoked := func(jti string) bool { return true }

		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, _ := token.SignedString([]byte(secret.String()))

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 for token without jti, got %d", rec.Code)
		}
	})

	t.Run("Invalid token is rejected before revocation check", func(t *testing.T) {
		checked := false
		isRevoked := func(jti string) bool {
			checked = true
			return false
		}

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
		if checked {
			t.Error("isRevoked should not be called for an invalid token")
		}
	})
}

func TestJWTWithRevocationAndScope(t *testing.T) {
	secret := alaye.Value("test-secret-key-12345")

	genToken := func(scope string) string {
		claims := jwt.MapClaims{
			"sub":   "user123",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"jti":   "test-jti-123",
			"scope": scope,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		s, _ := token.SignedString([]byte(secret.String()))
		return s
	}

	cfg := &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret}
	isRevoked := func(jti string) bool { return false }

	t.Run("JWTWithRevocationAndScope rejects challenge tokens", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken("challenge"))
		rec := httptest.NewRecorder()

		JWTWithRevocationAndScope(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("JWTWithRevocationAndScope accepts full tokens", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken("full"))
		rec := httptest.NewRecorder()

		JWTWithRevocationAndScope(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}

func TestGetClaims(t *testing.T) {
	secret := alaye.Value("test-secret-key-12345")

	genToken := func() string {
		claims := jwt.MapClaims{
			"sub":  "user123",
			"user": "admin",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		s, _ := token.SignedString([]byte(secret.String()))
		return s
	}

	cfg := &alaye.JWTAuth{Enabled: alaye.Active, Secret: secret}
	isRevoked := func(jti string) bool { return false }

	t.Run("GetClaims returns claims from context", func(t *testing.T) {
		var capturedClaims jwt.MapClaims

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+genToken())
		rec := httptest.NewRecorder()

		JWTWithRevocation(cfg, isRevoked)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r)
			if !ok {
				t.Error("GetClaims returned false")
			}
			capturedClaims = claims
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}

		if capturedClaims == nil {
			t.Fatal("capturedClaims is nil")
		}

		if user, _ := capturedClaims["user"].(string); user != "admin" {
			t.Errorf("expected user=admin, got %v", user)
		}
	})

	t.Run("GetClaims returns false when no claims in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r)
			if ok {
				t.Error("GetClaims should return false when no claims")
			}
			if claims != nil {
				t.Error("claims should be nil")
			}
			w.WriteHeader(http.StatusOK)
		})

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}
