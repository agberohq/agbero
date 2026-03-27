package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5" // Add this import
)

func setupTestTOTP(t *testing.T, admin alaye.Admin) *Shared {
	t.Helper()

	shared := &Shared{
		Logger: testLogger,
	}

	shared.UpdateState(&ActiveState{
		Global: &alaye.Global{
			Admin: admin,
		},
	})

	return shared
}

func TestTOTPHandler_Setup(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled:    alaye.Active,
			Digits:     6,
			Period:     30,
			Algorithm:  "SHA1",
			Issuer:     "Agbero Test",
			WindowSize: 1,
			Users: []alaye.TOTPUser{
				{
					Username: "existinguser",
					Secret:   alaye.Value("JBSWY3DPEHPK3PXP"),
				},
			},
		},
	}

	shared := setupTestTOTP(t, admin)

	t.Run("New user setup", func(t *testing.T) {
		r := chi.NewRouter()
		TOTPHandler(shared, r)

		req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
		// Fix: Use jwt.MapClaims instead of map[string]interface{}
		claims := jwt.MapClaims{"user": "newuser"}
		ctx := context.WithValue(req.Context(), auth.ClaimsContextKey, claims)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		var resp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if resp["secret"] == "" {
			t.Error("Expected secret in response")
		}
		if resp["uri"] == "" {
			t.Error("Expected URI in response")
		}
		if !strings.Contains(resp["uri"], "newuser") {
			t.Errorf("Expected URI to contain newuser, got %s", resp["uri"])
		}
	})

	t.Run("Existing user setup fails", func(t *testing.T) {
		r := chi.NewRouter()
		TOTPHandler(shared, r)

		req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
		// Fix: Use jwt.MapClaims
		claims := jwt.MapClaims{"user": "existinguser"}
		ctx := context.WithValue(req.Context(), auth.ClaimsContextKey, claims)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("Expected 409, got %d", w.Code)
		}
	})
}

func TestTOTPHandler_SetupWithoutAuth(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Active,
		},
	}

	shared := setupTestTOTP(t, admin)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
	// No auth context set - should return 401
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestTOTPHandler_SetupDisabled(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Inactive,
		},
	}

	shared := setupTestTOTP(t, admin)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
	// Fix: Use jwt.MapClaims
	claims := jwt.MapClaims{"user": "testuser"}
	ctx := context.WithValue(req.Context(), auth.ClaimsContextKey, claims)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected 501, got %d", w.Code)
	}
}

func TestTOTPHandler_QRCode(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Active,
			Issuer:  "Agbero Test",
			Users: []alaye.TOTPUser{
				{
					Username: "qruser",
					Secret:   alaye.Value("JBSWY3DPEHPK3PXP"),
				},
			},
		},
	}

	shared := setupTestTOTP(t, admin)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	t.Run("SVG QR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/totp/qruser/qr.svg", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Type"), "image/svg+xml") {
			t.Errorf("Expected SVG content type, got %s", w.Header().Get("Content-Type"))
		}
		if len(w.Body.String()) == 0 {
			t.Error("Expected SVG content")
		}
	})

	t.Run("PNG QR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/totp/qruser/qr.png", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Type"), "image/png") {
			t.Errorf("Expected PNG content type, got %s", w.Header().Get("Content-Type"))
		}
		if len(w.Body.Bytes()) == 0 {
			t.Error("Expected PNG content")
		}
	})
}

func TestTOTPHandler_QRCodeUserNotFound(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Active,
			Users:   []alaye.TOTPUser{},
		},
	}

	shared := setupTestTOTP(t, admin)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/totp/nonexistent/qr.svg", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestTOTPHandler_VerifyCode(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"

	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled:    alaye.Active,
			Digits:     6,
			Period:     30,
			Algorithm:  "SHA1",
			Issuer:     "Agbero Test",
			WindowSize: 1,
			Users: []alaye.TOTPUser{
				{
					Username: "verifyuser",
					Secret:   alaye.Value(testSecret),
				},
			},
		},
	}

	shared := setupTestTOTP(t, admin)

	totp := NewTOTP(shared)

	if totp.VerifyCode("verifyuser", "000000") {
		t.Error("Expected invalid code to fail")
	}

	if totp.VerifyCode("nonexistent", "123456") {
		t.Error("Expected nonexistent user to fail")
	}
}

func TestTOTPHandler_VerifyCodeDisabled(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Inactive,
		},
	}

	shared := setupTestTOTP(t, admin)

	totp := NewTOTP(shared)

	if totp.VerifyCode("anyuser", "123456") {
		t.Error("Expected verification to fail when TOTP is disabled")
	}
}

func TestTOTPHandler_SetupWithQRGeneration(t *testing.T) {
	admin := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled:    alaye.Active,
			Digits:     6,
			Period:     30,
			Algorithm:  "SHA1",
			Issuer:     "Agbero Test",
			WindowSize: 1,
			Users:      []alaye.TOTPUser{},
		},
	}

	shared := setupTestTOTP(t, admin)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
	// Fix: Use jwt.MapClaims
	claims := jwt.MapClaims{"user": "qruser"}
	ctx := context.WithValue(req.Context(), auth.ClaimsContextKey, claims)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["qr_svg"] == "" {
		t.Error("Expected QR SVG in response")
	}
	if !strings.Contains(resp["qr_svg"], "svg") {
		t.Error("Expected SVG content in qr_svg field")
	}
}
