package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/go-chi/chi/v5"
)

func TestTOTPHandler_Setup(t *testing.T) {
	globalConfig := alaye.Admin{
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

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	// Test setup for new user
	t.Run("New user setup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/totp/setup", nil)
		ctx := context.WithValue(req.Context(), "user", "newuser")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.setup(w, req)

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
		req := httptest.NewRequest(http.MethodPost, "/api/totp/setup", nil)
		ctx := context.WithValue(req.Context(), "user", "existinguser")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.setup(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("Expected 409, got %d", w.Code)
		}
	})
}

func TestTOTPHandler_SetupWithoutAuth(t *testing.T) {
	globalConfig := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Active,
		},
	}

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/totp/setup", nil)
	w := httptest.NewRecorder()
	handler.setup(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestTOTPHandler_SetupDisabled(t *testing.T) {
	globalConfig := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Inactive,
		},
	}

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/totp/setup", nil)
	ctx := context.WithValue(req.Context(), "user", "testuser")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.setup(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected 501, got %d", w.Code)
	}
}

func TestTOTPHandler_QRCode(t *testing.T) {
	globalConfig := alaye.Admin{
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

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	r := chi.NewRouter()
	handler.Mount(r)

	t.Run("SVG QR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/totp/qruser/qr.svg", nil)
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
		req := httptest.NewRequest(http.MethodGet, "/api/totp/qruser/qr.png", nil)
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
	globalConfig := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Active,
			Users:   []alaye.TOTPUser{},
		},
	}

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	r := chi.NewRouter()
	handler.Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/api/totp/nonexistent/qr.svg", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestTOTPHandler_VerifyCode(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP" // Base32 encoded "Hello!"

	globalConfig := alaye.Admin{
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

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	// Test with invalid code
	if handler.VerifyCode("verifyuser", "000000") {
		t.Error("Expected invalid code to fail")
	}

	// Test with non-existent user
	if handler.VerifyCode("nonexistent", "123456") {
		t.Error("Expected nonexistent user to fail")
	}
}

func TestTOTPHandler_VerifyCodeDisabled(t *testing.T) {
	globalConfig := alaye.Admin{
		TOTP: alaye.TOTP{
			Enabled: alaye.Inactive,
		},
	}

	globalFn := func() alaye.Admin {
		return globalConfig
	}

	handler := NewTOTPHandler(globalFn, testLogger)

	if handler.VerifyCode("anyuser", "123456") {
		t.Error("Expected verification to fail when TOTP is disabled")
	}
}
