package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

func setupTestTOTPWithConfig(t *testing.T) (*Shared, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		t.Fatalf("Failed to create hosts dir: %v", err)
	}

	global := &alaye.Global{
		Storage: alaye.Storage{HostsDir: hostsDir},
		Admin: alaye.Admin{
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
						// Plain base32 literal — no keeper needed in tests.
						Secret: expect.Value("JBSWY3DPEHPK3PXP"),
					},
				},
			},
		},
	}

	shared := &Shared{Logger: testLogger}
	shared.UpdateState(&ActiveState{Global: global})

	return shared, func() { os.RemoveAll(tmpDir) }
}

// addTOTPUser adds a user with a plain-text secret directly to the shared state.
// Used in tests where the secret is generated in-process and does not need keeper.
func addTOTPUser(shared *Shared, username, secret string) {
	state := shared.State()
	cfg := state.Global.Admin.TOTP
	cfg.Users = append(cfg.Users, alaye.TOTPUser{
		Username: username,
		Secret:   expect.Value(secret),
	})
	state.Global.Admin.TOTP = cfg
	shared.UpdateState(state)
}

func TestTOTPHandler_Verify_ValidCode(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	cfg := shared.State().Global.Admin.TOTP
	gen := security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    cfg.WindowSize,
		Issuer:    cfg.Issuer,
	})

	secret, err := gen.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	addTOTPUser(shared, "verifyuser", secret)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	validCode, err := gen.Now(secret)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": validCode})
	req := httptest.NewRequest(http.MethodPost, "/totp/verifyuser/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
		return
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if valid, ok := resp["valid"].(bool); !ok || !valid {
		t.Errorf("Expected valid=true, got %v", resp["valid"])
	}
}

func TestTOTPHandler_Verify_InvalidCode(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	body, _ := json.Marshal(map[string]string{"code": "000000"})
	req := httptest.NewRequest(http.MethodPost, "/totp/existinguser/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestTOTPHandler_Verify_WithWindow(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	state := shared.State()
	state.Global.Admin.TOTP.WindowSize = 2
	shared.UpdateState(state)

	cfg := shared.State().Global.Admin.TOTP
	gen := security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    2,
		Issuer:    cfg.Issuer,
	})

	secret, err := gen.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	addTOTPUser(shared, "windowuser", secret)

	// Code from 60 seconds ago — valid with window=2 (2 periods back).
	code, err := gen.GenerateCode(secret, time.Now().Unix()-60)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequest(http.MethodPost, "/totp/windowuser/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 with window=2, got %d", w.Code)
	}
}

func TestTOTPHandler_Verify_UserNotFound(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	body, _ := json.Marshal(map[string]string{"code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/totp/nonexistent/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestTOTPHandler_Verify_MissingCode(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/existinguser/verify", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestTOTPHandler_Setup(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
	claims := jwt.MapClaims{"user": "newuser"}
	ctx := context.WithValue(req.Context(), auth.ClaimsContextKey, claims)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d — body: %s", w.Code, w.Body.String())
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
	// store_key should be the canonical keeper path
	if resp["store_key"] != "vault://admin/totp/newuser" {
		t.Errorf("Expected store_key=vault://admin/totp/newuser, got %s", resp["store_key"])
	}
}

func TestTOTPHandler_Setup_AlreadyConfigured(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
	claims := jwt.MapClaims{"user": "existinguser"}
	ctx := context.WithValue(req.Context(), auth.ClaimsContextKey, claims)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected 409, got %d", w.Code)
	}
}

func TestTOTPHandler_Setup_WithoutAuth(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodPost, "/totp/setup", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestTOTPHandler_QRCode(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	t.Run("SVG QR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/totp/existinguser/qr.svg", nil)
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
		req := httptest.NewRequest(http.MethodGet, "/totp/existinguser/qr.png", nil)
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

func TestTOTPHandler_QRCode_UserNotFound(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/totp/nonexistent/qr.svg", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestTOTPHandler_VerifyCode_Integration(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	cfg := shared.State().Global.Admin.TOTP
	gen := security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    cfg.WindowSize,
		Issuer:    cfg.Issuer,
	})

	secret, err := gen.GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}
	addTOTPUser(shared, "integrationuser", secret)

	totp := NewTOTP(shared)

	validCode, err := gen.Now(secret)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if !totp.VerifyCode("integrationuser", validCode) {
		t.Error("Expected valid code to verify")
	}
	if totp.VerifyCode("integrationuser", "000000") {
		t.Error("Expected invalid code to fail")
	}
	if totp.VerifyCode("nonexistent", "123456") {
		t.Error("Expected false for non-existent user")
	}

	// Disable TOTP.
	state := shared.State()
	state.Global.Admin.TOTP.Enabled = alaye.Inactive
	shared.UpdateState(state)

	if totp.VerifyCode("integrationuser", validCode) {
		t.Error("Expected false when TOTP disabled")
	}
}
