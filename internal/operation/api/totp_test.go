// totp_test.go
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
		Storage: alaye.Storage{
			HostsDir: hostsDir,
		},
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
						Secret:   alaye.Value("JBSWY3DPEHPK3PXP"),
					},
				},
			},
		},
	}

	shared := &Shared{
		Logger: testLogger,
	}
	shared.UpdateState(&ActiveState{
		Global: global,
	})

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return shared, cleanup
}

// Helper to add a user to the TOTP config in the shared state
func addTOTPUser(shared *Shared, username, secret string) {
	state := shared.State()
	cfg := state.Global.Admin.TOTP
	cfg.Users = append(cfg.Users, alaye.TOTPUser{
		Username: username,
		Secret:   alaye.Value(secret),
	})
	state.Global.Admin.TOTP = cfg
	shared.UpdateState(state)
}

func TestTOTPHandler_Verify_ValidCode(t *testing.T) {
	shared, cleanup := setupTestTOTPWithConfig(t)
	defer cleanup()

	// Get the TOTP config
	cfg := shared.State().Global.Admin.TOTP

	// Generate a real TOTP secret for a test user
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

	// Add the user to config
	addTOTPUser(shared, "verifyuser", secret)

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	// Generate current valid code
	validCode, err := gen.Now(secret)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	verifyBody := map[string]string{"code": validCode}
	body, _ := json.Marshal(verifyBody)

	req := httptest.NewRequest(http.MethodPost, "/totp/verifyuser/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		bodyBytes := w.Body.Bytes()
		t.Errorf("Expected 200, got %d: %s", w.Code, string(bodyBytes))
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

	verifyBody := map[string]string{"code": "000000"}
	body, _ := json.Marshal(verifyBody)

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

	// Update window size in the shared state
	state := shared.State()
	state.Global.Admin.TOTP.WindowSize = 2
	shared.UpdateState(state)

	cfg := shared.State().Global.Admin.TOTP

	// Create generator with window=2
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

	// Add user to config
	addTOTPUser(shared, "windowuser", secret)

	// Get code from 60 seconds ago (2 periods)
	// This should be valid with window=2
	pastTime := time.Now().Unix() - 60
	code, err := gen.GenerateCode(secret, pastTime)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	r := chi.NewRouter()
	TOTPHandler(shared, r)

	verifyBody := map[string]string{"code": code}
	body, _ := json.Marshal(verifyBody)

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

	verifyBody := map[string]string{"code": "123456"}
	body, _ := json.Marshal(verifyBody)

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
		t.Errorf("Expected 400 for missing code, got %d", w.Code)
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

	// Generate a real secret for a new user
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

	// Add user to config
	addTOTPUser(shared, "integrationuser", secret)

	totp := NewTOTP(shared)

	// Generate valid code
	validCode, err := gen.Now(secret)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	// Test valid code
	if !totp.VerifyCode("integrationuser", validCode) {
		t.Error("Expected valid code to verify")
	}

	// Test invalid code
	if totp.VerifyCode("integrationuser", "000000") {
		t.Error("Expected invalid code to fail")
	}

	// Test non-existent user
	if totp.VerifyCode("nonexistent", "123456") {
		t.Error("Expected false for non-existent user")
	}

	// Test TOTP disabled
	state := shared.State()
	state.Global.Admin.TOTP.Enabled = alaye.Inactive
	shared.UpdateState(state)

	if totp.VerifyCode("integrationuser", validCode) {
		t.Error("Expected false when TOTP disabled")
	}
}
