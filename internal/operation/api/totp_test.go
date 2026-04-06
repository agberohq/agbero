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
	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// setupTestTOTPWithKeeper creates a test environment with an unlocked Keeper
// instance pre-configured for TOTP tests.
func setupTestTOTPWithKeeper(t *testing.T) (*Shared, *keeper.Keeper, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	hostsDir := expect.NewFolder(filepath.Join(tmpDir, "hosts.d"))
	if err := hostsDir.Init(0755); err != nil {
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
			},
		},
	}

	// Create and unlock a Keeper instance for testing
	keeperPath := filepath.Join(tmpDir, "keeper.db")
	store, err := keeper.New(keeper.Config{DBPath: keeperPath})
	if err != nil {
		t.Fatalf("keeper.New failed: %v", err)
	}

	passphrase := []byte("test-totp-passphrase")
	if err := store.Unlock(passphrase); err != nil {
		store.Close()
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create the vault:admin bucket for TOTP secrets
	if err := store.CreateBucket("vault", "admin", keeper.LevelPasswordOnly, "test"); err != nil {
		if !strings.Contains(err.Error(), "immutable") && !strings.Contains(err.Error(), "already exists") {
			store.Close()
			t.Fatalf("CreateBucket vault:admin failed: %v", err)
		}
	}

	shared := &Shared{
		Logger: testLogger,
		Keeper: store,
	}
	shared.UpdateState(&ActiveState{Global: global})

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return shared, store, cleanup
}

// addTOTPUserInKeeper stores a TOTP secret for a user in the Keeper instance
// at the canonical path: vault://admin/totp/<username>
func addTOTPUserInKeeper(t *testing.T, store *keeper.Keeper, username, secret string) {
	t.Helper()
	key := expect.Vault().AdminTOTP(username)
	if err := store.Set(key, []byte(secret)); err != nil {
		t.Fatalf("Failed to store TOTP secret for %s: %v", username, err)
	}
}

func TestTOTPHandler_Verify_ValidCode(t *testing.T) {
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
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
	addTOTPUserInKeeper(t, store, "verifyuser", secret)

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
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
	defer cleanup()

	// Add a user with a secret so we test code validation, not user lookup
	cfg := shared.State().Global.Admin.TOTP
	gen := security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    cfg.WindowSize,
		Issuer:    cfg.Issuer,
	})
	secret, _ := gen.GenerateSecret()
	addTOTPUserInKeeper(t, store, "existinguser", secret)

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
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
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
	addTOTPUserInKeeper(t, store, "windowuser", secret)

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
	shared, _, cleanup := setupTestTOTPWithKeeper(t)
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
	shared, _, cleanup := setupTestTOTPWithKeeper(t)
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
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
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
		return
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
	if resp["store_key"] != "vault://admin/totp/newuser" {
		t.Errorf("Expected store_key=vault://admin/totp/newuser, got %s", resp["store_key"])
	}

	// Verify the secret was actually stored in Keeper
	stored, err := store.Get(expect.Vault().AdminTOTP("newuser"))
	if err != nil {
		t.Errorf("Failed to retrieve stored secret from Keeper: %v", err)
	}
	if string(stored) != resp["secret"] {
		t.Error("Secret in response does not match stored secret")
	}
}

func TestTOTPHandler_Setup_AlreadyConfigured(t *testing.T) {
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
	defer cleanup()

	// Pre-configure TOTP for this user
	cfg := shared.State().Global.Admin.TOTP
	gen := security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Issuer:    cfg.Issuer,
	})
	secret, _ := gen.GenerateSecret()
	addTOTPUserInKeeper(t, store, "existinguser", secret)

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
	shared, _, cleanup := setupTestTOTPWithKeeper(t)
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
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
	defer cleanup()

	// Pre-configure TOTP for QR generation
	cfg := shared.State().Global.Admin.TOTP
	gen := security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Issuer:    cfg.Issuer,
	})
	secret, _ := gen.GenerateSecret()
	addTOTPUserInKeeper(t, store, "existinguser", secret)

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
	shared, _, cleanup := setupTestTOTPWithKeeper(t)
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
	shared, store, cleanup := setupTestTOTPWithKeeper(t)
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
	addTOTPUserInKeeper(t, store, "integrationuser", secret)

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
