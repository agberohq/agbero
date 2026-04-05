package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/go-chi/chi/v5"
)

var (
	p = security.NewPassword()
)

func setupTestPPK(t *testing.T) (*security.PPK, string, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	if err := security.NewPPK(keyPath); err != nil {
		t.Fatalf("Failed to create PPK: %v", err)
	}

	ppk, err := security.PPKLoad(keyPath)
	if err != nil {
		t.Fatalf("Failed to load PPK: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return ppk, keyPath, cleanup
}

func TestSecretsHandler_Hash(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action":   "hash",
		"password": "testpassword123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["hash"] == "" {
		t.Error("Expected hash in response")
	}
}

func TestSecretsHandler_HashNoPassword(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action": "hash",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestSecretsHandler_Password(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]interface{}{
		"action": "password",
		"length": 16,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["password"] == "" {
		t.Error("Expected password in response")
	}
	if resp["hash"] == "" {
		t.Error("Expected hash in response")
	}
	if len(resp["password"]) != 16 {
		t.Errorf("Expected password length 16, got %d", len(resp["password"]))
	}
}

func TestSecretsHandler_Key(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]interface{}{
		"action": "key",
		"length": 32,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["key"] == "" {
		t.Error("Expected key in response")
	}
	if len(resp["key"]) != 32 {
		t.Errorf("Expected key length 32, got %d", len(resp["key"]))
	}
}

func TestSecretsHandler_Token(t *testing.T) {
	ppk, _, cleanup := setupTestPPK(t)
	defer cleanup()

	shared := &Shared{
		PPK:    ppk,
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action":  "token",
		"service": "test-service",
		"ttl":     "1h",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["token"] == "" {
		t.Error("Expected token in response")
	}
	if resp["service"] != "test-service" {
		t.Errorf("Expected service test-service, got %s", resp["service"])
	}
	if resp["expires_in"] != "1h0m0s" {
		t.Errorf("Expected expires_in 1h0m0s, got %s", resp["expires_in"])
	}

	// Verify the token is actually valid
	verifiedService, err := ppk.Verify(resp["token"])
	if err != nil {
		t.Errorf("Failed to verify token: %v", err)
	}
	if verifiedService.Service != "test-service" {
		t.Errorf("Expected verified service test-service, got %s", verifiedService)
	}
}

func TestSecretsHandler_TokenNoService(t *testing.T) {
	ppk, _, cleanup := setupTestPPK(t)
	defer cleanup()

	shared := &Shared{
		PPK:    ppk,
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action": "token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestSecretsHandler_TokenNoPPK(t *testing.T) {
	shared := &Shared{
		PPK:    nil,
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action":  "token",
		"service": "test-service",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected 501, got %d", w.Code)
	}
}

func TestSecretsHandler_TokenInvalidTTL(t *testing.T) {
	ppk, _, cleanup := setupTestPPK(t)
	defer cleanup()

	shared := &Shared{
		PPK:    ppk,
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action":  "token",
		"service": "test-service",
		"ttl":     "invalid",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestSecretsHandler_UnknownAction(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action": "unknown",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestSecretsHandler_DefaultPasswordLength(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]interface{}{
		"action": "password",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp["password"]) != 32 {
		t.Errorf("Expected default password length 32, got %d", len(resp["password"]))
	}
}

func TestSecretsHandler_DefaultKeyLength(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]interface{}{
		"action": "key",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp["key"]) != 32 {
		t.Errorf("Expected default key length 32, got %d", len(resp["key"]))
	}
}

func TestSecretsHandler_TokenDefaultTTL(t *testing.T) {
	ppk, _, cleanup := setupTestPPK(t)
	defer cleanup()

	shared := &Shared{
		PPK:    ppk,
		Logger: testLogger,
	}

	r := chi.NewRouter()
	SecretsHandler(shared, r)

	reqBody := map[string]string{
		"action":  "token",
		"service": "test-service",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	expectedTTL := (365 * 24 * time.Hour).String()
	if resp["expires_in"] != expectedTTL {
		t.Errorf("Expected expires_in %s, got %s", expectedTTL, resp["expires_in"])
	}
}
