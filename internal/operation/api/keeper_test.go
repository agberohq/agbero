package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/go-chi/chi/v5"
)

func setupKeeperTest(t *testing.T) (*security.Store, string, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.kdbx")

	store, err := security.NewStore(security.StoreConfig{DBPath: storePath})
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	passphrase := "test-passphrase-123"
	if err := store.Unlock(passphrase); err != nil {
		t.Fatalf("Failed to unlock store: %v", err)
	}

	testSecrets := map[string]string{
		"db_password": "super_secret_db_pass",
		"api_key":     "abc123xyz789",
		"totp/admin":  "JBSWY3DPEHPK3PXP",
	}
	for key, val := range testSecrets {
		if err := store.Set(key, val); err != nil {
			t.Fatalf("Failed to set test secret %s: %v", key, err)
		}
	}

	if err := store.Lock(); err != nil {
		t.Fatalf("Failed to lock store: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return store, passphrase, cleanup
}

func TestKeeperRouter_UnlockLock(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Store: store, Logger: testLogger}, r)

	ts := httptest.NewServer(r)
	defer ts.Close()

	unlockPayload := map[string]string{"passphrase": passphrase}
	body, _ := json.Marshal(unlockPayload)
	resp, err := http.Post(ts.URL+"/keeper/unlock", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to unlock: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	lockResp, err := http.Post(ts.URL+"/keeper/lock", "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to lock: %v", err)
	}
	defer lockResp.Body.Close()

	if lockResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", lockResp.StatusCode)
	}
}

func TestKeeperRouter_CRUD(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Store: store, Logger: testLogger}, r)

	ts := httptest.NewServer(r)
	defer ts.Close()

	unlockPayload := map[string]string{"passphrase": passphrase}
	body, _ := json.Marshal(unlockPayload)
	resp, err := http.Post(ts.URL+"/keeper/unlock", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to unlock: %v", err)
	}
	resp.Body.Close()

	listResp, err := http.Get(ts.URL + "/keeper/secrets")
	if err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", listResp.StatusCode)
	}

	var listResult map[string][]string
	if err := json.NewDecoder(listResp.Body).Decode(&listResult); err != nil {
		t.Fatalf("Failed to decode list: %v", err)
	}
	if len(listResult["keys"]) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(listResult["keys"]))
	}

	getResp, err := http.Get(ts.URL + "/keeper/secrets/db_password")
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", getResp.StatusCode)
	}

	var getResult map[string]string
	if err := json.NewDecoder(getResp.Body).Decode(&getResult); err != nil {
		t.Fatalf("Failed to decode get: %v", err)
	}
	if getResult["value"] != "super_secret_db_pass" {
		t.Errorf("Expected super_secret_db_pass, got %s", getResult["value"])
	}

	newSecret := map[string]string{"key": "new_key", "value": "new_value"}
	newBody, _ := json.Marshal(newSecret)
	createResp, err := http.Post(ts.URL+"/keeper/secrets", "application/json", bytes.NewReader(newBody))
	if err != nil {
		t.Fatalf("Failed to create: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", createResp.StatusCode)
	}

	deleteReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/keeper/secrets/new_key", nil)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("Failed to delete: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", deleteResp.StatusCode)
	}
}

func TestKeeperRouter_SetWithBase64(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Store: store, Logger: testLogger}, r)

	ts := httptest.NewServer(r)
	defer ts.Close()

	unlockPayload := map[string]string{"passphrase": passphrase}
	body, _ := json.Marshal(unlockPayload)
	resp, err := http.Post(ts.URL+"/keeper/unlock", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to unlock: %v", err)
	}
	resp.Body.Close()

	testValue := "test-value-123"
	encodedValue := base64.StdEncoding.EncodeToString([]byte(testValue))
	setPayload := map[string]interface{}{
		"key":   "b64_key",
		"value": encodedValue,
		"b64":   true,
	}
	setBody, _ := json.Marshal(setPayload)
	setResp, err := http.Post(ts.URL+"/keeper/secrets", "application/json", bytes.NewReader(setBody))
	if err != nil {
		t.Fatalf("Failed to set: %v", err)
	}
	defer setResp.Body.Close()

	if setResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", setResp.StatusCode)
	}

	getResp, err := http.Get(ts.URL + "/keeper/secrets/b64_key")
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}
	defer getResp.Body.Close()

	var getResult map[string]string
	if err := json.NewDecoder(getResp.Body).Decode(&getResult); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	if getResult["value"] != testValue {
		t.Errorf("Expected %s, got %s", testValue, getResult["value"])
	}
}

func TestKeeperRouter_UnauthorizedWhenLocked(t *testing.T) {
	store, _, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Store: store, Logger: testLogger}, r)

	ts := httptest.NewServer(r)
	defer ts.Close()

	listResp, err := http.Get(ts.URL + "/keeper/secrets")
	if err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusLocked {
		t.Errorf("Expected 423, got %d", listResp.StatusCode)
	}
}
