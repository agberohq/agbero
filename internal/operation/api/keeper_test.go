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

	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
)

// setupKeeperTest creates a fresh keeper store pre-populated with test secrets
// and returns it locked so each test controls the unlock step.
//
// Bucket setup:
//
//	keeper.New creates default:__default__ only.
//	Every other namespace used here needs an explicit CreateBucket call
//	while the store is unlocked so the envelope is seeded immediately.
func setupKeeperTest(t *testing.T) (*keeper.Keeper, string, func()) {
	t.Helper()
	tmpDir := t.TempDir()

	store, err := keeper.New(keeper.Config{DBPath: filepath.Join(tmpDir, "test.db")})
	if err != nil {
		t.Fatalf("keeper.New failed: %v", err)
	}

	passphrase := []byte("test-passphrase-123")
	if err := store.Unlock(passphrase); err != nil {
		store.Close()
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create one LevelPasswordOnly bucket per namespace we are about to write.
	// parseKeyExtended("prod/db_password") -> scheme=default, namespace=prod
	// parseKeyExtended("staging/x")        -> scheme=default, namespace=staging
	// All these share the "default" scheme; only the namespace differs.
	for _, ns := range []string{"prod", "staging"} {
		if err := store.CreateBucket("default", ns, keeper.LevelPasswordOnly, "test"); err != nil {
			store.Close()
			t.Fatalf("CreateBucket default/%s failed: %v", ns, err)
		}
	}

	// Pre-populate user-space secrets (default scheme, various namespaces).
	userSecrets := map[string][]byte{
		"prod/db_password":       []byte("super_secret_db_pass"),
		"prod/api_key":           []byte("abc123xyz789"),
		"staging/connection_url": []byte("postgres://localhost:5432/test"),
	}
	for key, val := range userSecrets {
		if err := store.Set(key, val); err != nil {
			store.Close()
			t.Fatalf("Set %q failed: %v", key, err)
		}
	}

	if err := store.Lock(); err != nil {
		store.Close()
		t.Fatalf("Lock failed: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}
	return store, string(passphrase), cleanup
}

func unlockStore(t *testing.T, srv *httptest.Server, passphrase string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"passphrase": passphrase})
	resp, err := http.Post(srv.URL+"/keeper/unlock", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unlock request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock: want 200, got %d", resp.StatusCode)
	}
}

func TestKeeperRouter_UnlockLock(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	lockResp, err := http.Post(srv.URL+"/keeper/lock", "application/json", nil)
	if err != nil {
		t.Fatalf("lock request failed: %v", err)
	}
	defer lockResp.Body.Close()
	if lockResp.StatusCode != http.StatusOK {
		t.Errorf("lock: want 200, got %d", lockResp.StatusCode)
	}
}

func TestKeeperRouter_Status(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Locked status.
	resp, _ := http.Get(srv.URL + "/keeper/status")
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if m["locked"] != true {
		t.Errorf("locked before unlock: want true, got %v", m["locked"])
	}

	unlockStore(t, srv, passphrase)

	// Unlocked status.
	resp2, _ := http.Get(srv.URL + "/keeper/status")
	json.NewDecoder(resp2.Body).Decode(&m)
	resp2.Body.Close()
	if m["locked"] != false {
		t.Errorf("locked after unlock: want false, got %v", m["locked"])
	}
}

func TestKeeperRouter_UnauthorizedWhenLocked(t *testing.T) {
	store, _, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/keeper/secrets")
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusLocked {
		t.Errorf("list while locked: want 423, got %d", resp.StatusCode)
	}
}

func TestKeeperRouter_CRUD(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	// List — the list handler iterates all namespaces in the "default" scheme
	// and returns "namespace/key" paths. We have prod/db_password, prod/api_key,
	// staging/connection_url = 3 keys.
	listResp, err := http.Get(srv.URL + "/keeper/secrets")
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	var listResult map[string][]string
	json.NewDecoder(listResp.Body).Decode(&listResult)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("list: want 200, got %d", listResp.StatusCode)
	}
	if len(listResult["keys"]) != 3 {
		t.Errorf("list: want 3 keys, got %d: %v", len(listResult["keys"]), listResult["keys"])
	}

	// Get a known secret.
	getResp, err := http.Get(srv.URL + "/keeper/secrets/prod/db_password")
	if err != nil {
		t.Fatalf("get request failed: %v", err)
	}
	var getResult map[string]any
	json.NewDecoder(getResp.Body).Decode(&getResult)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("get: want 200, got %d", getResp.StatusCode)
	}

	// Decode the base64 value
	decodedValue, err := base64.StdEncoding.DecodeString(getResult["value"].(string))
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	if string(decodedValue) != "super_secret_db_pass" {
		t.Errorf("get value: want super_secret_db_pass, got %s", string(decodedValue))
	}

	// Set a new secret — the handler calls ensureDefaultBucket so no pre-creation needed.
	setBody, _ := json.Marshal(map[string]string{"key": "staging/new_key", "value": "new_value"})
	createResp, err := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(setBody))
	if err != nil {
		t.Fatalf("set request failed: %v", err)
	}
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusOK {
		t.Errorf("set: want 200, got %d", createResp.StatusCode)
	}

	// Delete it.
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/keeper/secrets/staging/new_key", nil)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Errorf("delete: want 200, got %d", delResp.StatusCode)
	}
}

func TestKeeperRouter_RequiresNamespace(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	tests := []struct {
		name       string
		key        string
		expectCode int
	}{
		{"valid namespace/key", "prod/test_key", http.StatusOK},
		{"valid ss:// scheme", "ss://prod/test_key2", http.StatusOK},
		{"missing namespace", "test_key", http.StatusBadRequest},
		{"empty key", "", http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"key": tc.key, "value": "v"})
			resp, err := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.expectCode {
				t.Errorf("want %d, got %d", tc.expectCode, resp.StatusCode)
			}
		})
	}
}

func TestKeeperRouter_ReservedNamespacesBlocked(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	t.Run("set internal blocked", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"key": "internal/test_key", "value": "v"})
		resp, err := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("internal set: want 400, got %d", resp.StatusCode)
		}
	})

	t.Run("set vault:// blocked", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"key": "vault://admin/users/hacker", "value": "v"})
		resp, err := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("vault set: want 400, got %d", resp.StatusCode)
		}
	})

	// vault:// keys contain "://" which is not a valid URL path segment.
	// Clients cannot send them via GET/DELETE URLs. The protection is enforced
	// at the POST body level (tested above). We verify GET also blocks them
	// by using a key that starts with "vault" but is a valid path.
	// The real protection: isReserved() checks secret.Scheme == SchemeVault,
	// which is only set when the key is parsed as a full vault:// URI.
	// A bare path "vault/admin/users/alice" would have scheme=default — not blocked.
	// This is intentional: scheme-based routing is the user's opt-in.

	t.Run("delete internal blocked", func(t *testing.T) {
		// "internal/blocked" -> namespace="internal" -> IsInternal()=true -> 403
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/keeper/secrets/internal/blocked", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("internal delete: want 403, got %d", resp.StatusCode)
		}
	})

	t.Run("user-space allowed", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"key": "staging/valid_key", "value": "v"})
		resp, err := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("user set: want 200, got %d", resp.StatusCode)
		}
	})
}

func TestKeeperRouter_SetWithBase64(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	testValue := "test-value-123"
	encoded := base64.StdEncoding.EncodeToString([]byte(testValue))

	setBody, _ := json.Marshal(map[string]any{
		"key":   "staging/b64_key",
		"value": encoded,
		"b64":   true,
	})
	setResp, err := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(setBody))
	if err != nil {
		t.Fatalf("set request failed: %v", err)
	}
	setResp.Body.Close()
	if setResp.StatusCode != http.StatusOK {
		t.Errorf("set: want 200, got %d", setResp.StatusCode)
	}

	getResp, err := http.Get(srv.URL + "/keeper/secrets/staging/b64_key")
	if err != nil {
		t.Fatalf("get request failed: %v", err)
	}
	var m map[string]any
	json.NewDecoder(getResp.Body).Decode(&m)
	getResp.Body.Close()

	// Decode the base64 value
	decodedValue, err := base64.StdEncoding.DecodeString(m["value"].(string))
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	if string(decodedValue) != testValue {
		t.Errorf("b64 value: want %q, got %q", testValue, string(decodedValue))
	}
}

func TestKeeperRouter_GetWithScheme(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	tests := []struct {
		name       string
		urlPath    string
		expectCode int
		expectVal  string
	}{
		{"bare namespace/key", "prod/db_password", http.StatusOK, "super_secret_db_pass"},
		{"ss:// scheme", "ss://prod/db_password", http.StatusOK, "super_secret_db_pass"},
		{"missing namespace", "invalid", http.StatusBadRequest, ""},
		// vault:// in a URL path is malformed; protection is at POST body level.
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + "/keeper/secrets/" + tc.urlPath)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.expectCode {
				t.Errorf("want %d, got %d", tc.expectCode, resp.StatusCode)
			}
			if tc.expectVal != "" {
				var m map[string]any
				json.NewDecoder(resp.Body).Decode(&m)

				// Decode the base64 value
				decodedValue, err := base64.StdEncoding.DecodeString(m["value"].(string))
				if err != nil {
					t.Fatalf("failed to decode base64: %v", err)
				}

				if string(decodedValue) != tc.expectVal {
					t.Errorf("value: want %q, got %q", tc.expectVal, string(decodedValue))
				}
			}
		})
	}
}

func TestKeeperRouter_DeleteWithScheme(t *testing.T) {
	store, passphrase, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	unlockStore(t, srv, passphrase)

	// Create something to delete.
	setBody, _ := json.Marshal(map[string]string{"key": "staging/to_delete", "value": "delete_me"})
	createResp, _ := http.Post(srv.URL+"/keeper/secrets", "application/json", bytes.NewReader(setBody))
	createResp.Body.Close()

	// Delete via ss:// prefix.
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/keeper/secrets/ss://staging/to_delete", nil)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Errorf("delete: want 200, got %d", delResp.StatusCode)
	}
}

func TestKeeperRouter_UnlockWrongPassphrase(t *testing.T) {
	store, _, cleanup := setupKeeperTest(t)
	defer cleanup()

	r := chi.NewRouter()
	KeeperHandler(&Shared{Keeper: store, Logger: testLogger}, r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"passphrase": "definitely-wrong"})
	resp, err := http.Post(srv.URL+"/keeper/unlock", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong passphrase: want 401, got %d", resp.StatusCode)
	}
}
