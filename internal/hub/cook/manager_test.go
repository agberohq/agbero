package cook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

const (
	testPoolSize     = 2
	testPollInterval = 50 * time.Millisecond
	testTimeout      = 5 * time.Second
	testCleanupSleep = 300 * time.Millisecond
)

// Tests the initialization logic for the cook manager
// Ensures valid instances are created and invalid configurations return errors
func TestManager_NewManager(t *testing.T) {
	logger := ll.New("test").Disable()
	pool := jack.NewPool(testPoolSize)
	t.Run("valid", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			WorkDir: expect.NewFolder(t.TempDir()),
			Pool:    pool,
			Logger:  logger,
		})
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}
	})
	t.Run("missing workDir", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			WorkDir: "",
			Pool:    pool,
			Logger:  logger,
		})
		if err == nil {
			t.Error("expected error for missing workDir")
		}
	})
	t.Run("missing pool", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			WorkDir: expect.NewFolder(t.TempDir()),
			Pool:    nil,
			Logger:  logger,
		})
		if err == nil {
			t.Error("expected error for missing pool")
		}
	})
}

// Tests the registration and webhook handling workflow
// Verifies successful cloning, valid signature processing, and invalid signature rejection
func TestManager_Register_And_Webhook(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	//workDir := t.TempDir()
	setupTestRepo(t, upstream)
	logger := ll.New("test").Disable()
	pool := jack.NewPool(testPoolSize)
	mgr, err := NewManager(ManagerConfig{
		WorkDir: expect.NewFolder(t.TempDir()),
		Pool:    pool,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	t.Cleanup(func() {
		mgr.Stop()
		time.Sleep(testCleanupSleep)
	})
	cfg := alaye.Git{
		Enabled:  expect.Active,
		URL:      upstream,
		Branch:   "master",
		Secret:   expect.Value("my_super_secret"),
		Interval: 0,
	}
	err = mgr.Register("test_route", cfg)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	deadline := time.Now().Add(testTimeout)
	var path string
	for time.Now().Before(deadline) {
		path = mgr.CurrentPath("test_route")
		if path != "" {
			break
		}
		time.Sleep(testPollInterval)
	}
	if path == "" {
		t.Fatal("expected current path to be set after register, timed out waiting for clone")
	}

	payload := WebhookPayload{
		Ref:    "refs/heads/master",
		Before: "0000000",
		After:  "1111111",
	}
	body, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte("my_super_secret"))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", signature)
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, req, "test_route")
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid")
	w = httptest.NewRecorder()
	mgr.HandleWebhook(w, req, "test_route")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for bad signature, got %d", w.Code)
	}
}

// Tests the health summary generation
// Validates that active deployments reflect a healthy state dynamically
func TestManager_Health(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)
	logger := ll.New("test").Disable()
	pool := jack.NewPool(testPoolSize)
	mgr, _ := NewManager(ManagerConfig{
		WorkDir: expect.NewFolder(t.TempDir()),
		Pool:    pool,
		Logger:  logger,
	})
	defer mgr.Stop()
	cfg := alaye.Git{
		Enabled: expect.Active,
		URL:     upstream,
		Branch:  "master",
	}
	_ = mgr.Register("healthy_route", cfg)

	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if mgr.CurrentPath("healthy_route") != "" {
			break
		}
		time.Sleep(testPollInterval)
	}

	health := mgr.Health()
	if len(health) != 1 {
		t.Fatalf("expected 1 health entry, got %d", len(health))
	}
	status := health["healthy_route"]
	if status.State != "healthy" {
		t.Errorf("expected healthy state, got %s", status.State)
	}
}

// Tests updating an existing registered Git route
// Verifies that redundant cloning operations are skipped while secrets and polling intervals update safely
func TestManager_Register_Update(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping: CI environment Git cleanup issues")
	}
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)
	logger := ll.New("test").Disable()
	pool := jack.NewPool(testPoolSize)

	workDir := expect.NewFolder(t.TempDir())
	mgr, _ := NewManager(ManagerConfig{
		WorkDir: workDir,
		Pool:    pool,
		Logger:  logger,
	})

	cfg1 := alaye.Git{
		Enabled:  expect.Active,
		URL:      upstream,
		Branch:   "master",
		Interval: alaye.Duration(50 * time.Millisecond), // Short interval to test
	}

	err := mgr.Register("update_route", cfg1)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Give it time to start polling
	time.Sleep(100 * time.Millisecond)

	cfg2 := alaye.Git{
		Enabled:  expect.Active,
		URL:      upstream,
		Branch:   "master",
		Secret:   expect.Value("new_secret"),
		Interval: alaye.Duration(1 * time.Minute),
	}

	err = mgr.Register("update_route", cfg2)
	if err != nil {
		t.Fatalf("Second Register failed: %v", err)
	}

	entry, ok := mgr.entries.Get("update_route")
	if !ok {
		t.Fatal("entry missing")
	}
	if entry.Config.Secret != "new_secret" {
		t.Errorf("expected secret to be updated to 'new_secret', got %q", entry.Config.Secret)
	}
	if entry.Config.Interval.StdDuration() != 1*time.Minute {
		t.Errorf("expected interval to be updated to 1m, got %v", entry.Config.Interval.StdDuration())
	}

	// Stop before cleanup
	mgr.Stop()
	time.Sleep(testCleanupSleep)
}
