package cook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

func TestManager_NewManager(t *testing.T) {
	logger := ll.New("test").Disable()
	pool := jack.NewPool(2)
	t.Run("valid", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			WorkDir: t.TempDir(),
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
			WorkDir: t.TempDir(),
			Pool:    nil,
			Logger:  logger,
		})
		if err == nil {
			t.Error("expected error for missing pool")
		}
	})
}

func TestManager_Register_And_Webhook(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()
	setupTestRepo(t, upstream)
	logger := ll.New("test").Disable()
	pool := jack.NewPool(2)
	mgr, err := NewManager(ManagerConfig{
		WorkDir: workDir,
		Pool:    pool,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	// Ensure cleanup happens before temp dir removal
	t.Cleanup(func() {
		mgr.Stop()
		// Wait for git processes to fully terminate
		time.Sleep(300 * time.Millisecond)
	})
	cfg := alaye.Git{
		Enabled:  alaye.Active,
		URL:      upstream,
		Branch:   "master",
		Secret:   alaye.Value("my_super_secret"),
		Interval: 0,
	}
	err = mgr.Register("test_route", cfg)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	// Poll for clone completion
	deadline := time.Now().Add(5 * time.Second)
	var path string
	for time.Now().Before(deadline) {
		path = mgr.CurrentPath("test_route")
		if path != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if path == "" {
		t.Fatal("expected current path to be set after register, timed out waiting for clone")
	}
	// Test Valid Webhook
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
	// Test Invalid Signature
	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid")
	w = httptest.NewRecorder()
	mgr.HandleWebhook(w, req, "test_route")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for bad signature, got %d", w.Code)
	}
}

func TestManager_Health(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()
	setupTestRepo(t, upstream)
	logger := ll.New("test").Disable()
	pool := jack.NewPool(2)
	mgr, _ := NewManager(ManagerConfig{
		WorkDir: workDir,
		Pool:    pool,
		Logger:  logger,
	})
	defer mgr.Stop()
	cfg := alaye.Git{
		Enabled: alaye.Active,
		URL:     upstream,
		Branch:  "master",
	}
	mgr.Register("healthy_route", cfg)
	time.Sleep(100 * time.Millisecond)
	health := mgr.Health()
	if len(health) != 1 {
		t.Fatalf("expected 1 health entry, got %d", len(health))
	}
	status := health["healthy_route"]
	if status.State != "healthy" {
		t.Errorf("expected healthy state, got %s", status.State)
	}
}
