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
	"github.com/agberohq/agbero/internal/core/def"
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

// helpers

func testManager(t *testing.T) *Manager {
	t.Helper()
	pool := jack.NewPool(testPoolSize)
	t.Cleanup(func() { pool.Shutdown(time.Second) })
	mgr, err := NewManager(ManagerConfig{
		WorkDir: expect.NewFolder(t.TempDir()),
		Pool:    pool,
		Logger:  ll.New("test").Disable(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { mgr.Stop() })
	return mgr
}

func signBody(t *testing.T, body []byte, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func webhookRequest(t *testing.T, body []byte, secret string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Hub-Signature-256", signBody(t, body, secret))
	}
	return req
}

func waitForPath(t *testing.T, mgr *Manager, routeKey string) string {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if p := mgr.CurrentPath(routeKey); p != "" {
			return p
		}
		time.Sleep(testPollInterval)
	}
	t.Fatalf("timed out waiting for CurrentPath(%q)", routeKey)
	return ""
}

// NewManager

func TestManager_NewManager(t *testing.T) {
	logger := ll.New("test").Disable()
	pool := jack.NewPool(testPoolSize)
	defer pool.Shutdown(time.Second)

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
		_, err := NewManager(ManagerConfig{Pool: pool, Logger: logger})
		if err == nil {
			t.Error("expected error for missing workDir")
		}
	})
	t.Run("missing pool", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			WorkDir: expect.NewFolder(t.TempDir()),
			Logger:  logger,
		})
		if err == nil {
			t.Error("expected error for missing pool")
		}
	})
}

// pull mode (URL + interval)

func TestManager_PullMode_Register_And_Clone(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled:  expect.Active,
		ID:       "pull-route",
		URL:      upstream,
		Branch:   "master",
		Interval: expect.Duration(30 * time.Minute), // pull mode
		Mode:     def.GitModePull,
	}
	if err := mgr.Register("pull-route", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	path := waitForPath(t, mgr, "pull-route")
	if _, err := os.Stat(filepath.Join(path, "index.html")); err != nil {
		t.Errorf("expected index.html in deployment: %v", err)
	}
}

func TestManager_PullMode_WebhookReturns405(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled:  expect.Active,
		ID:       "pull-only",
		URL:      upstream,
		Branch:   "master",
		Interval: expect.Duration(30 * time.Minute),
		Mode:     def.GitModePull,
	}
	if err := mgr.Register("pull-only", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitForPath(t, mgr, "pull-only")

	body, _ := json.Marshal(WebhookPayload{Ref: "refs/heads/master"})
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, webhookRequest(t, body, ""), "pull-only")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for pull-only webhook, got %d", w.Code)
	}
}

// push mode (URL + secret)

func TestManager_PushMode_Webhook_ValidSignature(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	const secret = "my_super_secret"
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "push-route",
		URL:     upstream,
		Branch:  "master",
		Secret:  expect.Value(secret),
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("push-route", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitForPath(t, mgr, "push-route")

	body, _ := json.Marshal(WebhookPayload{Ref: "refs/heads/master", After: "abc123"})
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, webhookRequest(t, body, secret), "push-route")
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestManager_PushMode_Webhook_InvalidSignature(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "push-sig",
		URL:     upstream,
		Branch:  "master",
		Secret:  expect.Value("correct-secret"),
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("push-sig", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitForPath(t, mgr, "push-sig")

	body, _ := json.Marshal(WebhookPayload{Ref: "refs/heads/master"})
	req := webhookRequest(t, body, "wrong-secret")
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, req, "push-sig")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid signature, got %d", w.Code)
	}
}

func TestManager_PushMode_Webhook_BranchMismatch(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	const secret = "branch-secret"
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "push-branch",
		URL:     upstream,
		Branch:  "master",
		Secret:  expect.Value(secret),
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("push-branch", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitForPath(t, mgr, "push-branch")

	body, _ := json.Marshal(WebhookPayload{Ref: "refs/heads/other-branch"})
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, webhookRequest(t, body, secret), "push-branch")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for branch mismatch (ignored), got %d", w.Code)
	}
}

// both mode (URL + interval + secret)

func TestManager_BothMode_PollsAndAcceptsWebhook(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	const secret = "both-secret"
	cfg := alaye.Git{
		Enabled:  expect.Active,
		ID:       "both-route",
		URL:      upstream,
		Branch:   "master",
		Secret:   expect.Value(secret),
		Interval: expect.Duration(30 * time.Minute),
		Mode:     def.GitModeBoth,
	}
	if err := mgr.Register("both-route", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitForPath(t, mgr, "both-route")

	// Webhook should also work in both mode.
	body, _ := json.Marshal(WebhookPayload{Ref: "refs/heads/master", After: "abc123"})
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, webhookRequest(t, body, secret), "both-route")
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

// push-only mode (no URL)

func TestManager_PushOnly_Register(t *testing.T) {
	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "push-only-route",
		URL:     "", // no clone
		Secret:  expect.Value("push-secret"),
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("push-only-route", cfg); err != nil {
		t.Fatalf("Register push-only: %v", err)
	}
	// CurrentPath must be set immediately — no clone to wait for.
	if p := mgr.CurrentPath("push-only-route"); p == "" {
		t.Error("expected CurrentPath to be set immediately for push-only mode")
	}
}

func TestManager_PushOnly_RequiresSecret(t *testing.T) {
	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "no-secret",
		URL:     "",
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("no-secret", cfg); err == nil {
		t.Error("expected error for push-only mode without secret")
	}
}

func TestManager_PushOnly_Webhook_WritesPayload(t *testing.T) {
	mgr := testManager(t)
	const secret = "push-only-secret"
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "push-only-write",
		URL:     "",
		Secret:  expect.Value(secret),
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("push-only-write", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	payload := map[string]string{"message": "hello from webhook"}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, webhookRequest(t, body, secret), "push-only-write")
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	workDir := mgr.CurrentPath("push-only-write")

	// Update the assertion to look for the hidden file ".payload.json"
	written, err := os.ReadFile(filepath.Join(workDir, ".payload.json"))
	if err != nil {
		t.Fatalf(".payload.json not written: %v", err)
	}
	if !bytes.Equal(written, body) {
		t.Errorf("payload mismatch: got %q, want %q", written, body)
	}
}

func TestManager_PushOnly_Webhook_InvalidSignature(t *testing.T) {
	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled: expect.Active,
		ID:      "push-only-sig",
		URL:     "",
		Secret:  expect.Value("correct"),
		Mode:    def.GitModePush,
	}
	if err := mgr.Register("push-only-sig", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"x": "y"})
	req := webhookRequest(t, body, "wrong")
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, req, "push-only-sig")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// unknown route

func TestManager_Webhook_UnknownRoute(t *testing.T) {
	mgr := testManager(t)
	body, _ := json.Marshal(WebhookPayload{Ref: "refs/heads/master"})
	w := httptest.NewRecorder()
	mgr.HandleWebhook(w, webhookRequest(t, body, ""), "does-not-exist")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// health

func TestManager_Health(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	cfg := alaye.Git{
		Enabled:  expect.Active,
		ID:       "healthy-route",
		URL:      upstream,
		Branch:   "master",
		Interval: expect.Duration(30 * time.Minute),
		Mode:     def.GitModePull,
	}
	if err := mgr.Register("healthy-route", cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitForPath(t, mgr, "healthy-route")

	health := mgr.Health()
	if len(health) != 1 {
		t.Fatalf("expected 1 health entry, got %d", len(health))
	}
	if health["healthy-route"].State != "healthy" {
		t.Errorf("expected healthy state, got %s", health["healthy-route"].State)
	}
}

// prune

func TestManager_Prune(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	mgr := testManager(t)
	for _, id := range []string{"keep", "remove"} {
		cfg := alaye.Git{
			Enabled:  expect.Active,
			ID:       id,
			URL:      upstream,
			Branch:   "master",
			Interval: expect.Duration(30 * time.Minute),
			Mode:     def.GitModePull,
		}
		if err := mgr.Register(id, cfg); err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}

	mgr.Prune(map[string]bool{"keep": true})

	if mgr.CurrentPath("remove") != "" {
		t.Error("expected 'remove' to be pruned")
	}
}
