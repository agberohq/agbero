package cook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// testingTB is a common interface for testing.T and testing.B
type testingTB interface {
	Helper()
	Fatalf(format string, args ...interface{})
	TempDir() string
}

func setupTestRepo(tb testingTB, path string) string {
	tb.Helper()

	r, err := git.PlainInit(path, false)
	if err != nil {
		tb.Fatalf("failed to init repo: %v", err)
	}

	w, err := r.Worktree()
	if err != nil {
		tb.Fatalf("failed to get worktree: %v", err)
	}

	err = os.WriteFile(filepath.Join(path, "index.html"), []byte("<h1>Hello World</h1>"), 0644)
	if err != nil {
		tb.Fatalf("failed to write file: %v", err)
	}

	_, err = w.Add("index.html")
	if err != nil {
		tb.Fatalf("failed to add file: %v", err)
	}

	commit, err := w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		tb.Fatalf("failed to commit: %v", err)
	}

	return commit.String()
}

func addCommit(t *testing.T, path string, content string) string {
	t.Helper()

	r, err := git.PlainOpen(path)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	w, err := r.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	err = os.WriteFile(filepath.Join(path, "index.html"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = w.Add("index.html")
	if err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	commit, err := w.Commit("Update", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	return commit.String()
}

func TestNew(t *testing.T) {
	logger := ll.New("test").Disable()

	t.Run("valid configuration", func(t *testing.T) {
		cfg := Config{
			ID:      "test-id",
			URL:     "https://github.com/example/repo.git",
			Branch:  "main",
			WorkDir: t.TempDir(),
			Logger:  logger,
		}
		c, err := New(cfg)
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		if c.config.ID != "test-id" {
			t.Errorf("expected ID 'test-id', got '%s'", c.config.ID)
		}
	})

	t.Run("missing ID", func(t *testing.T) {
		cfg := Config{
			ID:      "",
			URL:     "https://example.com",
			Branch:  "main",
			WorkDir: t.TempDir(),
			Logger:  logger,
		}
		_, err := New(cfg)
		if err == nil {
			t.Error("expected error for missing ID")
		}
	})

	t.Run("missing URL", func(t *testing.T) {
		cfg := Config{
			ID:      "test",
			URL:     "",
			Branch:  "main",
			WorkDir: t.TempDir(),
			Logger:  logger,
		}
		_, err := New(cfg)
		if err != ErrRepositoryNotSet {
			t.Errorf("expected ErrRepositoryNotSet, got %v", err)
		}
	})

	t.Run("missing workDir", func(t *testing.T) {
		cfg := Config{
			ID:      "test",
			URL:     "https://example.com",
			Branch:  "main",
			WorkDir: "",
			Logger:  logger,
		}
		_, err := New(cfg)
		if err != ErrWorkDirNotSet {
			t.Errorf("expected ErrWorkDirNotSet, got %v", err)
		}
	})
}

func TestCook_Make(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()

	initialCommit := setupTestRepo(t, upstream)

	logger := ll.New("test").Disable()
	cfg := Config{
		ID:      "route1",
		URL:     upstream,
		Branch:  "master",
		WorkDir: workDir,
		Logger:  logger,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// First deployment
	err = c.Make(context.Background())
	if err != nil {
		t.Fatalf("Make failed: %v", err)
	}

	currentPath := c.CurrentPath()
	if currentPath == "" {
		t.Fatal("CurrentPath is empty")
	}

	content, err := os.ReadFile(filepath.Join(currentPath, "index.html"))
	if err != nil {
		t.Fatalf("failed to read deployed file: %v", err)
	}
	if string(content) != "<h1>Hello World</h1>" {
		t.Fatalf("unexpected content: %s", string(content))
	}

	if c.CurrentCommit() != initialCommit {
		t.Errorf("expected commit %s, got %s", initialCommit[:8], c.CurrentCommit()[:8])
	}

	// Second deployment (same commit)
	err = c.Make(context.Background())
	if err != nil {
		t.Fatalf("second Make failed: %v", err)
	}

	// Add new commit and redeploy
	newContent := "<h1>Updated World</h1>"
	newCommit := addCommit(t, upstream, newContent)

	err = c.Make(context.Background())
	if err != nil {
		t.Fatalf("third Make failed: %v", err)
	}

	currentPath = c.CurrentPath()
	content, err = os.ReadFile(filepath.Join(currentPath, "index.html"))
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if string(content) != newContent {
		t.Fatalf("expected updated content, got: %s", string(content))
	}

	if c.CurrentCommit() != newCommit {
		t.Errorf("expected commit %s, got %s", newCommit[:8], c.CurrentCommit()[:8])
	}
}

func TestCook_Make_BadRepo(t *testing.T) {
	logger := ll.New("test").Disable()
	cfg := Config{
		ID:      "route_bad",
		URL:     "/does/not/exist",
		Branch:  "master",
		WorkDir: t.TempDir(),
		Logger:  logger,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = c.Make(context.Background())
	if err == nil {
		t.Fatal("expected Make to fail with bad repository URL")
	}
	if !strings.Contains(err.Error(), "clone failed") {
		t.Errorf("expected clone error, got: %v", err)
	}
}

func TestCook_Rollback(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()

	commit1 := setupTestRepo(t, upstream)

	logger := ll.New("test").Disable()
	cfg := Config{
		ID:      "test",
		URL:     upstream,
		Branch:  "master",
		WorkDir: workDir,
		Logger:  logger,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Deploy commit1
	if err := c.Make(context.Background()); err != nil {
		t.Fatalf("first make failed: %v", err)
	}

	// Add and deploy commit2
	commit2 := addCommit(t, upstream, "<h1>Version 2</h1>")
	if err := c.Make(context.Background()); err != nil {
		t.Fatalf("second make failed: %v", err)
	}

	// Verify we're on commit2
	content, _ := os.ReadFile(filepath.Join(c.CurrentPath(), "index.html"))
	if string(content) != "<h1>Version 2</h1>" {
		t.Fatalf("expected v2 content, got: %s", string(content))
	}

	// Rollback to commit1
	if err := c.Rollback(commit1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	content, _ = os.ReadFile(filepath.Join(c.CurrentPath(), "index.html"))
	if string(content) != "<h1>Hello World</h1>" {
		t.Errorf("rollback to v1 failed, got: %s", string(content))
	}

	// Rollback to commit2
	if err := c.Rollback(commit2); err != nil {
		t.Fatalf("rollback to v2 failed: %v", err)
	}

	content, _ = os.ReadFile(filepath.Join(c.CurrentPath(), "index.html"))
	if string(content) != "<h1>Version 2</h1>" {
		t.Errorf("rollback to v2 failed, got: %s", string(content))
	}

	// Invalid rollback
	if err := c.Rollback("invalid"); err == nil {
		t.Error("expected error for invalid commit")
	}
}

func TestCook_ListDeployments(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()

	setupTestRepo(t, upstream)
	addCommit(t, upstream, "<h1>V2</h1>")

	logger := ll.New("test").Disable()
	cfg := Config{
		ID:      "test",
		URL:     upstream,
		Branch:  "master",
		WorkDir: workDir,
		Logger:  logger,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Deploy first time (gets V2)
	if err := c.Make(context.Background()); err != nil {
		t.Fatalf("first make failed: %v", err)
	}

	// Add V3 and deploy again
	addCommit(t, upstream, "<h1>V3</h1>")
	if err := c.Make(context.Background()); err != nil {
		t.Fatalf("second make failed: %v", err)
	}

	deps, err := c.ListDeployments()
	if err != nil {
		t.Fatalf("ListDeployments failed: %v", err)
	}
	if len(deps) != 2 {
		t.Errorf("expected 2 deployments, got %d", len(deps))
	}
}

func TestCook_ConcurrentDeployments(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()
	setupTestRepo(t, upstream)

	logger := ll.New("test").Disable()
	cfg := Config{
		ID:      "concurrent",
		URL:     upstream,
		Branch:  "master",
		WorkDir: workDir,
		Logger:  logger,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	// Trigger multiple concurrent deployments
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			// Small stagger to avoid exact same timing
			time.Sleep(time.Duration(iteration) * 10 * time.Millisecond)

			if err := c.Make(context.Background()); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	errCount := 0
	for err := range errs {
		errCount++
		t.Logf("concurrent deployment error: %v", err)
	}

	// Some may fail due to concurrent git operations, but repo should remain consistent
	currentPath := c.CurrentPath()
	if currentPath == "" {
		t.Error("current path is empty after concurrent deployments")
	}
	t.Logf("Final deployment path: %s", currentPath)
}

func TestManager_NewManager(t *testing.T) {
	logger := ll.New("test").Disable()
	pool := jack.NewPool(2)

	t.Run("valid", func(t *testing.T) {
		_, err := NewManager(t.TempDir(), pool, logger)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}
	})

	t.Run("missing workDir", func(t *testing.T) {
		_, err := NewManager("", pool, logger)
		if err == nil {
			t.Error("expected error for missing workDir")
		}
	})

	t.Run("missing pool", func(t *testing.T) {
		_, err := NewManager(t.TempDir(), nil, logger)
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
	mgr, err := NewManager(workDir, pool, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

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

	// Poll for clone completion instead of fixed sleep
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
	mgr, _ := NewManager(workDir, pool, logger)
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

func TestCook_Cleanup(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	workDir := t.TempDir()

	setupTestRepo(t, upstream)

	logger := ll.New("test").Disable()
	cfg := Config{
		ID:       "test",
		URL:      upstream,
		Branch:   "master",
		WorkDir:  workDir,
		Logger:   logger,
		KeepLast: 2,
	}
	c, _ := New(cfg)

	// Deploy first commit
	if err := c.Make(context.Background()); err != nil {
		t.Fatalf("make 0 failed: %v", err)
	}

	// Add and deploy 3 more commits
	for i := 1; i <= 3; i++ {
		addCommit(t, upstream, fmt.Sprintf("<h1>V%d</h1>", i+1))
		if err := c.Make(context.Background()); err != nil {
			t.Fatalf("make %d failed: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for background cleanup
	time.Sleep(100 * time.Millisecond)

	deps, _ := c.ListDeployments()
	// With KeepLast=2, background cleanup keeps current + 2 = 3
	if len(deps) < 3 {
		t.Fatalf("expected at least 3 deployments, got %d", len(deps))
	}

	// Explicit cleanup keeping 2
	if err := c.Cleanup(2); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	deps, _ = c.ListDeployments()
	if len(deps) != 3 {
		t.Errorf("expected 3 deployments after cleanup (current + 2), got %d", len(deps))
	}
}

func BenchmarkCook_Make(b *testing.B) {
	upstream := filepath.Join(b.TempDir(), "upstream")
	workDir := b.TempDir()
	setupTestRepo(b, upstream)

	logger := ll.New("test").Disable()
	cfg := Config{
		ID:      "bench",
		URL:     upstream,
		Branch:  "master",
		WorkDir: workDir,
		Logger:  logger,
	}
	c, _ := New(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = c.Make(ctx)
		cancel()
	}
}
