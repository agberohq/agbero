package xserverless

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/cook"
	"github.com/agberohq/agbero/internal/hub/orchestrator"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// helpers

// setupTestRepo initialises a local bare git repo with one commit.
// Mirrors the helper in the cook package tests — no network required.
func setupTestRepo(t *testing.T, path string) {
	t.Helper()
	r, err := git.PlainInit(path, false)
	if err != nil {
		t.Fatalf("git init failed: %v", err)
	}
	w, err := r.Worktree()
	if err != nil {
		t.Fatalf("worktree failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "script.sh"), []byte(`#!/bin/sh
		echo hello`), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := w.Add("script.sh"); err != nil {
		t.Fatalf("git add failed: %v", err)
	}
	if _, err := w.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "t@t.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
}

func testLogger(t *testing.T) *ll.Logger {
	t.Helper()
	return ll.New("test").Disable()
}

func testResource(t *testing.T) *resource.Resource {
	t.Helper()
	res := resource.New()
	res.Logger = testLogger(t)
	return res
}

func testOrch(t *testing.T, allowed []string) *orchestrator.Manager {
	t.Helper()
	return orchestrator.New(orchestrator.Config{
		Logger:          testLogger(t),
		WorkDir:         expect.NewFolder(t.TempDir()),
		AllowedCommands: allowed,
	})
}

// rootRoute returns a route with an explicit serverless.root — the most
// common non-git configuration.
func rootRoute(t *testing.T) alaye.Route {
	t.Helper()
	return alaye.Route{
		Serverless: alaye.Serverless{Root: t.TempDir()},
	}
}

func testHandler(t *testing.T, work alaye.Work, route alaye.Route, orch *orchestrator.Manager) *WorkerHandler {
	t.Helper()
	return NewWorker(WorkerConfig{
		Resource: testResource(t),
		Work:     work,
		Route:    route,
		Orch:     orch,
	})
}

func serve(t *testing.T, h *WorkerHandler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// core execution

func TestWorkerServeHTTP_Success(t *testing.T) {
	work := alaye.Work{
		Name:    "echo-worker",
		Command: []string{"sh", "-c", "echo hello-agbero"},
	}
	rr := serve(t, testHandler(t, work, rootRoute(t), testOrch(t, []string{"sh"})))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "hello-agbero") {
		t.Errorf("expected 'hello-agbero' in body, got %q", rr.Body.String())
	}
}

func TestWorkerServeHTTP_StdinForwarded(t *testing.T) {
	work := alaye.Work{
		Name:    "cat-worker",
		Command: []string{"sh", "-c", "cat"},
	}
	handler := testHandler(t, work, rootRoute(t), testOrch(t, []string{"sh"}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("forwarded-body"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "forwarded-body") {
		t.Errorf("expected stdin forwarded to worker, got %q", rr.Body.String())
	}
}

func TestWorkerServeHTTP_NonZeroExit(t *testing.T) {
	work := alaye.Work{
		Name:    "fail-worker",
		Command: []string{"sh", "-c", "exit 1"},
	}
	rr := serve(t, testHandler(t, work, rootRoute(t), testOrch(t, []string{"sh"})))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-zero exit, got %d", rr.Code)
	}
}

// allowlist enforcement

func TestWorkerServeHTTP_BlockedCommand(t *testing.T) {
	work := alaye.Work{
		Name:    "blocked-worker",
		Command: []string{"curl", "https://example.com"},
	}
	rr := serve(t, testHandler(t, work, rootRoute(t), testOrch(t, []string{"sh"})))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for blocked command, got %d", rr.Code)
	}
}

func TestWorkerServeHTTP_EmptyAllowlist(t *testing.T) {
	work := alaye.Work{
		Name:    "any-worker",
		Command: []string{"sh", "-c", "echo should-not-run"},
	}
	rr := serve(t, testHandler(t, work, rootRoute(t), testOrch(t, []string{})))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 with empty allowlist, got %d", rr.Code)
	}
}

// misconfiguration guards

func TestWorkerServeHTTP_NilOrch(t *testing.T) {
	handler := NewWorker(WorkerConfig{
		Resource: testResource(t),
		Work:     alaye.Work{Name: "w", Command: []string{"sh", "-c", "exit 0"}},
		Route:    rootRoute(t),
		Orch:     nil,
	})
	rr := serve(t, handler)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for nil orch, got %d", rr.Code)
	}
}

// web.git isolation

// TestWorker_WebGitNotUsed verifies that a route with web.git enabled does
// NOT cause the worker to use the web git checkout as its working directory.
// web and serverless are intentionally separated — executed scripts must never
// be co-located with publicly served files.
func TestWorker_WebGitNotUsed(t *testing.T) {
	work := alaye.Work{
		Name:    "isolation-check",
		Command: []string{"sh", "-c", "echo dir=$(pwd)"},
	}

	// Route has web.git enabled but no serverless.git and no serverless.root.
	// ResolveDir must fall through to the workDir default, not the web git path.
	route := alaye.Route{
		Web: alaye.Web{
			Git: alaye.Git{
				Enabled: expect.Active,
				ID:      "web-repo",
			},
		},
	}

	orch := testOrch(t, []string{"sh"})
	rr := serve(t, testHandler(t, work, route, orch))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The working directory must be under the orchestrator's workDir,
	// not under any web git checkout path.
	body := rr.Body.String()
	if strings.Contains(body, "web-repo") {
		t.Errorf("worker used web git path — isolation broken: %s", body)
	}
}

// serverless.git pending

// TestWorker_ServerlessGitPending verifies that when serverless.git is enabled
// but the cook manager has not yet completed the initial clone, the handler
// returns 503 rather than executing in an empty or wrong directory.
//
// We simulate "registered but not deployed" by submitting the Register call
// with a zero-worker pool — the initial Make is queued but never runs, so
// CurrentPath returns "".
func TestWorker_ServerlessGitPending(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "upstream")
	setupTestRepo(t, upstream)

	// Block the pool with a long-running task before registering.
	// Register submits the initial Make asynchronously — since the pool
	// worker is occupied, CurrentPath stays empty for the duration of
	// this test.
	blocked := make(chan struct{})
	idlePool := jack.NewPool(1)
	defer func() {
		close(blocked)
		idlePool.Shutdown(time.Second)
	}()
	_ = idlePool.Submit(jack.Func(func() error {
		<-blocked // holds the single worker until test cleanup
		return nil
	}))
	// Give the blocker task time to be picked up by the worker.
	time.Sleep(10 * time.Millisecond)

	cookMgr, err := cook.NewManager(cook.ManagerConfig{
		WorkDir: expect.NewFolder(t.TempDir()),
		Pool:    idlePool,
		Logger:  testLogger(t),
	})
	if err != nil {
		t.Fatalf("cook.NewManager failed: %v", err)
	}

	const gitID = "pending-serverless-repo"
	if err := cookMgr.Register(gitID, alaye.Git{
		Enabled: expect.Active,
		ID:      gitID,
		URL:     upstream,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Confirm the path is indeed empty (clone not yet run).
	if cookMgr.CurrentPath(gitID) != "" {
		t.Fatal("expected empty CurrentPath before deployment")
	}

	orch := orchestrator.New(orchestrator.Config{
		Logger:          testLogger(t),
		WorkDir:         expect.NewFolder(t.TempDir()),
		CookMgr:         cookMgr,
		AllowedCommands: []string{"sh"},
	})

	route := alaye.Route{
		Serverless: alaye.Serverless{
			Git: alaye.Git{
				Enabled: expect.Active,
				ID:      gitID,
			},
		},
	}

	handler := testHandler(t, alaye.Work{
		Name:    "pending-worker",
		Command: []string{"sh", "-c", "echo should-not-run"},
	}, route, orch)

	rr := serve(t, handler)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for pending git deployment, got %d: %s", rr.Code, rr.Body.String())
	}
}
