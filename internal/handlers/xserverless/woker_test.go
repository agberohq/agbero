// Package xserverless_test provides unit tests for the serverless binary worker handler.
// It verifies that processes are spawned and their output is correctly streamed.
package xserverless

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/orchestrator"
)

const (
	testWorkerName   = "test-echo"
	testResponseText = "hello-from-worker"
)

// TestWorkerServeHTTP checks if the worker handler correctly executes a shell command.
// It verifies that stdout from the process is captured and returned as the HTTP response body.
func TestWorkerServeHTTP(t *testing.T) {
	res := resource.New()
	tempWork := t.TempDir()

	orch := orchestrator.New(res.Logger, tempWork, nil, nil)

	uniqueString := "agbero-test-token-" + zulu.XXHash([]byte(t.Name()))
	var cmd []string
	if runtime.GOOS == "windows" {
		cmd = []string{"cmd", "/c", "echo", uniqueString}
	} else {
		cmd = []string{"echo", uniqueString}
	}

	work := alaye.Work{
		Name:    "test-worker",
		Command: cmd,
	}

	handler := NewWorker(WorkerConfig{
		Resource: res,
		Work:     work,
		Orch:     orch,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	actual := strings.TrimSpace(rr.Body.String())
	if actual != uniqueString {
		t.Errorf("expected output %q, got %q", uniqueString, actual)
	}
}

// TestWorkerExecutionFailure verifies the error handling when a worker process fails to start.
// It confirms that an internal server error is returned to the client.
func TestWorkerExecutionFailure(t *testing.T) {
	res := resource.New()
	orch := orchestrator.New(res.Logger, os.TempDir(), nil, nil)

	work := alaye.Work{
		Name:    "fail-worker",
		Command: []string{"non-existent-binary-xyz"},
	}

	handler := NewWorker(WorkerConfig{
		Resource: res,
		Work:     work,
		Orch:     orch,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 for failed execution, got %d", rr.Code)
	}
}
