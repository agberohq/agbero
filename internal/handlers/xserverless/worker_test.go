package xserverless

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/pkg/orchestrator"
)

const (
	testWorkerName = "test-echo"
)

// TestWorkerServeHTTP checks if the worker handler correctly executes a shell command.
// It verifies that stdout from the process is captured and returned as the HTTP response body.
func TestWorkerServeHTTP(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		fmt.Fprintln(os.Stdout, os.Getenv("TEST_UNIQUE_ID"))
		os.Exit(0)
	}

	res := resource.New()
	tempWork := t.TempDir()

	orch := orchestrator.New(res.Logger, tempWork, nil, nil)

	uniqueString := "agbero-test-token-" + fmt.Sprintf("%d", os.Getpid())
	var cmd []string
	if runtime.GOOS == "windows" {
		cmd = []string{os.Args[0], "-test.run=TestWorkerServeHTTP", "--"}
	} else {
		cmd = []string{os.Args[0], "-test.run=TestWorkerServeHTTP", "--"}
	}

	work := alaye.Work{
		Name:    testWorkerName,
		Command: cmd,
	}

	route := alaye.Route{
		Serverless: alaye.Serverless{
			Root: tempWork,
		},
	}

	handler := NewWorker(WorkerConfig{
		Resource: res,
		Work:     work,
		Route:    route,
		Orch:     orch,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test-Id", uniqueString)
	rr := httptest.NewRecorder()

	os.Setenv("GO_WANT_HELPER_PROCESS", "1")
	os.Setenv("TEST_UNIQUE_ID", uniqueString)
	defer os.Unsetenv("GO_WANT_HELPER_PROCESS")
	defer os.Unsetenv("TEST_UNIQUE_ID")

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

// TestWorkerGitDeploymentPending verifies that a 503 Service Unavailable is returned
// when the execution directory is empty and Git is enabled (signifying pending deployment).
//func TestWorkerGitDeploymentPending(t *testing.T) {
//	res := resource.New()
//	orch := orchestrator.New(res.Logger, os.TempDir(), nil, nil)
//
//	work := alaye.Work{
//		Name:    "git-worker",
//		Command:
