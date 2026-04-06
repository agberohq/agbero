package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

// TestProcess_Run verifies that the Process struct correctly executes an OS command.
// It uses the test binary itself as the command to ensure cross-platform compatibility.
func TestProcess_Run(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		// Helper process: just print args and exit
		fmt.Fprintln(os.Stdout, os.Args[len(os.Args)-1])
		os.Exit(0)
	}

	logger := ll.New("test").Disable()
	buf := &bytes.Buffer{}

	proc := &Process{
		Config: alaye.Work{
			Name:    "test-echo",
			Command: []string{os.Args[0], "-test.run=TestProcess_Run", "--", "hello-agbero"},
		},
		Logger: logger,
	}

	proc.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")

	err := proc.Run(context.Background(), nil, buf)
	if err != nil {
		t.Fatalf("Process.Run failed: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != "hello-agbero" {
		t.Errorf("Expected 'hello-agbero', got %q", output)
	}
}

// TestManager_ResolveDir verifies the path resolution hierarchy of the orchestrator.
// It ensures that explicit roots take precedence over default managed paths.
func TestManager_ResolveDir(t *testing.T) {
	tmpDir := expect.NewFolder(t.TempDir())
	logger := ll.New("test").Disable()
	mgr := New(logger, tmpDir, nil, nil)

	host := "example.com"
	work := alaye.Work{Name: "worker1"}

	// Case 1: Default managed path
	routeDefault := alaye.Route{}
	resolvedDefault := mgr.ResolveDir(host, routeDefault, work)
	expectedDefault := tmpDir.FilePath("workers", host, "worker1")
	if resolvedDefault != expectedDefault {
		t.Errorf("Expected default path %q, got %q", expectedDefault, resolvedDefault)
	}

	// Case 2: Explicit root override
	routeOverride := alaye.Route{
		Serverless: alaye.Serverless{Root: "/custom/root"},
	}
	resolvedOverride := mgr.ResolveDir(host, routeOverride, work)
	if resolvedOverride != "/custom/root" {
		t.Errorf("Expected overridden path '/custom/root', got %q", resolvedOverride)
	}
}

// TestManager_ProvisionRunOnce verifies that 'RunOnce' tasks are executed immediately.
// It uses a temporary file to confirm that the command was actually run by the manager.
func TestManager_ProvisionRunOnce(t *testing.T) {
	tmpDir := expect.NewFolder(t.TempDir())
	markerFile := tmpDir.FilePath("done.txt")
	logger := ll.New("test").Disable()
	mgr := New(logger, tmpDir, nil, nil)

	route := alaye.Route{
		Serverless: alaye.Serverless{
			Enabled: alaye.Active,
			Workers: []alaye.Work{
				{
					Name:    "initializer",
					Command: []string{"touch", markerFile},
					RunOnce: true,
				},
			},
		},
	}

	err := mgr.Provision("localhost", route)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if !tmpDir.FileExists("done.txt") {
		t.Error("RunOnce task failed to execute: marker file not found")
	}
}

// TestManager_Stop verifies that the orchestrator manager shuts down all loopers.
// It ensures that the looper registry is empty after a stop signal is received.
func TestManager_Stop(t *testing.T) {
	tmpDir := expect.NewFolder(t.TempDir())
	logger := ll.New("test").Disable()
	mgr := New(logger, tmpDir, nil, nil)

	// Mock a background process using a long-running command
	proc := &Process{
		Config: alaye.Work{Name: "sleeper", Command: []string{"sleep", "10"}, Background: true},
		Logger: logger,
	}

	mgr.startLooper("sleeper", proc)

	if mgr.loopers.Len() != 1 {
		t.Errorf("Expected 1 looper, got %d", mgr.loopers.Len())
	}

	mgr.Stop()

	if mgr.loopers.Len() != 0 {
		t.Errorf("Expected 0 loopers after stop, got %d", mgr.loopers.Len())
	}
}
