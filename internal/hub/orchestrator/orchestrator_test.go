package orchestrator

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

// test helpers

func testLogger(t *testing.T) *ll.Logger {
	t.Helper()
	return ll.New("test").Disable()
}

// newTestManager builds a Manager with an explicit allowlist.
// No defaults — mirrors production behaviour where the operator must
// declare every permitted command.
func newTestManager(t *testing.T, allowed []string) *Manager {
	t.Helper()
	return New(Config{
		Logger:          testLogger(t),
		WorkDir:         expect.NewFolder(t.TempDir()),
		AllowedCommands: allowed,
	})
}

// newTestProcess builds a Process with an explicit allowlist.
func newTestProcess(t *testing.T, cmd []string, allowed []string) *Process {
	t.Helper()
	allowedMap := make(map[string]bool, len(allowed))
	for _, c := range allowed {
		allowedMap[c] = true
	}
	return &Process{
		Config:          alaye.Work{Name: "test-worker", Command: cmd},
		Dir:             t.TempDir(),
		Logger:          testLogger(t),
		AllowedCommands: allowedMap,
	}
}

func TestProcess_Run_AllowedCommand(t *testing.T) {
	proc := newTestProcess(t, []string{"sh", "-c", "exit 0"}, []string{"sh"})
	if err := proc.Run(context.Background(), nil, nil); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestProcess_Run_CreatesWorkDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "dir")
	proc := newTestProcess(t, []string{"sh", "-c", "exit 0"}, []string{"sh"})
	proc.Dir = dir
	if err := proc.Run(context.Background(), nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("work directory was not created")
	}
}

func TestProcess_Run_BlockedCommand(t *testing.T) {
	// curl is not in the allowlist
	proc := newTestProcess(t, []string{"curl", "https://example.com"}, []string{"sh"})
	err := proc.Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "command not allowed") {
		t.Fatalf("expected 'command not allowed', got: %v", err)
	}
}

func TestProcess_Run_EmptyAllowlist(t *testing.T) {
	// Empty allowlist — nothing may run, not even sh
	proc := newTestProcess(t, []string{"sh", "-c", "exit 0"}, []string{})
	err := proc.Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "command not allowed") {
		t.Fatalf("expected 'command not allowed' with empty allowlist, got: %v", err)
	}
}

func TestProcess_Run_EmptyCommand(t *testing.T) {
	proc := newTestProcess(t, []string{}, []string{"sh"})
	err := proc.Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "empty command") {
		t.Fatalf("expected 'empty command', got: %v", err)
	}
}

func TestProcess_Run_NonZeroExit(t *testing.T) {
	proc := newTestProcess(t, []string{"sh", "-c", "exit 42"}, []string{"sh"})
	if err := proc.Run(context.Background(), nil, nil); err == nil {
		t.Fatal("expected non-zero exit to return error")
	}
}

func TestProcess_Run_StdoutCapture(t *testing.T) {
	var buf bytes.Buffer
	proc := newTestProcess(t, []string{"sh", "-c", "echo hello"}, []string{"sh"})
	if err := proc.Run(context.Background(), nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("expected 'hello' in output, got: %q", buf.String())
	}
}

func TestProcess_Run_StdinPipe(t *testing.T) {
	input := strings.NewReader("world\n")
	var buf bytes.Buffer
	proc := newTestProcess(t, []string{"sh", "-c", "cat"}, []string{"sh"})
	if err := proc.Run(context.Background(), input, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "world") {
		t.Fatalf("expected 'world' in output, got: %q", buf.String())
	}
}

func TestProcess_Run_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	proc := newTestProcess(t, []string{"sh", "-c", "sleep 60"}, []string{"sh"})

	done := make(chan error, 1)
	go func() { done <- proc.Run(ctx, nil, nil) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after context cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("process did not exit after context cancellation")
	}
}

// allowlist is explicit, no defaults

func TestNew_EmptyAllowlistBlocksEverything(t *testing.T) {
	mgr := newTestManager(t, []string{})
	if mgr.IsAllowed("sh") {
		t.Error("sh should not be allowed with empty allowlist")
	}
	if mgr.IsAllowed("python3") {
		t.Error("python3 should not be allowed with empty allowlist")
	}
}

func TestNew_ExplicitAllowlistHonoured(t *testing.T) {
	mgr := newTestManager(t, []string{"python3", "node"})
	if !mgr.IsAllowed("python3") {
		t.Error("python3 should be allowed")
	}
	if !mgr.IsAllowed("node") {
		t.Error("node should be allowed")
	}
	if mgr.IsAllowed("sh") {
		t.Error("sh should not be allowed — not declared")
	}
}

func TestNew_AllowedCommandsIsCopy(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	copy1 := mgr.AllowedCommands()
	copy1["injected"] = true
	if mgr.IsAllowed("injected") {
		t.Error("mutating the returned map affected internal state")
	}
}

// Manager.NewProcess wires allowlist

func TestManager_NewProcess_InheritsAllowlist(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	proc := mgr.NewProcess(
		alaye.Work{Name: "w", Command: []string{"sh", "-c", "exit 0"}},
		nil,
		t.TempDir(),
		testLogger(t),
	)
	if !proc.AllowedCommands["sh"] {
		t.Error("process should inherit sh from manager allowlist")
	}
	if proc.AllowedCommands["curl"] {
		t.Error("process should not have curl — not in manager allowlist")
	}
}

// Manager.Provision (RunOnce)

func TestManager_ProvisionRunOnce(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	marker := filepath.Join(t.TempDir(), "done.txt")

	route := alaye.Route{
		Serverless: alaye.Serverless{
			Root: t.TempDir(),
			Workers: []alaye.Work{
				{
					Name:    "marker-writer",
					Command: []string{"sh", "-c", "touch " + marker},
					RunOnce: true,
				},
			},
		},
	}

	if err := mgr.Provision("test.local", route); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	mgr.WaitRunOnce()

	if _, err := os.Stat(marker); os.IsNotExist(err) {
		t.Fatal("RunOnce task did not execute: marker file not found")
	}
}

func TestManager_ProvisionRunOnce_MultipleWorkers(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	dir := t.TempDir()

	workers := []alaye.Work{
		{Name: "w1", Command: []string{"sh", "-c", "touch " + filepath.Join(dir, "w1")}, RunOnce: true},
		{Name: "w2", Command: []string{"sh", "-c", "touch " + filepath.Join(dir, "w2")}, RunOnce: true},
		{Name: "w3", Command: []string{"sh", "-c", "touch " + filepath.Join(dir, "w3")}, RunOnce: true},
	}

	route := alaye.Route{Serverless: alaye.Serverless{Root: dir, Workers: workers}}
	if err := mgr.Provision("test.local", route); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	mgr.WaitRunOnce()

	for _, name := range []string{"w1", "w2", "w3"} {
		if _, err := os.Stat(filepath.Join(dir, name)); os.IsNotExist(err) {
			t.Errorf("marker for worker %s not found", name)
		}
	}
}

func TestManager_ProvisionRunOnce_BlockedByEmptyAllowlist(t *testing.T) {
	mgr := newTestManager(t, []string{}) // nothing allowed
	marker := filepath.Join(t.TempDir(), "should-not-exist")

	route := alaye.Route{
		Serverless: alaye.Serverless{
			Root: t.TempDir(),
			Workers: []alaye.Work{
				{
					Name:    "blocked",
					Command: []string{"sh", "-c", "touch " + marker},
					RunOnce: true,
				},
			},
		},
	}

	_ = mgr.Provision("test.local", route)
	mgr.WaitRunOnce()

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("blocked worker should not have produced output")
	}
}

func TestManager_ProvisionRunOnce_BlockedByAllowlist(t *testing.T) {
	mgr := newTestManager(t, []string{"python3"}) // sh not listed
	marker := filepath.Join(t.TempDir(), "should-not-exist")

	route := alaye.Route{
		Serverless: alaye.Serverless{
			Root: t.TempDir(),
			Workers: []alaye.Work{
				{
					Name:    "blocked",
					Command: []string{"sh", "-c", "touch " + marker},
					RunOnce: true,
				},
			},
		},
	}

	_ = mgr.Provision("test.local", route)
	mgr.WaitRunOnce()

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("sh is not in allowlist, worker should not have run")
	}
}

// Manager.Provision (validation)

func TestManager_Provision_InvalidHost(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	err := mgr.Provision("bad host!", alaye.Route{})
	if err == nil || !strings.Contains(err.Error(), "invalid host name") {
		t.Fatalf("expected host-validation error, got: %v", err)
	}
}

func TestManager_Provision_InvalidWorkerName(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	route := alaye.Route{
		Serverless: alaye.Serverless{
			Workers: []alaye.Work{
				{Name: "../escape", Command: []string{"sh", "-c", "exit 0"}},
			},
		},
	}
	if err := mgr.Provision("test.local", route); err == nil {
		t.Fatal("expected validation error for invalid worker name")
	}
}

func TestManager_Provision_MissingCommand(t *testing.T) {
	mgr := newTestManager(t, []string{"sh"})
	route := alaye.Route{
		Serverless: alaye.Serverless{
			Workers: []alaye.Work{{Name: "nocommand"}},
		},
	}
	err := mgr.Provision("test.local", route)
	if err == nil || !strings.Contains(err.Error(), "command required") {
		t.Fatalf("expected 'command required', got: %v", err)
	}
}

// sanitizeHostName

func TestSanitizeHostName(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"example.com", false},
		{"my-host_1.internal", false},
		{"UPPER.COM", false}, // lowercased internally
		{"", true},
		{strings.Repeat("a", 256), true},
		{"bad host", true},
		{"path/../traversal", true},
		{"host;evil", true},
	}
	for _, tc := range cases {
		_, err := sanitizeHostName(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("sanitizeHostName(%q): wantErr=%v, got err=%v", tc.input, tc.wantErr, err)
		}
	}
}

// sanitizeName

func TestSanitizeName(t *testing.T) {
	cases := []struct{ input, want string }{
		{"simple", "simple"},
		{"with/slash", "with_slash"},
		{"with\\back", "with_back"},
		{"dot..dot", "dotdot"},
		{"colon:name", "colon_name"},
		{"null\x00byte", "nullbyte"},
	}
	for _, tc := range cases {
		got := sanitizeName(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// isValidEnvName

func TestIsValidEnvName(t *testing.T) {
	for _, n := range []string{"HOME", "PATH", "MY_VAR", "x", "X1"} {
		if !isValidEnvName(n) {
			t.Errorf("expected %q to be valid", n)
		}
	}
	for _, n := range []string{"", "1START", "has space", "has-dash", "has.dot"} {
		if isValidEnvName(n) {
			t.Errorf("expected %q to be invalid", n)
		}
	}
}

// validateWorkerConfig

func TestValidateWorkerConfig(t *testing.T) {
	long := strings.Repeat("a", maxWorkerNameLen+1)
	cases := []struct {
		w       alaye.Work
		wantErr string
	}{
		{alaye.Work{Name: "ok", Command: []string{"sh"}}, ""},
		{alaye.Work{Name: "", Command: []string{"sh"}}, "name required"},
		{alaye.Work{Name: long, Command: []string{"sh"}}, "name too long"},
		{alaye.Work{Name: "ok"}, "command required"},
		{alaye.Work{Name: "bad/name", Command: []string{"sh"}}, "invalid characters"},
	}
	for _, tc := range cases {
		err := validateWorkerConfig(tc.w)
		if tc.wantErr == "" && err != nil {
			t.Errorf("worker %q: unexpected error: %v", tc.w.Name, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("worker %q: expected %q, got: %v", tc.w.Name, tc.wantErr, err)
		}
	}
}

func TestManager_ResolveDir_ExplicitRoot(t *testing.T) {
	base := t.TempDir()
	mgr := New(Config{
		Logger:          testLogger(t),
		WorkDir:         expect.NewFolder(base),
		AllowedCommands: []string{"sh"},
	})

	// Absolute path within workDir — must be returned as-is.
	insideRoot := filepath.Join(base, "myapp")
	route := alaye.Route{Serverless: alaye.Serverless{Root: insideRoot}}
	got := mgr.ResolveDir("host", route, alaye.Work{Name: "w"})
	if got != insideRoot {
		t.Errorf("expected %q, got %q", insideRoot, got)
	}

	// Absolute path outside workDir — traversal blocked, falls back to default.
	route2 := alaye.Route{Serverless: alaye.Serverless{Root: "/explicit/outside"}}
	got2 := mgr.ResolveDir("host", route2, alaye.Work{Name: "w"})
	if strings.HasPrefix(got2, "/explicit") {
		t.Errorf("path outside workDir should not be returned, got %q", got2)
	}
	if !strings.Contains(got2, "workers") {
		t.Errorf("expected fallback to workers default, got %q", got2)
	}
}

func TestManager_ResolveDir_RelativeRoot(t *testing.T) {
	base := t.TempDir()
	mgr := New(Config{
		Logger:          testLogger(t),
		WorkDir:         expect.NewFolder(base),
		AllowedCommands: []string{"sh"},
	})
	route := alaye.Route{Serverless: alaye.Serverless{Root: "relative/path"}}
	got := mgr.ResolveDir("host", route, alaye.Work{Name: "w"})
	if !strings.HasPrefix(got, base) {
		t.Errorf("relative root should be under workDir, got %q", got)
	}
}

func TestManager_ResolveDir_DefaultPath(t *testing.T) {
	base := t.TempDir()
	mgr := New(Config{
		Logger:          testLogger(t),
		WorkDir:         expect.NewFolder(base),
		AllowedCommands: []string{"sh"},
	})
	got := mgr.ResolveDir("myhost", alaye.Route{}, alaye.Work{Name: "myworker"})
	if !strings.Contains(got, "workers") || !strings.Contains(got, "myworker") {
		t.Errorf("unexpected default dir: %q", got)
	}
}
