package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lx"
)

// Process encapsulates a single worker invocation.  AllowedCommands is
// set by the Manager at construction time from Config; it must not be nil.
type Process struct {
	Config          alaye.Work
	Env             []string
	Dir             string
	Logger          *ll.Logger
	AllowedCommands map[string]bool // authoritative per-manager allowlist
	DropPrivileges  bool            // when true, worker runs as uid/gid 65534
}

// Do runs the process with a background context and no explicit I/O wiring.
func (p *Process) Do() error {
	return p.Run(context.Background(), nil, nil)
}

// Run executes the configured command.  It enforces the allowlist, creates
// the working directory, wires up I/O, applies platform sandboxing, and
// waits for the process to exit.
func (p *Process) Run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if len(p.Config.Command) == 0 {
		return fmt.Errorf("empty command")
	}

	cmdName := filepath.Base(p.Config.Command[0])
	if !p.isAllowed(cmdName) {
		p.Logger.Fields("command", cmdName, "worker", p.Config.Name).Error("command not in allowlist")
		return fmt.Errorf("command not allowed: %s", cmdName)
	}

	if err := os.MkdirAll(p.Dir, def.WorkDirPerm); err != nil {
		return fmt.Errorf("create workdir: %w", err)
	}

	env, err := buildEnvironment(p.Config.Env, p.Logger)
	if err != nil {
		return fmt.Errorf("build environment: %w", err)
	}

	var limits *jobLimits
	if runtime.GOOS == "windows" {
		limits, err = setupProcessGroup(nil, false)
		if err != nil {
			return err
		}
	}

	cmd := exec.CommandContext(ctx, p.Config.Command[0], p.Config.Command[1:]...)
	cmd.Dir = p.Dir
	cmd.Env = env

	if stdin != nil {
		cmd.Stdin = stdin
	}
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = p.Logger.Writer(lx.LevelInfo)
	}
	cmd.Stderr = p.Logger.Writer(lx.LevelError)

	if runtime.GOOS != "windows" {
		setupProcessGroup(cmd, p.DropPrivileges)
	}

	if p.Config.Landlock.Active() {
		if err := applySandbox(p.Dir, p.Logger); err != nil {
			p.Logger.Fields("worker", p.Config.Name, "error", err).Error("sandbox failed")
			return fmt.Errorf("sandbox failed: %w", err)
		}
	}

	var pid atomic.Int32
	cmd.Cancel = func() error {
		if v := int(pid.Load()); v > 0 {
			return killProcessGroup(v)
		}
		return nil
	}

	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start process: %w", err)
	}
	pid.Store(int32(cmd.Process.Pid))

	if runtime.GOOS == "windows" && limits != nil {
		if err := assignToJob(limits, cmd.Process.Pid); err != nil {
			p.Logger.Fields("pid", cmd.Process.Pid, "error", err).Warn("failed to assign to job object")
		}
	}

	if err := applyCgroups(cmd.Process.Pid, sanitizeName(p.Config.Name), p.Logger); err != nil {
		p.Logger.Fields("pid", cmd.Process.Pid, "error", err).Warn("cgroup setup failed")
	}

	p.Logger.Fields("pid", cmd.Process.Pid, "command", cmdName, "worker", p.Config.Name).Info("worker started")

	err = cmd.Wait()

	status := "success"
	if err != nil {
		status = "failure"
	}

	p.Logger.Fields(
		"worker", p.Config.Name,
		"pid", cmd.Process.Pid,
		"duration", time.Since(startTime).String(),
		"status", status,
	).Info("worker stopped")

	if runtime.GOOS == "windows" && limits != nil {
		cleanupJob(limits)
	}

	return err
}

// isAllowed checks cmdName against the per-process allowlist.  Falls back
// to DefaultAllowedCommands when AllowedCommands is nil (defensive only;
// Manager always sets it).
func (p *Process) isAllowed(cmdName string) bool {
	return p.AllowedCommands[cmdName]
}

// environment helpers

func buildEnvironment(envMap map[string]expect.Value, logger *ll.Logger) ([]string, error) {
	base := os.Environ()
	result := make([]string, 0, len(base)+len(envMap))

	for _, e := range base {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if isValidEnvName(parts[0]) {
			result = append(result, e)
		}
	}

	for k, v := range envMap {
		if !isValidEnvName(k) {
			logger.Fields("name", k).Warn("invalid env var name, skipping")
			continue
		}
		val := strings.ReplaceAll(v.String(), "\x00", "")
		if strings.Contains(val, "\n") || strings.Contains(val, "\r") {
			logger.Fields("name", k).Warn("env var contains newlines, skipping")
			continue
		}
		result = append(result, fmt.Sprintf("%s=%s", k, val))
	}

	return result, nil
}

func isValidEnvName(name string) bool {
	if name == "" {
		return false
	}
	if name[0] >= '0' && name[0] <= '9' {
		return false
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

func sanitizeName(name string) string {
	return strings.NewReplacer(
		"..", "",
		"/", "_",
		"\\", "_",
		":", "_",
		"\x00", "",
	).Replace(name)
}
