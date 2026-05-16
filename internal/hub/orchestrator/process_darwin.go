//go:build darwin && !cgo

package orchestrator

import (
	"os/exec"
	"syscall"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/olekukonko/ll"
)

type jobLimits struct{}

func assignToJob(_ *jobLimits, _ int) error { return nil }
func cleanupJob(_ *jobLimits)               {}

func setupProcessGroup(cmd *exec.Cmd, dropPrivileges bool) (*jobLimits, error) {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if dropPrivileges {
		attr.Credential = &syscall.Credential{
			Uid: uint32(65534),
			Gid: uint32(65534),
		}
	}
	cmd.SysProcAttr = attr
	return nil, nil
}

func killProcessGroup(pid int, done <-chan struct{}) error {
	syscall.Kill(-pid, syscall.SIGTERM)
	go func() {
		select {
		case <-time.After(def.DefaultWorkerPoolSize * time.Second):
			// Graceful shutdown window elapsed — force-kill the process group.
			syscall.Kill(-pid, syscall.SIGKILL)
		case <-done:
			// cmd.Wait() returned: the process was fully reaped and its PID
			// returned to the OS pool. Do NOT send SIGKILL — it could hit a
			// completely unrelated process that inherited this PID.
		}
	}()
	return nil
}

func applyCgroups(_ int, _ string, _ *ll.Logger) error { return nil }

func applySandbox(_ string, logger *ll.Logger) error {
	logger.Warn("seatbelt sandbox unavailable: CGo disabled at build time")
	return nil
}
