//go:build darwin && !cgo

package orchestrator

import (
	"os/exec"
	"syscall"
	"time"

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

func killProcessGroup(pid int) error {
	syscall.Kill(-pid, syscall.SIGTERM)
	go func() {
		<-time.After(10 * time.Second)
		syscall.Kill(-pid, syscall.SIGKILL)
	}()
	return nil
}

func applyCgroups(_ int, _ string, _ *ll.Logger) error { return nil }

func applySandbox(_ string, logger *ll.Logger) error {
	logger.Warn("seatbelt sandbox unavailable: CGo disabled at build time")
	return nil
}
