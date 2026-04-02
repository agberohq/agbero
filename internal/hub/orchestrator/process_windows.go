//go:build windows

package orchestrator

import (
	"os/exec"
	"syscall"
)

func setupProcessGroup(cmd *exec.Cmd) {
	// Windows doesn't have process groups like Unix
	// Use job objects for group management if needed, or just skip
	// For now, no-op - individual process termination only
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Could use CreationFlags with CREATE_NEW_PROCESS_GROUP here
		// but it requires syscall handle management
	}
}

func killProcessGroup(pid int) error {
	// Windows: terminate process by PID (no negative PID semantics)
	p, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(p)
	return syscall.TerminateProcess(p, 1)
}
