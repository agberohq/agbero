//go:build windows

package orchestrator

import (
	"fmt"
	"os/exec"
	"time"
	"unsafe"

	"github.com/olekukonko/ll"
	"golang.org/x/sys/windows"
)

type jobLimits struct {
	handle windows.Handle
}

// setupProcessGroup creates a Windows Job Object with memory and process
// limits. dropPrivileges is accepted for signature parity with the unix/darwin
// builds but has no effect on Windows — Job Object limits serve the same
// containment purpose.
func setupProcessGroup(_ *exec.Cmd, _ bool) (*jobLimits, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
				windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
				windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
				windows.JOB_OBJECT_LIMIT_JOB_MEMORY,
			ActiveProcessLimit: 32,
		},
		ProcessMemoryLimit: 512 * 1024 * 1024,  // 512MB per process
		JobMemoryLimit:     1024 * 1024 * 1024, // 1GB total
	}

	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("set job limits: %w", err)
	}

	return &jobLimits{handle: job}, nil
}

func assignToJob(job *jobLimits, pid int) error {
	if job == nil {
		return nil
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(pid),
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job.handle, h)
}

func killProcessGroup(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
	time.AfterFunc(10*time.Second, func() {
		windows.TerminateProcess(h, 1)
	})
	return nil
}

func cleanupJob(limits *jobLimits) {
	if limits != nil {
		windows.CloseHandle(limits.handle)
	}
}

func applySandbox(_ string, _ *ll.Logger) error {
	// Sandboxing on Windows is handled structurally via Job Objects in
	// setupProcessGroup. No additional action needed here.
	return nil
}

func applyCgroups(_ int, _ string, _ *ll.Logger) error {
	return nil
}
