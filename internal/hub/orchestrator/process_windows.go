//go:build windows

package orchestrator

import (
	"fmt"
	"os/exec"
	"time"
	"unsafe"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/olekukonko/ll"
	"golang.org/x/sys/windows"
)

type jobLimits struct {
	handle windows.Handle
}

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
		ProcessMemoryLimit: 512 * 1024 * 1024,
		JobMemoryLimit:     1024 * 1024 * 1024,
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

func killProcessGroup(pid int, done <-chan struct{}) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
	go func() {
		// Hold the handle open for the lifetime of this goroutine so the
		// TerminateProcess call below always uses a live handle. The original
		// code used defer CloseHandle inside killProcessGroup, which closed
		// the handle the moment the function returned — before the 10-second
		// timer fired — causing a use-after-close on every graceful shutdown.
		defer windows.CloseHandle(h)
		select {
		case <-time.After(def.DefaultWorkerPoolSize * time.Second):
			// Graceful shutdown window elapsed — force-terminate the process.
			windows.TerminateProcess(h, 1)
		case <-done:
			// cmd.Wait() returned: process exited cleanly, no action needed.
			// Handle is closed by defer above.
		}
	}()
	return nil
}

func cleanupJob(limits *jobLimits) {
	if limits != nil {
		windows.CloseHandle(limits.handle)
	}
}

func applySandbox(_ string, _ *ll.Logger) error {
	return nil
}

func applyCgroups(_ int, _ string, _ *ll.Logger) error {
	return nil
}
