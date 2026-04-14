//go:build !windows && !darwin

package orchestrator

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/olekukonko/ll"
)

const (
	cgroupBase       = "/sys/fs/cgroup/agbero"
	maxMemoryDefault = 512 * 1024 * 1024 // 512MB
	maxPidsDefault   = 32
	cpuWeightDefault = 100
)

type jobLimits struct{}

func assignToJob(_ *jobLimits, _ int) error { return nil }
func cleanupJob(_ *jobLimits)               {}

// setupProcessGroup mirrors the darwin signature. dropPrivileges=true
// requires the parent process to be root.
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

func applySandbox(workDir string, logger *ll.Logger) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := landlock.V3.RestrictPaths(
		landlock.RODirs(
			"/bin", "/usr/bin", "/usr/local/bin",
			"/lib", "/usr/lib", "/lib64", "/usr/lib64",
			"/etc",
		),
		landlock.RWDirs(workDir),
	)
	if err != nil {
		logger.Fields("err", err, "workDir", workDir).Error("landlock sandbox failed")
		return fmt.Errorf("sandbox initialization failed")
	}
	logger.Fields("workDir", workDir).Debug("landlock: sandbox applied")
	return nil
}

func applyCgroups(pid int, workerName string, logger *ll.Logger) error {
	if err := os.MkdirAll(cgroupBase, 0750); err != nil {
		return err
	}

	cgroupPath := filepath.Join(cgroupBase, workerName)
	if err := os.MkdirAll(cgroupPath, 0750); err != nil {
		return err
	}

	limits := map[string]string{
		"memory.max": strconv.FormatInt(maxMemoryDefault, 10),
		"pids.max":   strconv.Itoa(maxPidsDefault),
		"cpu.weight": strconv.Itoa(cpuWeightDefault),
	}
	for file, value := range limits {
		path := filepath.Join(cgroupPath, file)
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			logger.Fields("file", file, "err", err).Error("cgroup limit failed")
		}
	}

	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to add process to cgroup: %w", err)
	}
	return nil
}
