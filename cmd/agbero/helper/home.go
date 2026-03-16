package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/charmbracelet/huh"
	"github.com/kardianos/service"
)

type Home struct {
	p      *Helper
	viewer *zulu.Viewer
}

// Navigates to the specified target directory and opens an interactive shell
// Supports viewing or editing the configuration file based on the selected action
func (h *Home) Navigate(target, action string) {
	ctx := installer.NewContext(h.p.Logger, "")

	openShell := false
	showContent := false
	editorCmd := ""

	if after, ok := strings.CutPrefix(action, "@"); ok {
		if action == "@" {
			openShell = true
		} else {
			showContent = true
			editorCmd = after
		}
	} else if target == "@" {
		target = "base"
		openShell = true
	}

	var dir, filePath string
	switch strings.ToLower(target) {
	case "hosts":
		dir = ctx.Paths.HostsDir.Path()
	case "certs":
		dir = ctx.Paths.CertsDir.Path()
	case "data":
		dir = ctx.Paths.DataDir.Path()
	case "logs":
		dir = ctx.Paths.LogsDir.Path()
	case "work":
		dir = ctx.Paths.WorkDir.Path()
	case "config":
		filePath = ctx.Paths.ConfigFile
		dir = filepath.Dir(ctx.Paths.ConfigFile)
	default:
		dir = ctx.Paths.BaseDir.Path()
	}

	if showContent && filePath != "" {
		runEditor(editorCmd, filePath)
		return
	}

	if openShell {
		if err := os.Chdir(dir); err != nil {
			fmt.Printf("failed to enter directory: %v\n", err)
			return
		}

		if h.viewer == nil {
			h.viewer = zulu.NewViewer()
		}

		h.viewer.Show(dir, true)

		shell := os.Getenv("SHELL")
		if shell == "" {
			if runtime.GOOS == woos.Windows {
				shell = "cmd.exe"
			} else {
				shell = "/bin/sh"
			}
		}

		cmd := exec.Command(shell)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		return
	}

	if filePath != "" {
		fmt.Println(filePath)
	} else {
		fmt.Println(dir)
	}
}

// Removes all state managed by the application from the operating system
// Requires explicit interactive confirmation unless the force flag is provided
func (h *Home) UninstallEverything(svc service.Service, configPath string, force bool) {
	if !force {
		var confirm bool
		err := huh.NewConfirm().
			Title("DANGER: Complete Uninstall").
			Description(
				"This will:\n" +
					"  • Stop and remove the system service\n" +
					"  • Remove the local Certificate Authority from system trust\n" +
					"  • Delete all configurations, host files, certificates, logs, and data\n" +
					"  • Attempt to remove the agbero binary\n\n" +
					"The binary removal may require manual cleanup on Windows.\n" +
					"This action cannot be undone.",
			).
			Value(&confirm).
			Run()
		if err != nil || !confirm {
			fmt.Println("Uninstall cancelled.")
			return
		}
	}

	h.p.Logger.Info("starting complete uninstall sequence")

	h.uninstallService(svc)
	h.uninstallCA(configPath)
	h.deleteDataDirectories()
	h.deleteBinary()
}

// Stops and uninstalls the system service if it currently exists
// Prevents panics by safely handling a nil service reference before stopping
func (h *Home) uninstallService(svc service.Service) {
	if svc == nil {
		return
	}
	h.p.Logger.Info("stopping and removing system service")
	if err := svc.Stop(); err != nil {
		h.p.Logger.Warnf("service stop: %v (may already be stopped)", err)
	}
	if err := svc.Uninstall(); err != nil {
		h.p.Logger.Warnf("service uninstall: %v (may already be removed)", err)
	}
}

// Removes the local certificate authority from the operating system trust store
// Defers to the dedicated certificate helper logic for safe environment cleanup
func (h *Home) uninstallCA(configPath string) {
	h.p.Logger.Info("removing local Certificate Authority")
	certHelper := &Cert{p: h.p}
	certHelper.Uninstall(configPath)
}

// Deletes the base directory containing all application data and configuration
// Exits early and skips processing if the target directory does not exist
func (h *Home) deleteDataDirectories() {
	ctx := installer.NewContext(h.p.Logger, "")
	baseDir := ctx.Paths.BaseDir.Path()

	h.p.Logger.Infof("deleting all agbero data in %s", baseDir)

	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		h.p.Logger.Info("data directory does not exist, nothing to remove")
		return
	}

	if err := os.RemoveAll(baseDir); err != nil {
		h.p.Logger.Warnf("could not fully remove %s: %v — manual cleanup may be required", baseDir, err)
	} else {
		h.p.Logger.Infof("removed %s", baseDir)
	}
}

// Attempts to securely remove the running application executable from disk
// Resolves symbolic links prior to issuing the binary deletion command
func (h *Home) deleteBinary() {
	h.p.Logger.Info("removing agbero binary")

	execPath, err := os.Executable()
	if err != nil {
		h.p.Logger.Warnf("could not determine binary path: %v", err)
		return
	}

	resolved, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		resolved = execPath
	}

	if err := os.Remove(resolved); err != nil {
		h.p.Logger.Warnf("could not remove binary at %s: %v", resolved, err)
		fmt.Printf("\nManual removal required: rm -f %s\n", resolved)
		return
	}

	h.p.Logger.Infof("removed binary at %s", resolved)
	fmt.Println("\nagbero has been completely uninstalled.")
}
