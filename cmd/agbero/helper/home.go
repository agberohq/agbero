package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/kardianos/service"
)

type Home struct {
	p      *Helper
	viewer *ui.Viewer
}

func (h *Home) Navigate(target, action string) {
	ctx := setup.NewContext(h.p.Logger)

	openShell := false
	showContent := false
	openInExplorer := false
	editorCmd := ""

	switch {
	case action == "@" || target == "@":
		openShell = true
		if target == "@" {
			target = "base"
		}
	case action == "." || action == "open" || target == "." || target == "open":
		openInExplorer = true
		if target == "." || target == "open" {
			target = "base"
		}
	case strings.HasPrefix(action, "@"):
		showContent = true
		editorCmd = strings.TrimPrefix(action, "@")
	}

	var dir, filePath string
	switch strings.ToLower(target) {
	case "hosts", "host":
		dir = ctx.Paths.HostsDir.Path()
	case "certs", "cert":
		dir = ctx.Paths.CertsDir.Path()
	case "data", "datas":
		dir = ctx.Paths.DataDir.Path()
	case "logs", "log":
		dir = ctx.Paths.LogsDir.Path()
	case "work", "works":
		dir = ctx.Paths.WorkDir.Path()
	case "config", "configs":
		filePath = ctx.Paths.ConfigFile
		dir = filepath.Dir(ctx.Paths.ConfigFile)
	default:
		dir = ctx.Paths.BaseDir.Path()
	}

	if showContent && filePath != "" {
		runEditor(editorCmd, filePath)
		return
	}
	if openInExplorer {
		if err := h.open(dir); err != nil {
			fmt.Printf("failed to open directory in explorer: %v\n", err)
		}
		return
	}
	if openShell {
		if err := os.Chdir(dir); err != nil {
			fmt.Printf("failed to enter directory: %v\n", err)
			return
		}
		if h.viewer == nil {
			h.viewer = ui.NewViewerWithUI(ui.New())
		}
		h.viewer.Show(dir, false)
		shell := os.Getenv("SHELL")
		if shell == "" {
			if runtime.GOOS == def.Windows {
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

// Uninstall performs a complete removal of agbero in the correct sequence:
//
// Confirm via ui.Confirm (skipped when force=true)
// Prompt for backup before destruction
// Stop service, then delegate to agbero service uninstall
// Delegate to agbero cert uninstall (removes CA from system trust store)
// Delete all data directories (wipes keeper.db, hosts, config, logs, work)
// Remove binary only when force=true
//
// --force: skip confirmation AND remove the binary.
func (h *Home) Uninstall(svc service.Service, configPath string, force bool) {
	u := ui.New()
	if !force {
		u.Render(func() {
			u.DialogBox(ui.DialogDanger,
				"DANGER — Complete uninstall",
				[]string{
					"stop and remove the system service",
					"remove the local Certificate Authority from system trust",
					"delete all configurations, host files, certificates, logs, and data",
				},
				"This action cannot be undone.  Pass --force to also remove the binary.",
			)
		})
		confirmed, err := u.Confirm(
			"Confirm complete uninstall",
			"Are you sure you want to remove agbero and all its data?",
		)
		if err != nil || !confirmed {
			u.Render(func() { u.InfoLine("uninstall cancelled") })
			return
		}
	}

	h.p.Logger.Info("starting uninstall sequence")

	// Step 1: Backup prompt.
	h.promptBackup(configPath, force)

	// Step 2: Stop then uninstall service.
	// Stop is warn-only (may already be stopped).
	// Uninstall delegates to Service helper which has the root check.
	if svc != nil {
		h.p.Logger.Info("stopping system service")
		if err := svc.Stop(); err != nil {
			h.p.Logger.Warnf("service stop: %v (may already be stopped)", err)
		}
		h.p.Service().Uninstall(svc)
	}

	// Step 3: CA trust store removal + store cleanup.
	// Delegates to Cert helper which uses the correct store backend
	// (keeper or disk) and already has the right logic.
	h.p.Cert().Uninstall(configPath)

	// Step 4: Wipe all data (keeper.db, hosts, certs on disk, logs, work, config).
	h.deleteDataDirectories()

	// Step 5: Binary only with --force.
	if force {
		h.deleteBinary()
	} else {
		execPath, _ := os.Executable()
		u.Render(func() { u.InfoLine(fmt.Sprintf("binary kept at %s — pass --force to remove it", execPath)) })
		u.Blank()
	}

	u.Blank()
	u.Render(func() { u.SuccessLine("agbero uninstalled") })
}

// promptBackup offers a backup before destructive removal.
// All UI goes through ui.Confirm — huh is never called directly.
func (h *Home) promptBackup(configPath string, force bool) {
	if force {
		h.p.Logger.Warn("force mode: skipping backup prompt")
		return
	}

	u := ui.New()
	doBackup, err := u.Confirm(
		"Create backup before uninstall?",
		"A backup lets you restore agbero later. The service must be stopped first.",
	)
	if err != nil || !doBackup {
		h.p.Logger.Info("backup skipped")
		return
	}

	sys := setup.NewSystem(setup.SystemConfig{Logger: h.p.Logger})
	if err := sys.Backup(configPath, "", ""); err != nil {
		h.p.Logger.Warnf("backup failed: %v — continuing with uninstall", err)
	}
}

func (h *Home) deleteDataDirectories() {
	ctx := setup.NewContext(h.p.Logger)
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

// openTLSStore returns the best available store for uninstall context where
// the keeper may not yet be injected into Helper.
func (h *Home) openTLSStore(configPath string) tlsstore.Store {
	if h.p.Store != nil {
		if ks, err := tlsstore.NewKeeper(h.p.Store); err == nil {
			return ks
		}
	}
	if configPath != "" {
		if global, err := loadGlobal(configPath); err == nil {
			dataDir := global.Storage.DataDir
			if !dataDir.IsSet() {
				ctx := setup.NewContext(h.p.Logger)
				dataDir = ctx.Paths.DataDir
			}
			store, openErr := secrets.Open(secrets.Config{
				DataDir:         dataDir,
				Setting:         &global.Security.Keeper,
				Logger:          h.p.Logger,
				Interactive:     false,
				DisableAutoLock: true,
			})
			if openErr == nil && !store.IsLocked() {
				if ks, err := tlsstore.NewKeeper(store); err == nil {
					return ks
				}
				store.Close()
			}
			ds, err := tlsstore.NewDisk(tlsstore.DiskConfig{
				DataDir: dataDir,
				CertDir: global.Storage.CertsDir,
			})
			if err == nil {
				return ds
			}
		}
	}
	h.p.Logger.Warn("could not open TLS store for CA removal — CA may need manual trust store cleanup")
	return tlsstore.NewMemory()
}

func (h *Home) open(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", dir)
	case "darwin":
		cmd = exec.Command("open", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open directory: %w", err)
	}
	return nil
}
