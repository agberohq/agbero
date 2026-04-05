package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/kardianos/service"
)

type Service struct {
	p *Helper
}

func (s *Service) requiresRoot(cmd string) bool {
	if runtime.GOOS == woos.Windows {
		return true
	}
	if os.Geteuid() == 0 {
		return true
	}

	exe := "agbero"
	if len(os.Args) > 0 {
		exe = filepath.Base(os.Args[0])
	}
	ui.New().ErrorHint(
		"this command requires root privileges",
		"try:  sudo "+exe+" service "+cmd,
	)
	return false
}

// preflightCheck simulates the critical boot steps to ensure the service won't crash on start
func (s *Service) preflightCheck(configPath string) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return fmt.Errorf("failed to parse configuration file: %w", err)
	}

	dataDir := global.Storage.DataDir
	if dataDir == "" {
		ctx := setup.NewContext(s.p.Logger)
		dataDir = ctx.Paths.DataDir.Path()
	}

	store, err := secrets.OpenStore(dataDir, &global.Security.Keeper, s.p.Logger)
	if err != nil {
		return fmt.Errorf("keeper validation failed (wrong passphrase?): %w", err)
	}
	defer store.Close()

	if store.IsLocked() {
		return fmt.Errorf(
			"Keeper is locked. The service will crash on startup because it cannot decrypt its secrets.\n" +
				"Hint: Ensure 'AGBERO_PASSPHRASE' is exported, or 'keeper.passphrase' is correctly configured in agbero.hcl.",
		)
	}

	// Verify critical system secrets exist (ensures 'agbero init' was run successfully)
	if _, err := store.GetNamespacedFull("vault", "system", "auth/ppk"); err != nil {
		return fmt.Errorf("missing internal auth key. Did you run 'agbero init'?")
	}

	if _, err := store.GetNamespacedFull("vault", "system", "auth/jwt_secret"); err != nil {
		return fmt.Errorf("missing admin JWT secret. Did you run 'agbero init'?")
	}

	return nil
}

func (s *Service) Install(svc service.Service, installHere bool, configPath string) {
	u := ui.New()
	if installHere {
		u.InfoLine("local mode — service registration skipped")
		return
	}
	if !s.requiresRoot("install") {
		return
	}

	u.Step("run", "Running pre-flight checks...")
	if err := s.preflightCheck(configPath); err != nil {
		s.p.Logger.Fatal("Pre-flight check failed! Fix the errors below before installing the service:\n\n", err)
		return
	}
	u.Step("ok", "Pre-flight checks passed")

	u.Step("run", "installing system service")
	if err := svc.Install(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			u.WarnLine("service already exists")
		} else {
			s.p.Logger.Fatal(s.mapError(err, "install"))
		}
		return
	}
	u.SuccessLine("service installed")
}

func (s *Service) Uninstall(svc service.Service) {
	if !s.requiresRoot("uninstall") {
		return
	}
	u := ui.New()
	u.Step("run", "uninstalling system service")
	if err := svc.Uninstall(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "uninstall"))
	}
	u.SuccessLine("service uninstalled")
}

func (s *Service) Start(svc service.Service) {
	if !s.requiresRoot("start") {
		return
	}
	u := ui.New()
	u.Step("run", "starting system service")
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	u.SuccessLine("service started")
}

func (s *Service) Stop(svc service.Service) {
	if !s.requiresRoot("stop") {
		return
	}
	u := ui.New()
	u.Step("run", "stopping system service")
	if err := svc.Stop(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "stop"))
	}
	u.SuccessLine("service stopped")
}

func (s *Service) Restart(svc service.Service) {
	if !s.requiresRoot("restart") {
		return
	}
	u := ui.New()
	u.Step("run", "stopping system service")
	if err := svc.Stop(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "stop"))
	}
	time.Sleep(2 * time.Second)
	u.Step("run", "starting system service")
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	u.SuccessLine("service restarted")
}

func (s *Service) Status(svc service.Service, configPath string) {
	status, err := svc.Status()
	if err != nil {
		s.p.Logger.Fatal(s.mapError(err, "status"))
	}

	statusStr := "unknown"
	switch status {
	case service.StatusRunning:
		statusStr = "running"
	case service.StatusStopped:
		statusStr = "stopped"
	case service.StatusUnknown:
		statusStr = "unknown"
	}

	var pid string
	if status == service.StatusRunning {
		if global, err := loadGlobal(configPath); err == nil && global.Storage.DataDir != "" {
			pidFile := filepath.Join(global.Storage.DataDir, "agbero.pid")
			if data, err := os.ReadFile(pidFile); err == nil {
				pid = strings.TrimSpace(string(data))
			}
		}
	}

	u := ui.New()
	u.ServiceStatus(statusStr, pid, configPath)
}

func (s *Service) mapError(err error, cmd string) error {
	ctx := setup.NewContext(s.p.Logger)
	svc := setup.NewService(ctx)
	errMsg := err.Error()
	switch cmd {
	case "status":
		if strings.Contains(errMsg, "not installed") {
			return fmt.Errorf("service not installed — run: sudo agbero service install")
		}
	case "restart":
		if strings.Contains(errMsg, "not running") {
			return fmt.Errorf("service not running — try: sudo agbero service start")
		}
	}
	return svc.MapError(err, cmd)
}
