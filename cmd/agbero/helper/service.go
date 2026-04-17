package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/kardianos/service"
	"github.com/olekukonko/errors"
)

type Service struct {
	p *Helper
}

func (s *Service) requiresRoot(cmd string) bool {
	if runtime.GOOS == def.Windows {
		return true
	}
	if os.Geteuid() == 0 {
		return true
	}

	cmdPath := os.Args[0]
	cmdName := filepath.Base(cmdPath)

	ui.New().Render(func() {
		ui.New().ErrorHint(
			"this command requires root privileges",
			"try:  sudo "+cmdName+" service "+cmd,
		)
	})
	return false
}

func (s *Service) preflightCheck(configPath string) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return fmt.Errorf("failed to parse configuration file: %w", err)
	}

	dataDir := global.Storage.DataDir
	if dataDir == "" {
		ctx := setup.NewContext(s.p.Logger)
		dataDir = ctx.Paths.DataDir
	}

	store, err := secrets.MustOpen(secrets.Config{
		DataDir:     dataDir,
		Setting:     &global.Security.Keeper,
		Logger:      s.p.Logger,
		Interactive: false,
	})
	if err != nil {
		return fmt.Errorf("keeper validation failed: %w", err)
	}
	defer store.Close()

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
		u.Render(func() {
			u.InfoLine("local mode — service registration skipped")
		})
		return
	}
	if !s.requiresRoot("install") {
		return
	}

	u.Render(func() {
		u.Step("run", "Running pre-flight checks...")
	})
	if err := s.preflightCheck(configPath); err != nil {
		s.p.Logger.Fatal("Pre-flight check failed:\n\n", err)
		return
	}
	u.Render(func() {
		u.Step("ok", "Pre-flight checks passed")
		u.Step("run", "installing system service")
	})
	if err := svc.Install(); err != nil {
		if errors.Is(err, def.ErrAlreadyExists) {
			u.Render(func() { u.WarnLine("service already exists") })
		} else {
			s.p.Logger.Fatal(s.mapError(err, "install"))
		}
		return
	}
	u.Render(func() { u.SuccessLine("service installed") })
}

func (s *Service) Uninstall(svc service.Service) {
	if !s.requiresRoot("uninstall") {
		return
	}
	u := ui.New()
	u.Render(func() {
		u.Step("run", "uninstalling system service")
	})
	if err := svc.Uninstall(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "uninstall"))
	}
	u.Render(func() { u.SuccessLine("service uninstalled") })
}

func (s *Service) Start(svc service.Service) {
	if !s.requiresRoot("start") {
		return
	}
	u := ui.New()
	u.Render(func() { u.Step("run", "starting system service") })
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	u.Render(func() { u.SuccessLine("service started") })
}

func (s *Service) Stop(svc service.Service) {
	if !s.requiresRoot("stop") {
		return
	}
	u := ui.New()
	u.Render(func() { u.Step("run", "stopping system service") })
	if err := svc.Stop(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "stop"))
	}
	u.Render(func() { u.SuccessLine("service stopped") })
}

func (s *Service) Restart(svc service.Service) {
	if !s.requiresRoot("restart") {
		return
	}
	u := ui.New()
	u.Render(func() {
		u.Step("run", "stopping system service")
	})
	if err := svc.Stop(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "stop"))
	}
	time.Sleep(2 * time.Second)
	u.Render(func() {
		u.Step("run", "starting system service")
	})
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	u.Render(func() { u.SuccessLine("service restarted") })
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
			pidFile := global.Storage.DataDir.FilePath("agbero.pid")
			if data, err := os.ReadFile(pidFile); err == nil {
				pid = strings.TrimSpace(string(data))
			}
		}
	}

	u := ui.New()
	u.Render(func() {
		u.ServiceStatus(statusStr, pid, configPath)
	})
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
