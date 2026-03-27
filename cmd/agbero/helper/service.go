package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/kardianos/service"
)

type Service struct {
	p *Helper
}

// requiresRoot checks whether the current process has the privileges needed
// to manage system services and warns the user if not.
//
// On Unix: root is euid 0.
// On Windows: elevation check is not straightforward — we let the OS error
// surface naturally and mapError provides a clear message.
func (s *Service) requiresRoot(cmd string) bool {
	if runtime.GOOS == woos.Windows {
		return true // let Windows surface its own elevation error
	}
	if os.Geteuid() == 0 {
		return true
	}
	// Not root — show a clear hint before attempting.
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

func (s *Service) Install(svc service.Service, installHere bool) {
	u := ui.New()
	if installHere {
		u.InfoLine("local mode — service registration skipped")
		return
	}
	if !s.requiresRoot("install") {
		return
	}
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
