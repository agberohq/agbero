package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/kardianos/service"
)

type Service struct {
	p *Helper
}

func (s *Service) Install(svc service.Service, installHere bool) {
	if installHere {
		s.p.Logger.Info("local mode: service registration skipped.")
		return
	}
	s.p.Logger.Info("installing system service...")
	if err := svc.Install(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			s.p.Logger.Warn("service already exists.")
		} else {
			s.p.Logger.Fatal(s.mapError(err, "install"))
		}
		return
	}
	s.p.Logger.Info("service installed.")
}

func (s *Service) Uninstall(svc service.Service) {
	s.p.Logger.Info("uninstalling system service...")
	if err := svc.Uninstall(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "uninstall"))
	}
	s.p.Logger.Info("service uninstalled.")
}

func (s *Service) Start(svc service.Service) {
	s.p.Logger.Info("starting system service...")
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	s.p.Logger.Info("service started.")
}

func (s *Service) Stop(svc service.Service) {
	s.p.Logger.Info("stopping system service...")
	if err := svc.Stop(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "stop"))
	}
	s.p.Logger.Info("service stopped.")
}

func (s *Service) Restart(svc service.Service) {
	s.p.Logger.Info("restarting system service...")
	if err := svc.Stop(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "stop"))
	}
	time.Sleep(2 * time.Second)
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	s.p.Logger.Info("service restarted.")
}

func (s *Service) Status(svc service.Service, configPath string) {
	s.p.Logger.Info("checking service status...")
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
		statusStr = "unknown (not installed?)"
	}
	s.p.Logger.Infof("service status: %s", statusStr)

	if status == service.StatusRunning {
		if global, err := loadGlobal(configPath); err == nil && global.Storage.DataDir != "" {
			pidFile := filepath.Join(global.Storage.DataDir, "agbero.pid")
			if data, err := os.ReadFile(pidFile); err == nil {
				s.p.Logger.Infof("process ID: %s", strings.TrimSpace(string(data)))
			}
		}
	}
}

func (s *Service) mapError(err error, cmd string) error {
	ctx := installer.NewContext(s.p.Logger, "")
	svc := installer.NewService(ctx)
	errMsg := err.Error()
	switch cmd {
	case "status":
		if strings.Contains(errMsg, "not installed") {
			return fmt.Errorf("service not installed. Run 'sudo agbero service install' first")
		}
	case "restart":
		if strings.Contains(errMsg, "not running") {
			return fmt.Errorf("service not running. Try 'sudo agbero service start'")
		}
	}
	return svc.MapError(err, cmd)
}
