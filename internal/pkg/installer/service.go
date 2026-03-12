package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/kardianos/service"
)

type Service struct {
	ctx *Context
}

func NewService(ctx *Context) *Service {
	return &Service{ctx: ctx}
}

func (s *Service) Install(svc service.Service) error {
	s.ctx.Logger.Info("Installing system service...")
	if err := svc.Install(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			s.ctx.Logger.Warn("Service already exists.")
			return nil
		}
		return s.MapError(err, "install")
	}
	s.ctx.Logger.Info("Service installed.")
	return nil
}

func (s *Service) Uninstall(svc service.Service) error {
	s.ctx.Logger.Info("Uninstalling system service...")
	if err := svc.Uninstall(); err != nil {
		return s.MapError(err, "uninstall")
	}
	s.ctx.Logger.Info("Service uninstalled.")
	return nil
}

func (s *Service) Start(svc service.Service) error {
	s.ctx.Logger.Info("Starting system service...")
	if err := svc.Start(); err != nil {
		return s.MapError(err, "start")
	}
	s.ctx.Logger.Info("Service started.")
	return nil
}

func (s *Service) Stop(svc service.Service) error {
	s.ctx.Logger.Info("Stopping system service...")
	if err := svc.Stop(); err != nil {
		return s.MapError(err, "stop")
	}
	s.ctx.Logger.Info("Service stopped.")
	return nil
}

func (s *Service) MapError(err error, cmd string) error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	exeName := s.getExecutableName()

	if runtime.GOOS == woos.Darwin && strings.Contains(errStr, "launchctl") {
		if strings.Contains(errStr, "Expecting a LaunchAgents path") {
			return fmt.Errorf("requires root: sudo %s service install", exeName)
		}
	}
	if runtime.GOOS == woos.Linux && strings.Contains(errStr, "systemctl") {
		return fmt.Errorf("requires root: sudo %s service %s", exeName, cmd)
	}
	return fmt.Errorf("failed to %s service: %v", cmd, err)
}

func (s *Service) getExecutableName() string {
	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}
	return woos.Name
}
