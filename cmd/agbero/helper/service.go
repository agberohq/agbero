package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
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

	store, err := secrets.Open(secrets.Config{
		DataDir:     dataDir,
		Setting:     &global.Security.Keeper,
		Logger:      s.p.Logger,
		Interactive: false,
	})
	if err != nil {
		// A missing passphrase source is recoverable at start time via the
		// local unlock endpoint. An insecure/invalid file is not.
		if errors.Is(err, os.ErrNotExist) {
			ui.New().WarnLine("keeper passphrase source is missing; service install will continue and the service can be unlocked after start")
			return nil
		}
		return fmt.Errorf("keeper validation failed: %w", err)
	}
	defer store.Close()
	if store.IsLocked() {
		ui.New().WarnLine("keeper is locked; service install will continue and the service can be unlocked after start")
		return nil
	}

	if _, err := store.Get(expect.Vault().Key("internal")); err != nil {
		return fmt.Errorf("missing internal auth key at vault:key/internal. Run 'agbero init' to generate it")
	}

	jwtKeys, err := store.ListPrefixNamespacedFull("vault", "admin", "jwt/")
	if err != nil {
		return fmt.Errorf("failed to inspect admin JWT keys: %w", err)
	}
	if len(jwtKeys) == 0 {
		return fmt.Errorf("missing admin JWT secret at vault:admin/jwt/<user>. Run 'agbero init' to generate it")
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
	status, statusErr := svc.Status()
	if statusErr != nil || status == service.StatusUnknown {
		u.Render(func() { u.WarnLine("service is not installed; skipping service removal") })
		return
	}
	u.Render(func() {
		u.Step("run", "uninstalling system service")
	})
	if err := svc.Uninstall(); err != nil {
		if st, serr := svc.Status(); serr != nil || st != service.StatusRunning {
			u.Render(func() { u.WarnLine("service unit was already absent or could not be removed; continuing") })
			return
		}
		s.p.Logger.Fatal(s.mapError(err, "uninstall"))
	}
	u.Render(func() { u.SuccessLine("service uninstalled") })
}

func (s *Service) Start(svc service.Service, configPath string) {
	if !s.requiresRoot("start") {
		return
	}
	u := ui.New()
	u.Render(func() { u.Step("run", "starting system service") })
	if err := svc.Start(); err != nil {
		s.p.Logger.Fatal(s.mapError(err, "start"))
	}
	if !waitRunning(svc, 8*time.Second) {
		s.p.Logger.Fatal("service did not stay running — check: journalctl -u " + def.Name + " -n 80 --no-pager")
	}
	u.Render(func() { u.SuccessLine("service started") })
	s.unlockWaiting(configPath)
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

func (s *Service) Restart(svc service.Service, configPath string) {
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
	if !waitRunning(svc, 8*time.Second) {
		s.p.Logger.Fatal("service did not stay running — check: journalctl -u " + def.Name + " -n 80 --no-pager")
	}
	u.Render(func() { u.SuccessLine("service restarted") })
	s.unlockWaiting(configPath)
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
			pidFile := global.Storage.DataDir.FilePath(def.DefaultPIDName)
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

func (s *Service) unlockWaiting(configPath string) {
	global, err := loadGlobal(configPath)
	if err != nil {
		return
	}
	var cfErr error
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, cfErr = secrets.ReadControlFile(global.Storage.DataDir); cfErr == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if cfErr != nil {
		return
	}
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		ui.New().WarnLine("keeper is locked; run 'agbero keeper unlock' from a terminal")
		return
	}
	u := ui.New()
	result, err := u.PasswordRequired("Keeper passphrase")
	if err != nil {
		s.p.Logger.Fatal("read passphrase: ", err)
	}
	pass := result.Bytes()
	defer result.Zero()
	if err := secrets.UnlockControl(global.Storage.DataDir, pass); err != nil {
		ui.New().WarnLine("keeper still locked: " + err.Error())
		return
	}
	ui.New().SuccessLine("keeper unlocked")
}

func waitRunning(svc service.Service, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		status, err := svc.Status()
		if err == nil && status == service.StatusRunning {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}
