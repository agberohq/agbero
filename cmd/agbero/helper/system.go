package helper

import (
	"github.com/agberohq/agbero/internal/setup"
)

// System is the CLI-facing accessor for system-level operations.
// All logic lives in internal/pkg/installer. This wrapper fatals on error so
// cmd/* stays free of error-handling boilerplate, while the installer layer
// remains fully testable by returning errors.
type System struct {
	p *Helper
}

// Backup delegates to installer.System.Backup.
func (s *System) Backup(configPath, outPath, password string) {
	sys := setup.NewSystem(setup.SystemConfig{Logger: s.p.Logger})
	if err := sys.Backup(configPath, outPath, password); err != nil {
		s.p.Logger.Fatal("backup: ", err)
	}
}

// Restore delegates to installer.System.Restore.
func (s *System) Restore(inPath, configPath, password string, force, autoYes bool) {
	sys := setup.NewSystem(setup.SystemConfig{Logger: s.p.Logger})
	if err := sys.Restore(inPath, configPath, password, force, autoYes); err != nil {
		s.p.Logger.Fatal("restore: ", err)
	}
}

// Update delegates to installer.System.Update.
func (s *System) Update(force, autoYes bool) {
	sys := setup.NewSystem(setup.SystemConfig{Logger: s.p.Logger})
	if err := sys.Update(force, autoYes); err != nil {
		s.p.Logger.Fatal("update: ", err)
	}
}
