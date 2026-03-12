package installer

import (
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/charmbracelet/huh"
)

type CA struct {
	ctx *Context
}

func NewCA(ctx *Context) *CA {
	return &CA{ctx: ctx}
}

func (c *CA) IsInstalled() bool {
	return tlss.IsCARootInstalled(c.ctx.Paths.CertsDir.Path())
}

func (c *CA) Install() error {
	installer := tlss.NewLocal(c.ctx.Logger, c.ctx.Paths.CertsDir)
	if err := installer.InstallCARootIfNeeded(); err != nil {
		return err
	}
	return nil
}

func (c *CA) Uninstall() error {
	installer := tlss.NewLocal(c.ctx.Logger, c.ctx.Paths.CertsDir)
	return installer.UninstallCARoot()
}

func (c *CA) PromptAndInstall() error {
	if c.IsInstalled() {
		return nil
	}

	if !c.ctx.Interactive {
		c.ctx.Logger.Warn("Local CA is not installed. Skipping automatic installation in headless mode. Run with --install-ca to force.")
		return nil
	}

	var confirm bool
	err := huh.NewConfirm().
		Title("Local Certificate Authority").
		Description("It looks like you don't have a local CA installed.\nAgbero needs this to provide secure HTTPS (no browser warnings) for local development.\n\nWould you like to install it now? (Requires admin/sudo password)").
		Value(&confirm).
		Run()

	if err != nil {
		return err
	}

	if confirm {
		c.ctx.Logger.Info("Installing local Certificate Authority...")
		if err := c.Install(); err != nil {
			c.ctx.Logger.Error("Failed to install CA", "err", err)
			return err
		}
		c.ctx.Logger.Info("Local CA installed successfully!")
	} else {
		c.ctx.Logger.Warn("Skipped CA installation. Local HTTPS connections may show browser warnings.")
	}

	return nil
}
