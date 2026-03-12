package installer

import (
	"bytes"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
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
		installer.RemoveCA()
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
		c.ctx.Logger.Println("✓ Local CA is already installed")
		return nil
	}

	if !c.ctx.Interactive {
		c.ctx.Logger.Warn("Local CA is not installed. Skipping automatic installation in headless mode. Run with --install-ca to force.")
		return nil
	}

	var output bytes.Buffer
	table := zulu.Table(&output)
	table.Append([]string{""})
	table.Append([]string{"Warning: HTTPS certificates will show browser"})
	table.Append([]string{"warnings without a local CA installed"})
	table.Append([]string{""})
	table.Render()
	c.ctx.Logger.Println(output.String())

	var confirm bool
	err := huh.NewConfirm().
		Title("Local Certificate Authority").
		Description("Would you like to install it now? (Requires admin/sudo password)").
		WithButtonAlignment(lipgloss.Left).
		Value(&confirm).
		Run()

	if err != nil {
		return err
	}

	if confirm {
		c.ctx.Logger.Println("Installing local Certificate Authority...")
		if err := c.Install(); err != nil {
			c.ctx.Logger.Error("Failed to install CA", "err", err)
			return err
		}
		c.ctx.Logger.Println("✓ Local CA installed successfully!")
	} else {
		c.ctx.Logger.Warn("Skipped CA installation. Local HTTPS connections may show browser warnings.")
	}

	return nil
}
