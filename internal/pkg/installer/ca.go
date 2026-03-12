package installer

import (
	"fmt"

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
		fmt.Println("✓ Local CA is already installed")
		return nil
	}

	if !c.ctx.Interactive {
		c.ctx.Logger.Warn("Local CA is not installed. Skipping automatic installation in headless mode. Run with --install-ca to force.")
		return nil
	}

	// Simple ASCII box
	fmt.Println("╭─────────────────────────────────────────────────────╮")
	fmt.Println("│                                                     │")
	fmt.Println("│  Warning: HTTPS certificates will show browser      │")
	fmt.Println("│  warnings without a local CA installed.             │")
	fmt.Println("│                                                     │")
	fmt.Println("╰─────────────────────────────────────────────────────╯")
	fmt.Println()

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
		fmt.Println("Installing local Certificate Authority...")
		if err := c.Install(); err != nil {
			c.ctx.Logger.Error("Failed to install CA", "err", err)
			return err
		}
		fmt.Println("✓ Local CA installed successfully!")
	} else {
		c.ctx.Logger.Warn("Skipped CA installation. Local HTTPS connections may show browser warnings.")
	}

	return nil
}
