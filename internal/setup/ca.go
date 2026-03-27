package setup

import (
	"runtime"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/agberohq/agbero/internal/pkg/ui"
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
	c.printNSSHint(installer)
	return nil
}

func (c *CA) Uninstall() error {
	installer := tlss.NewLocal(c.ctx.Logger, c.ctx.Paths.CertsDir)
	return installer.UninstallCARoot()
}

// printNSSHint logs the OS-appropriate certutil install command when NSS is absent.
// Firefox and Chrome on Linux/macOS require certutil to register the local CA.
func (c *CA) printNSSHint(loc *tlss.Local) {
	if loc.HasCertutil() {
		return
	}
	switch runtime.GOOS {
	case woos.Darwin:
		c.ctx.Logger.Warn(woos.NSSInstallHintDarwin)
	case woos.Linux:
		c.ctx.Logger.Warn(woos.NSSInstallHintLinux)
	default:
		c.ctx.Logger.Warn(woos.NSSInstallHintOther)
	}
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

	u := ui.New()
	u.DialogBox(ui.DialogDanger,
		"Local Certificate Authority",
		[]string{
			"HTTPS certificates will show browser warnings without a local CA installed",
		},
		"please read the documentation for more information:",
	)

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
