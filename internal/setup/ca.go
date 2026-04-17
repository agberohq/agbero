package setup

import (
	"fmt"
	"runtime"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

type CA struct {
	ctx   *Context
	store tlsstore.Store
}

// NewCA creates CA with disk store (for all modes - persistence needed)
func NewCA(ctx *Context) *CA {
	var store tlsstore.Store
	// Always use disk store for CA - certificates need persistence
	store, err := tlsstore.NewDisk(tlsstore.DiskConfig{
		DataDir: ctx.Paths.DataDir,
		CertDir: ctx.Paths.CertsDir,
	})
	if err != nil {
		ctx.Logger.Error("Failed to create disk store, using memory fallback: ", err)
		store = tlsstore.NewMemory()
	}
	return &CA{
		ctx:   ctx,
		store: store,
	}
}

// NewCAWithStore creates CA with provided store (for when you already have one)
func NewCAWithStore(ctx *Context, store tlsstore.Store) *CA {
	return &CA{
		ctx:   ctx,
		store: store,
	}
}

func (c *CA) IsInstalled() bool {
	if c.store == nil {
		return false
	}
	_, _, err := c.store.Load("ca")
	return err == nil
}

func (c *CA) Install() error {
	if c.store == nil {
		return fmt.Errorf("TLS store not available")
	}

	installer := tlss.NewLocal(c.ctx.Logger, c.store)
	if err := installer.InstallCARootIfNeeded(); err != nil {
		installer.RemoveCA()
		return err
	}
	c.printNSSHint(installer)
	return nil
}

func (c *CA) Uninstall() error {
	if c.store == nil {
		return fmt.Errorf("TLS store not available")
	}

	installer := tlss.NewLocal(c.ctx.Logger, c.store)
	return installer.UninstallCARoot()
}

func (c *CA) printNSSHint(loc *tlss.Local) {
	if loc.HasCertutil() {
		return
	}
	switch runtime.GOOS {
	case def.Darwin:
		c.ctx.Logger.Warn(def.NSSInstallHintDarwin)
	case def.Linux:
		c.ctx.Logger.Warn(def.NSSInstallHintLinux)
	default:
		c.ctx.Logger.Warn(def.NSSInstallHintOther)
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

	confirm, err := u.Confirm("Local Certificate Authority", "Would you like to install it now? (Requires admin/sudo password)")
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
