package secrets

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/prompter"
	"github.com/olekukonko/zero"
)

// Config controls how secrets.Open initialises the Keeper store.
type Config struct {
	DataDir     expect.Folder
	Logger      *ll.Logger
	Setting     *alaye.Keeper
	Interactive bool

	DisableAutoLock bool
}

// Open opens or creates the Keeper store according to kfg.
// It attempts passphrase resolution in the following order:
// alaye.Keeper.Passphrase (config file value, may itself be a secret ref)
// AGBERO_PASSPHRASE environment variable
// Interactive prompt — only when kfg.Interactive == true
//
// If the store remains locked after all attempts and kfg.Interactive is false
// the unlocked store is still returned; the caller must check store.IsLocked()
// and decide whether to fail fast (server) or proceed (library embed).
func Open(kfg Config) (*keeper.Keeper, error) {
	var (
		store *keeper.Keeper
		err   error
	)

	if kfg.Logger == nil {
		kfg.Logger = ll.New("secrets").Disable()
	} else {
		kfg.Logger = kfg.Logger.Namespace("secrets")
	}

	if err = kfg.DataDir.Make(true); err != nil {
		return nil, fmt.Errorf("failed to initialize data directory: %w", err)
	}

	dbPath := filepath.Join(kfg.DataDir.Path(), woos.DefaultKeeperName)

	kConfig := keeper.Config{
		DBPath:      dbPath,
		Logger:      kfg.Logger,
		EnableAudit: true,
	}

	if kfg.Setting != nil {
		if !kfg.Setting.Logging.Active() {
			kConfig.Logger = kfg.Logger.Disable()
		}

		if kfg.Setting.Enabled.Inactive() {
			kfg.Logger.Warn("keeper is marked disabled in config but is a compulsory component — proceeding")
		}

		if !kfg.DisableAutoLock && kfg.Setting.AutoLock > 0 {
			kConfig.AutoLockInterval = kfg.Setting.AutoLock.StdDuration()
		}

		if kfg.Setting.Audit.Active() {
			kConfig.EnableAudit = true
		}
	}

	isNew := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isNew = true
	}

	if isNew {
		store, err = keeper.New(kConfig)
	} else {
		store, err = keeper.Open(kConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open keeper database: %w", err)
	}

	if !store.IsLocked() {
		return store, nil
	}

	passphrase := resolvePassphrase(kfg.Setting)

	if passphrase != "" && passphrase != "dev" {
		kfg.Logger.Debug("attempting to unlock keeper with configured passphrase")
		passBytes := []byte(passphrase)
		unlockErr := store.Unlock(passBytes)
		zero.Bytes(passBytes)

		if unlockErr == nil {
			kfg.Logger.Info("keeper unlocked successfully using configured passphrase")
			return store, nil
		}

		store.Close()
		return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
	}

	if passphrase == "dev" {
		kfg.Logger.Warn("keeper: opening in DEV mode — DO NOT use in production")
		devPass := []byte("agbero-dev-mode-insecure-passphrase")
		master, deriveErr := store.DeriveMaster(devPass)
		zero.Bytes(devPass)
		if deriveErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to derive dev master key: %w", deriveErr)
		}
		if unlockErr := store.UnlockDatabase(master); unlockErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to unlock keeper in dev mode: %w", unlockErr)
		}
		kfg.Logger.Warn("keeper unlocked in DEV mode — DO NOT use in production")
		return store, nil
	}

	if store.IsLocked() && kfg.Interactive {
		kfg.Logger.Debug("keeper locked, prompting user for passphrase")

		var result *prompter.Result
		var promptErr error

		if isNew {
			result, promptErr = prompter.NewSecret("Create Keeper Master Passphrase",
				prompter.WithRequired(true),
			).WithConfirmation("Confirm Passphrase").Run()
		} else {
			result, promptErr = prompter.NewSecret("Keeper Passphrase",
				prompter.WithRequired(true),
			).Run()
		}

		if promptErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to prompt for passphrase: %w", promptErr)
		}

		pass := result.Bytes()
		unlockErr := store.Unlock(pass)

		zero.Bytes(pass)
		result.Zero()

		if unlockErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
		}
		kfg.Logger.Info("keeper unlocked via interactive prompt")
		return store, nil
	}

	if store.IsLocked() {
		kfg.Logger.Debug("keeper remains locked — caller must unlock via store.Unlock()")
	}
	return store, nil
}

// MustOpen opens the keeper and returns an error if the store is still locked
// after all unlock attempts.  Useful for non-interactive server startup paths
// that require a fully unlocked store before proceeding.
func MustOpen(kfg Config) (*keeper.Keeper, error) {
	store, err := Open(kfg)
	if err != nil {
		return nil, err
	}
	if store.IsLocked() {
		store.Close()
		return nil, fmt.Errorf("keeper is locked. Set AGBERO_PASSPHRASE environment variable or configure keeper.passphrase in agbero.hcl")
	}
	return store, nil
}

func resolvePassphrase(cfg *alaye.Keeper) string {
	if cfg != nil {
		if p := cfg.Passphrase.String(); p != "" {
			return p
		}
	}
	return os.Getenv("AGBERO_PASSPHRASE")
}
