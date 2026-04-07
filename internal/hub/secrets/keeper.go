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

// Open opens (or creates) the keeper database at dataDir/keeper.db.
//
// Passphrase resolution order:
// cfg.Passphrase (any expect.Value — plain text, env., ss://, b64. …)
// AGBERO_PASSPHRASE environment variable
// Interactive prompt (if Interactive=true)
// Return locked store (if Interactive=false and no passphrase available)
//
// Special case — development mode:
// If cfg.Passphrase resolves to the literal string "dev" (or AGBERO_PASSPHRASE="dev"),
// the store is unlocked with a fixed sentinel passphrase. The KDF rejects empty
// passwords so we cannot use []byte{}. The sentinel is stable across restarts —
// a dev store opened twice with "dev" opens correctly both times.
// Production stores must never use this mode.
//
// A nil cfg is valid and means "open the store locked, let the caller unlock".
// An empty passphrase string (cfg.Passphrase = "") also means locked-on-return
// unless AGBERO_PASSPHRASE is set.

type Config struct {
	DataDir     expect.Folder
	Logger      *ll.Logger
	Setting     *alaye.Keeper
	Interactive bool
}

// Open opens or creates the keeper database with the given configuration.
// Returns the store (may be locked if no passphrase available and not interactive).
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

	// Initialize data directory
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
		// Disable logging if logging is disabled
		if !kfg.Setting.Logging.Active() {
			kConfig.Logger = kfg.Logger.Disable()
		}

		if kfg.Setting.Enabled.Inactive() {
			kfg.Logger.Warn("keeper is marked disabled in config but is a compulsory component — proceeding")
		}
		if kfg.Setting.AutoLock > 0 {
			kConfig.AutoLockInterval = kfg.Setting.AutoLock.StdDuration()
		}
		if kfg.Setting.Audit.Active() {
			kConfig.EnableAudit = true
		}
	}

	// Check if the database file is entirely new
	isNew := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isNew = true
	}

	// Open or create the database
	if isNew {
		store, err = keeper.New(kConfig)
	} else {
		store, err = keeper.Open(kConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open keeper database: %w", err)
	}

	// If store is already unlocked, return immediately
	if !store.IsLocked() {
		return store, nil
	}

	// Try automatic unlock from config/env
	passphrase := resolvePassphrase(kfg.Setting)

	if passphrase != "" && passphrase != "dev" {
		kfg.Logger.Debug("attempting to unlock keeper with configured passphrase")
		passBytes := []byte(passphrase)
		master, deriveErr := store.DeriveMaster(passBytes)
		zero.Bytes(passBytes) // Wipe immediately after derivation
		if deriveErr == nil {
			if unlockErr := store.UnlockDatabase(master); unlockErr == nil {
				kfg.Logger.Info("keeper unlocked successfully using configured passphrase")
				return store, nil
			}
		}
		// Passphrase was provided but failed to unlock - this is a hard error
		store.Close()
		return nil, fmt.Errorf("failed to unlock keeper database: invalid passphrase")
	}

	// Handle dev mode (special case, no prompting)
	if passphrase == "dev" {
		kfg.Logger.Warn("keeper: opening in DEV mode — DO NOT use in production")
		devPass := []byte("agbero-dev-mode-insecure-passphrase")
		master, deriveErr := store.DeriveMaster(devPass)
		zero.Bytes(devPass) // Wipe immediately after derivation
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

	// Interactive prompt (only if configured and store is still locked)
	if store.IsLocked() && kfg.Interactive {
		kfg.Logger.Debug("keeper locked, prompting user for passphrase")

		var result *prompter.Result
		var promptErr error

		// Force the user to confirm their password if creating a brand new database
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

		// Securely wipe memory buffers
		zero.Bytes(pass)
		result.Zero()

		if unlockErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
		}
		kfg.Logger.Info("keeper unlocked via interactive prompt")
		return store, nil
	}

	// Return locked store for caller to handle (e.g. background daemon mode)
	if store.IsLocked() {
		kfg.Logger.Debug("keeper remains locked — caller must unlock via store.Unlock()")
	}
	return store, nil
}

// MustOpen opens the keeper database and requires it to be unlocked.
// Returns an error if the store is locked after all resolution attempts.
// Use this for daemon mode where an unlocked store is required.
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

// resolvePassphrase returns the first non-empty passphrase from:
// cfg.Passphrase (resolved through expect.Value — handles env., b64., ss:// …)
// AGBERO_PASSPHRASE environment variable
//
// Returns "" when no passphrase is available — callers that need an unlocked
// store must detect this and prompt the user or return an error.
func resolvePassphrase(cfg *alaye.Keeper) string {
	if cfg != nil {
		if p := cfg.Passphrase.String(); p != "" {
			return p
		}
	}
	return os.Getenv("AGBERO_PASSPHRASE")
}
