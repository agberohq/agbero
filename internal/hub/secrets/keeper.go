package secrets

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/zero"
)

// OpenStore opens (or creates) the keeper database at dataDir/keeper.db.
//
// Passphrase resolution order:
// cfg.Passphrase (any expect.Value — plain text, env., ss://, b64. …)
// AGBERO_PASSPHRASE environment variable
// If neither is set: return a locked store so the caller can prompt and
//
//	call store.Unlock(passphrase) themselves (used by setup/home.go and the
//	interactive run mode).
//
// A nil cfg is valid and means "open the store locked, let the caller unlock".
// An empty passphrase string (cfg.Passphrase = "") also means locked-on-return
// unless AGBERO_PASSPHRASE is set.
//
// Special case — development mode:
// If cfg.Passphrase resolves to the literal string "dev" (or AGBERO_PASSPHRASE="dev"),
// the store is unlocked with a fixed sentinel passphrase. The KDF rejects empty
// passwords so we cannot use []byte{}. The sentinel is stable across restarts —
// a dev store opened twice with "dev" opens correctly both times.
// Production stores must never use this mode.
func OpenStore(dataDir string, cfg *alaye.Keeper, logger *ll.Logger) (*keeper.Keeper, error) {
	if logger == nil {
		logger = ll.New("keeper").Disable()
	}

	if err := os.MkdirAll(dataDir, woos.DirPerm); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, woos.DefaultKeeperName)

	kConfig := keeper.Config{
		DBPath:      dbPath,
		Logger:      logger,
		EnableAudit: true,
	}

	if cfg != nil {

		// disable logging if logging is disabled
		if !cfg.Logging.Active() {
			kConfig.Logger = ll.New("keeper").Disable()
		}

		if cfg.Enabled.Inactive() {
			logger.Warn("keeper is marked disabled in config but is a compulsory component — proceeding")
		}
		if cfg.AutoLock > 0 {
			kConfig.AutoLockInterval = cfg.AutoLock.StdDuration()
		}
		if cfg.Audit.Active() {
			kConfig.EnableAudit = true
		}
	}

	// Open or create the database.
	isNew := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isNew = true
	}

	var (
		store *keeper.Keeper
		err   error
	)
	if isNew {
		store, err = keeper.New(kConfig)
	} else {
		store, err = keeper.Open(kConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open keeper database: %w", err)
	}

	// Resolve passphrase.
	passphrase := resolvePassphrase(cfg)

	switch {
	case passphrase == "":
		// No passphrase available. Return the store locked; the caller is
		// responsible for prompting and calling store.Unlock.
		return store, nil

	case passphrase == "dev":
		// Development shorthand. The KDF rejects empty passwords so we use a
		// non-empty sentinel. It is deterministic — a dev store opened
		// twice with passphrase="dev" reopens correctly.
		// Log loudly so this is never silently used in production.
		logger.Warn("keeper: opening in DEV mode — DO NOT use in production")
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
		return store, nil

	default:
		// Normal passphrase. Derive and unlock, then zero the raw bytes.
		passBytes := []byte(passphrase)
		master, deriveErr := store.DeriveMaster(passBytes)
		zero.Bytes(passBytes)
		if deriveErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to derive master key: %w", deriveErr)
		}
		if unlockErr := store.UnlockDatabase(master); unlockErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
		}
		return store, nil
	}
}

// resolvePassphrase returns the first non-empty passphrase from:
// cfg.Passphrase (resolved through expect.Value — handles env., b64., ss:// …)
// AGBERO_PASSPHRASE environment variable
//
// Returns "" when no passphrase is available — callers that need an unlocked
// store must detect this and prompt the user.
func resolvePassphrase(cfg *alaye.Keeper) string {
	if cfg != nil {
		if p := cfg.Passphrase.String(); p != "" {
			return p
		}
	}
	return os.Getenv("AGBERO_PASSPHRASE")
}
