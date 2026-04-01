package security

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/zero"
)

// OpenStore is the single source of truth for configuring and opening Keeper.
func OpenStore(dataDir string, cfg *alaye.Keeper, logger *ll.Logger) (*keeper.Keeper, error) {
	if logger == nil {
		logger = ll.New("keeper").Disable()
	}
	dbPath := filepath.Join(dataDir, woos.DefaultKeeperName)
	kConfig := keeper.Config{
		DBPath:           dbPath,
		Logger:           logger,
		EnableAudit:      true,
		AutoLockInterval: 0,
	}
	var passphrase string
	if cfg != nil {
		if cfg.Enabled.Inactive() {
			logger.Warn("Keeper is marked as disabled in config, but is a compulsory component. Proceeding anyway.")
		}
		if cfg.AutoLock > 0 {
			kConfig.AutoLockInterval = cfg.AutoLock.StdDuration()
		}
		passphrase = cfg.Passphrase.String()
	}
	if passphrase == "" {
		passphrase = os.Getenv("AGBERO_PASSPHRASE")
	}
	isNew := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isNew = true
	}
	var store *keeper.Keeper
	var err error
	if isNew {
		store, err = keeper.New(kConfig)
	} else {
		store, err = keeper.Open(kConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open keeper database: %w", err)
	}

	// Handle passphrase-based unlock or empty passphrase
	if passphrase != "" {
		passBytes := []byte(passphrase)
		master, deriveErr := store.DeriveMaster(passBytes)
		zero.Bytes(passBytes) // Use exported function
		if deriveErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to derive master key: %w", deriveErr)
		}
		if unlockErr := store.UnlockDatabase(master); unlockErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
		}
	} else {
		// Empty passphrase: create an unlocked store without encryption (development mode)
		if err := store.UnlockDatabase(nil); err != nil {
			// If UnlockDatabase doesn't accept nil, create a default master key
			defaultKey := make([]byte, 32)
			master, deriveErr := store.DeriveMaster(defaultKey)
			zero.Bytes(defaultKey) // Use exported function
			if deriveErr != nil {
				store.Close()
				return nil, fmt.Errorf("failed to derive default master key: %w", deriveErr)
			}
			if unlockErr := store.UnlockDatabase(master); unlockErr != nil {
				store.Close()
				return nil, fmt.Errorf("failed to unlock database with default key: %w", unlockErr)
			}
		}
	}

	// Configure auto-lock if enabled
	if kConfig.AutoLockInterval > 0 {
		go func() {
			ticker := time.NewTicker(kConfig.AutoLockInterval)
			defer ticker.Stop()
			for range ticker.C {
				if store.IsLocked() {
					continue
				}
				if err := store.Lock(); err != nil {
					logger.Error("Failed to auto-lock store", "error", err)
				}
			}
		}()
	}

	return store, nil
}
