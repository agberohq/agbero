package secrets

import (
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
)

var (
	globalStore *keeper.Keeper
	globalMu    sync.RWMutex
)

// SetGlobalStore is called once when the Keeper is first opened
func SetGlobalStore(store *keeper.Keeper) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalStore = store
}

// GetGlobalStore returns the global Keeper instance (nil if not set)
func GetGlobalStore() *keeper.Keeper {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore
}

// OpenAndSetGlobal opens the Keeper and sets it as the global instance
func OpenAndSetGlobal(dataDir string, cfg *alaye.Keeper, logger *ll.Logger) (*keeper.Keeper, error) {
	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		return nil, err
	}
	SetGlobalStore(store)
	return store, nil
}
