package secrets

import (
	"github.com/agberohq/keeper"
)

// SetGlobalStore registers store as the process-wide default Keeper instance.
// It delegates to keeper.GlobalStore so that both the keeper library's own
// GlobalGet and this package's GetGlobalStore always return the same value.
// Pass nil to clear the reference (e.g. during shutdown, before store.Close).
func SetGlobalStore(store *keeper.Keeper) {
	keeper.GlobalStore(store)
}

// GetGlobalStore returns the process-wide default Keeper instance, or nil if
// none has been registered.
func GetGlobalStore() *keeper.Keeper {
	return keeper.GlobalGet()
}
