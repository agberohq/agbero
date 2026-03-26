package security

import (
	"github.com/agberohq/agbero/internal/core/alaye"
)

// Resolver bridges a *Store to alaye's value resolution system.
//
// Usage in server.go:
//
//	r := security.NewResolver(store)
//	r.Wire()   // calls alaye.SetStoreLookup — do this after Unlock()
//
// After Wire() is called, any alaye.Value containing "ss://key",
// "ss.key", or "keeper.key" will be transparently resolved from
// the store whenever .String() or .Resolve() is called.
type Resolver struct {
	store *Store
}

// NewResolver creates a Resolver for the given store.
func NewResolver(store *Store) *Resolver {
	return &Resolver{store: store}
}

// Wire registers the store's Get method as the global keeper lookup in alaye.
// Call this immediately after Store.Unlock() or Store.UnlockShamir() succeeds.
//
// It is safe to call Wire multiple times (e.g. after a key rotation); the
// most recent call wins.
func (r *Resolver) Wire() {
	alaye.SetStoreLookup(r.store.Get)
}

// Unwire removes the global keeper lookup (e.g. when the store is locked).
// After this call, any alaye.Value with a keeper ref will silently return "".
func (r *Resolver) Unwire() {
	alaye.SetStoreLookup(nil)
}

// Resolve is a convenience wrapper for resolving a single alaye.Value
// using the store — useful in server-side code that already has a Resolver
// but wants explicit resolution with error feedback.
func (r *Resolver) Resolve(v alaye.Value) (string, error) {
	return v.ResolveErr(nil) // storeLookupFn already wired via Wire()
}
