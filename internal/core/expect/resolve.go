package expect

import (
	"github.com/agberohq/keeper"
)

// Resolver bridges a *Keeper to alaye's value resolution system with namespace support.
//
//	r := security.NewResolver(store)
//	r.Wire()   // calls alaye.SetStoreLookup — do this after Unlock()
//
// After Wire() is called, any alaye.Value containing "ss://key",
// "ss.key", or "keeper.key" will be transparently resolved from
// the store whenever .String() or .Resolve() is called.
//
// Namespace support:
//   - "ss://prod/db/password" resolves from scheme=prod, namespace=db
//   - "ss://db/password"      resolves from default scheme, namespace=db
//   - "ss.db/password"        resolves from default scheme, namespace=db
type Resolver struct {
	store *keeper.Keeper
}

// NewResolver creates a Resolver for the given store.
func NewResolver(store *keeper.Keeper) *Resolver {
	return &Resolver{store: store}
}

// Wire registers the store's Get method as the global keeper lookup in alaye.
// Call this immediately after Store.Unlock() succeeds.
//
// keeper.Get handles the full 3-tier format: [scheme://][namespace/]key
// so we delegate directly — no manual parsing needed.
func (r *Resolver) Wire() {
	SetStoreLookup(func(key string) (string, error) {
		// Check if this looks like a keeper key
		if key == "" {
			return "", nil
		}

		// Try to get the value from the store
		val, err := r.store.Get(key)
		if err != nil {
			// If the key doesn't exist, return the original key as fallback
			// This allows non-keeper keys to work normally
			if err == keeper.ErrKeyNotFound {
				return key, nil
			}
			// For other errors (locked store, etc.), return the original key
			// but log the error in debug mode
			return key, nil
		}

		// Return the resolved value as a string
		return string(val), nil
	})
}

// Unwire removes the global keeper lookup (e.g. when the store is locked).
func (r *Resolver) Unwire() {
	SetStoreLookup(nil)
}

// Resolve is a convenience wrapper for resolving a single alaye.Value.
// Note: This relies on Wire() having been called to set the global lookup.
func (r *Resolver) Resolve(v Value) (string, error) {
	// First try to resolve using the global lookup
	resolved, err := v.ResolveErr(nil)
	if err != nil {
		// If resolution fails with an error, try manual lookup
		key := v.String()
		val, getErr := r.store.Get(key)
		if getErr != nil {
			return key, getErr
		}
		return string(val), nil
	}

	// If resolved is the same as the original key string, try manual lookup
	// This handles cases where the global lookup returned the key itself
	if resolved == v.String() {
		val, getErr := r.store.Get(resolved)
		if getErr == nil {
			return string(val), nil
		}
	}

	return resolved, err
}

// ResolveNamespaced resolves an alaye.Value from explicit scheme/namespace.
func (r *Resolver) ResolveNamespaced(scheme, namespace string, v Value) (string, error) {
	val, err := r.store.GetNamespacedFull(scheme, namespace, v.String())
	if err != nil {
		// If the key doesn't exist, return the original value
		if err == keeper.ErrKeyNotFound {
			return v.String(), nil
		}
		return "", err
	}
	return string(val), nil
}
