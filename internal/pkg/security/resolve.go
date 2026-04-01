// security/resolve.go
package security

import (
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/keeper"
)

type Resolver struct {
	store *keeper.Keeper
}

func NewResolver(store *keeper.Keeper) *Resolver {
	return &Resolver{store: store}
}

func (r *Resolver) Wire() {
	expect.SetStoreLookup(func(key string) (string, error) {
		if key == "" {
			return "", nil
		}

		val, err := r.store.Get(key)
		if err != nil {
			if err == keeper.ErrKeyNotFound {
				return key, nil
			}
			return key, nil
		}
		return string(val), nil
	})
}

func (r *Resolver) Unwire() {
	expect.SetStoreLookup(nil)
}

func (r *Resolver) Resolve(v expect.Value) (string, error) {
	return v.ResolveErr(nil)
}

func (r *Resolver) ResolveNamespaced(scheme, namespace string, v expect.Value) (string, error) {
	val, err := r.store.GetNamespacedFull(scheme, namespace, v.String())
	if err != nil {
		if err == keeper.ErrKeyNotFound {
			return v.String(), nil
		}
		return "", err
	}
	return string(val), nil
}
