package cache

import (
	"hash/fnv"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/maypok86/otter/v2"
)

type Map struct {
	inner *otter.Cache[string, *Item]
	locks [256]sync.Mutex
}

// NewMap creates a bounded concurrent cache with handler lifecycle management.
func NewMap() *Map {
	c := otter.Must(&otter.Options[string, *Item]{
		MaximumSize: int(woos.CacheMax),
		OnDeletion: func(e otter.DeletionEvent[string, *Item]) {
			closeItem(e.Value)
		},
	})
	return &Map{inner: c}
}

// Load returns the value stored under the given key, if present.
func (m *Map) Load(key string) (*Item, bool) {
	return m.inner.GetIfPresent(key)
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
func (m *Map) LoadOrStore(key string, value *Item) (*Item, bool) {
	v, stored := m.inner.SetIfAbsent(key, value)
	if stored {
		return v, false
	}
	return v, true
}

// Store sets the value for a key, replacing any existing value.
func (m *Map) Store(key string, value *Item) {
	mu := m.lockFor(key)
	mu.Lock()
	defer mu.Unlock()

	if old, ok := m.inner.GetIfPresent(key); ok && old != value {
		closeItem(old)
	}
	m.inner.Set(key, value)
}

// Delete removes the value associated with the key.
func (m *Map) Delete(key string) {
	m.inner.Invalidate(key)
}

// LoadAndDelete deletes the value for a key and returns the previous value if present.
func (m *Map) LoadAndDelete(key string) (*Item, bool) {
	mu := m.lockFor(key)
	mu.Lock()
	defer mu.Unlock()

	v, ok := m.inner.GetIfPresent(key)
	if !ok {
		return nil, false
	}
	m.inner.Invalidate(key)
	return v, true
}

// Swap sets the value for a key and returns the previous value if present.
func (m *Map) Swap(key string, value *Item) (*Item, bool) {
	mu := m.lockFor(key)
	mu.Lock()
	defer mu.Unlock()

	old, ok := m.inner.GetIfPresent(key)
	if ok && old != value {
		closeItem(old)
	}
	m.inner.Set(key, value)
	return old, ok
}

// CompareAndSwap replaces the value for a key only if it currently equals old.
func (m *Map) CompareAndSwap(key string, old, new *Item) bool {
	mu := m.lockFor(key)
	mu.Lock()
	defer mu.Unlock()

	cur, ok := m.inner.GetIfPresent(key)
	if !ok || cur != old {
		return false
	}

	if cur != new {
		closeItem(cur)
	}
	m.inner.Set(key, new)
	return true
}

func (m *Map) lockFor(key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &m.locks[h.Sum32()%uint32(len(m.locks))]
}

// closeItem closes the underlying handler if it implements Close.
func closeItem(it *Item) {
	if it == nil || it.Handler == nil {
		return
	}
	if closer, ok := it.Handler.(interface{ Close() error }); ok {
		_ = closer.Close()
		return
	}
	if closer, ok := it.Handler.(interface{ Close() }); ok {
		closer.Close()
	}
}
