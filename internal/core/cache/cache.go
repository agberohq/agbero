package cache

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/maypok86/otter/v2"
)

type Item struct {
	Value        any          `json:"value"`
	LastAccessed atomic.Int64 `json:"last_accessed"`
	Exp          time.Time    `json:"exp"`
}

func (it *Item) MarshalJSON() ([]byte, error) {
	type Alias Item
	return json.Marshal(&struct {
		LastAccessed int64 `json:"last_accessed"`
		*Alias
	}{
		LastAccessed: it.LastAccessed.Load(),
		Alias:        (*Alias)(it),
	})
}

func (it *Item) UnmarshalJSON(b []byte) error {
	type Alias Item
	aux := &struct {
		LastAccessed int64 `json:"last_accessed"`
		*Alias
	}{
		Alias: (*Alias)(it),
	}
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	it.LastAccessed.Store(aux.LastAccessed)
	return nil
}

type Cache struct {
	inner *otter.Cache[string, *Item]
	now   func() time.Time
}

type Options struct {
	MaximumSize int
	OnDelete    func(key string, it *Item)
	Now         func() time.Time
}

func New(opt Options) *Cache {
	nowFn := opt.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	c := otter.Must(&otter.Options[string, *Item]{
		MaximumSize: opt.MaximumSize,
		OnDeletion: func(e otter.DeletionEvent[string, *Item]) {
			if opt.OnDelete == nil || e.Value == nil {
				return
			}
			opt.OnDelete(e.Key, e.Value)
		},
	})

	return &Cache{inner: c, now: nowFn}
}

func (c *Cache) Load(key string) (*Item, bool) {
	it, ok := c.inner.GetIfPresent(key)
	if !ok || it == nil {
		return nil, false
	}
	if !it.Exp.IsZero() && c.now().After(it.Exp) {
		c.inner.Invalidate(key)
		return nil, false
	}
	return it, true
}

func (c *Cache) Store(key string, it *Item) {
	c.inner.Set(key, it)
}

func (c *Cache) StoreTTL(key string, it *Item, ttl time.Duration) {
	if it == nil {
		return
	}
	if ttl > 0 {
		it.Exp = c.now().Add(ttl)
	} else {
		it.Exp = time.Time{}
	}
	c.inner.Set(key, it)
}

func (c *Cache) LoadOrStore(key string, it *Item) (*Item, bool) {
	v, stored := c.inner.SetIfAbsent(key, it)
	if stored {
		return v, false
	}

	if v == nil {
		return nil, true
	}

	if !v.Exp.IsZero() && c.now().After(v.Exp) {
		c.inner.Invalidate(key)
		c.inner.Set(key, it)
		return it, false
	}

	return v, true
}

func (c *Cache) Delete(key string) {
	c.inner.Invalidate(key)
}

func (c *Cache) LoadAndDelete(key string) (*Item, bool) {
	it, ok := c.Load(key)
	if !ok {
		return nil, false
	}
	c.inner.Invalidate(key)
	return it, true
}

func Get[T any](it *Item) (T, bool) {
	var zero T
	if it == nil || it.Value == nil {
		return zero, false
	}
	v, ok := it.Value.(T)
	return v, ok
}
