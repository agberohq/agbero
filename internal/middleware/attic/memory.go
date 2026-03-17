package attic

import (
	"net/http"
	"strconv"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/cespare/xxhash/v2"
	"github.com/olekukonko/mappo"
)

type MemoryStore struct {
	cache  *mappo.Cache
	maxTTL time.Duration
}

func NewMemoryStore(cfg *alaye.Cache) (*MemoryStore, error) {
	maxItems := 10_000

	if cfg.Memory != nil && cfg.Memory.MaxItems > 0 {
		maxItems = cfg.Memory.MaxItems
	}

	return &MemoryStore{
		cache: mappo.NewCache(mappo.CacheOptions{
			MaximumSize: maxItems,
			OnDelete:    mappo.CloserDelete,
		}),
		maxTTL: cfg.TTL.StdDuration(),
	}, nil
}

func (s *MemoryStore) Get(key string) (*Entry, bool) {
	it, ok := s.cache.Load(key)
	if !ok {
		return nil, false
	}
	entry, valid := mappo.GetTyped[*Entry](it)
	if !valid {
		s.cache.Delete(key)
		return nil, false
	}
	return entry, true
}

func (s *MemoryStore) Set(key string, entry *Entry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	item := &mappo.Item{Value: entry}
	s.cache.StoreTTL(key, item, ttl)
}

func (s *MemoryStore) Delete(key string) {
	s.cache.Delete(key)
}

func (s *MemoryStore) Clear() error {
	s.cache.Clear()
	return nil
}

func (s *MemoryStore) Close() error {
	return s.cache.Close()
}

func generateKey(r *http.Request) string {
	h := xxhash.New()
	h.WriteString(r.Host)
	h.WriteString(r.Method)
	h.WriteString(r.URL.Path)
	h.WriteString(r.URL.RawQuery)
	for _, header := range []string{"Accept-Language", "Accept-Encoding", "Accept"} {
		if v := r.Header.Get(header); v != "" {
			h.WriteString(header)
			h.WriteString(v)
		}
	}
	return strconv.FormatUint(h.Sum64(), 36)
}
