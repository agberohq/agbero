package stash

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/cespare/xxhash/v2"
	"github.com/olekukonko/mappo"
)

type MemoryStore struct {
	cache      *mappo.Cache
	defaultTTL time.Duration
	policy     *alaye.TTLPolicy
}

func NewMemoryStore(cfg *Config) (*MemoryStore, error) {
	maxItems := cfg.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

	return &MemoryStore{
		cache: mappo.NewCache(mappo.CacheOptions{
			MaximumSize: maxItems,
			OnDelete:    mappo.CloserDelete,
		}),
		defaultTTL: cfg.DefaultTTL,
		policy:     cfg.Policy,
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

func (s *MemoryStore) SetWithPolicy(key string, entry *Entry, policy *alaye.TTLPolicy, defaultTTL time.Duration) {
	usePolicy := policy
	if usePolicy == nil {
		usePolicy = s.policy
	}

	if usePolicy == nil || !usePolicy.IsEnabled() {
		s.Set(key, entry, defaultTTL)
		return
	}

	ttl := usePolicy.GetTTL(defaultTTL, entry.ContentType)
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

// Key generates a cache key from request with optional scope support
func Key(r *http.Request, scope []string) string {
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

	for _, s := range scope {
		switch {
		case strings.HasPrefix(s, "header:"):
			header := strings.TrimPrefix(s, "header:")
			if v := r.Header.Get(header); v != "" {
				h.WriteString(header)
				h.WriteString(v)
			}
		case s == "auth":
			if authID := r.Context().Value("auth_id"); authID != nil {
				if id, ok := authID.(string); ok {
					h.WriteString("auth")
					h.WriteString(id)
				}
			}
			// "query" case is intentionally omitted - RawQuery already includes it
		}
	}

	return strconv.FormatUint(h.Sum64(), 36)
}

func KeyWithCustomHeaders(r *http.Request, scope []string, additionalHeaders []string) string {
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

	for _, header := range additionalHeaders {
		if v := r.Header.Get(header); v != "" {
			h.WriteString(header)
			h.WriteString(v)
		}
	}

	for _, s := range scope {
		switch {
		case strings.HasPrefix(s, "header:"):
			header := strings.TrimPrefix(s, "header:")
			if v := r.Header.Get(header); v != "" {
				h.WriteString(header)
				h.WriteString(v)
			}
		case s == "auth":
			if authID := r.Context().Value("auth_id"); authID != nil {
				if id, ok := authID.(string); ok {
					h.WriteString("auth")
					h.WriteString(id)
				}
			}
		}
	}

	return strconv.FormatUint(h.Sum64(), 36)
}
