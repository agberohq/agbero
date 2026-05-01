package stash

import (
	"fmt"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// Store is the cache backend interface.
// PurgeByTag is required for CDN surrogate-key invalidation.
type Store interface {
	Get(key string) (*Entry, bool)
	Set(key string, entry *Entry, ttl time.Duration)
	SetWithPolicy(key string, entry *Entry, policy *alaye.TTLPolicy, defaultTTL time.Duration)
	Delete(key string)
	Clear() error
	Close() error

	// Purge removes all cached entries that carry the given surrogate tag.
	Purge(tag string) error
}

type Config struct {
	Driver     string
	DefaultTTL time.Duration
	MaxItems   int

	// MaxCacheableSize is the maximum response body size (bytes) that will be
	// stored. Responses larger than this are passed through without caching.
	// 0 means use the built-in default (def.CacheMaxBodySize).
	MaxCacheableSize int64

	Redis  *alaye.RedisCache
	Policy *alaye.TTLPolicy
}

func NewStore(cfg *Config) (Store, error) {
	switch cfg.Driver {
	case "memory", "":
		return NewMemoryStore(cfg)
	case "redis":
		return NewRedisStore(cfg)
	default:
		return nil, fmt.Errorf("unsupported cache driver: %s", cfg.Driver)
	}
}
