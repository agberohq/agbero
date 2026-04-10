package stash

import (
	"fmt"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

type Store interface {
	Get(key string) (*Entry, bool)
	Set(key string, entry *Entry, ttl time.Duration)
	SetWithPolicy(key string, entry *Entry, policy *alaye.TTLPolicy, defaultTTL time.Duration)
	Delete(key string)
	Clear() error
	Close() error
}

type Config struct {
	Driver     string
	DefaultTTL time.Duration
	MaxItems   int
	Redis      *alaye.RedisCache
	Policy     *alaye.TTLPolicy
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
