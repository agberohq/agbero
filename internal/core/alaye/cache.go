package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Cache struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Driver  string        `hcl:"driver,attr" json:"driver"`
	TTL     Duration      `hcl:"ttl,attr" json:"ttl"`
	Methods []string      `hcl:"methods,attr" json:"methods"`

	Memory *MemoryCache `hcl:"memory,block" json:"memory,omitempty"`
	Redis  *RedisCache  `hcl:"redis,block" json:"redis,omitempty"`
}

type MemoryCache struct {
	MaxItems int `hcl:"max_items,attr" json:"max_items"`
}

type RedisCache struct {
	Host      string `hcl:"host,attr" json:"host"`
	Port      int    `hcl:"port,attr" json:"port"`
	Password  string `hcl:"password,attr" json:"password"`
	DB        int    `hcl:"db,attr" json:"db"`
	KeyPrefix string `hcl:"key_prefix,attr" json:"key_prefix"`
}

// Validate checks that the cache driver is one of the supported values.
// It does not set defaults — all defaults are applied by woos.defaultCache.
func (c *Cache) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	if c.Driver != "memory" && c.Driver != "redis" {
		return errors.Newf("cache: unsupported driver %q", c.Driver)
	}
	return nil
}
