package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Cache struct {
	Enabled Enabled       `hcl:"enabled,optional" json:"enabled"`
	Driver  string        `hcl:"driver,optional" json:"driver"` // "memory", "redis"
	TTL     time.Duration `hcl:"ttl,optional" json:"ttl"`
	Methods []string      `hcl:"methods,optional" json:"methods"`

	Memory *MemoryCache `hcl:"memory,block" json:"memory,omitempty"`
	Redis  *RedisCache  `hcl:"redis,block" json:"redis,omitempty"`
}

type MemoryCache struct {
	MaxItems int `hcl:"max_items,optional" json:"max_items"`
}

type RedisCache struct {
	Host      string `hcl:"host,optional" json:"host"`
	Port      int    `hcl:"port,optional" json:"port"`
	Password  string `hcl:"password,optional" json:"password"`
	DB        int    `hcl:"db,optional" json:"db"`
	KeyPrefix string `hcl:"key_prefix,optional" json:"key_prefix"`
}

func (c *Cache) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	if c.Driver == "" {
		c.Driver = "memory"
	}
	if c.Driver != "memory" && c.Driver != "redis" {
		return errors.Newf("cache: unsupported driver %q", c.Driver)
	}
	for i, m := range c.Methods {
		c.Methods[i] = strings.ToUpper(m)
	}
	return nil
}
