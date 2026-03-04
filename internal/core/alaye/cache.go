package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Cache struct {
	Enabled Enabled       `hcl:"enabled,optional" json:"enabled"`
	Driver  string        `hcl:"driver,optional" json:"driver"` // "memory"
	TTL     time.Duration `hcl:"ttl,optional" json:"ttl"`
	Methods []string      `hcl:"methods,optional" json:"methods"`
	// Driver specific options (e.g. max_size_mb for memory)
	Options map[string]string `hcl:"options,optional" json:"options"`
}

func (c *Cache) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	if c.Driver == "" {
		c.Driver = "memory"
	}
	if c.Driver != "memory" {
		return errors.Newf("cache: unsupported driver %q", c.Driver)
	}
	for i, m := range c.Methods {
		c.Methods[i] = strings.ToUpper(m)
	}
	return nil
}
