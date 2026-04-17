package alaye

import (
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Compression struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Level   int           `hcl:"level,attr" json:"level"`
	Type    string        `hcl:"type,attr" json:"type"`
}

// Validate checks compression level bounds and type value.
// It does not set defaults — all defaults are applied by woos.defaultCompression.
func (c *Compression) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	if c.Level < def.MinCompressionLevel || c.Level > def.MaxCompressionLevel {
		return def.ErrInvalidCompressionLevel
	}
	if c.Type != def.CompressionGzip && c.Type != def.CompressionBrotli {
		return errors.Newf("compression: unsupported type %q", c.Type)
	}
	return nil
}

func (c Compression) IsZero() bool {
	return c.Enabled.IsZero() && c.Level == 0 && c.Type == ""
}
