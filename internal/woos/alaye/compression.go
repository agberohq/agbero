package alaye

import (
	"strings"
)

type Compression struct {
	Enabled bool   `hcl:"enabled,optional"`
	Level   int    `hcl:"level,optional"` // 1-11, default 5
	Type    string `hcl:"type,optional"`  // "gzip" (default) or "brotli"
}

func (c *Compression) Validate() error {
	if !c.Enabled {
		return nil // No validation needed if compression is disabled
	}

	// Level validation
	if c.Level < MinCompressionLevel || c.Level > MaxCompressionLevel {
		return ErrInvalidCompressionLevel
	}

	// Type validation (if provided)
	if c.Type != "" {
		c.Type = strings.ToLower(c.Type)
		if c.Type != "gzip" && c.Type != "brotli" {
			return ErrInvalidCompressionType
		}
	} else {
		c.Type = DefaultCompressionType // Default
	}

	return nil
}
