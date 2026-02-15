package alaye

import (
	"strings"
)

type Compression struct {
	Status Enabled `hcl:"enabled,optional" json:"enabled"`
	Level  int     `hcl:"level,optional" json:"level"` // 1-11, default 5
	Type   string  `hcl:"type,optional" json:"type"`   // "gzip" (default) or "brotli"
}

func (c *Compression) Validate() error {
	if c.Status.No() {
		return nil // No validation needed if compression is disabled
	}

	// Level validation
	if c.Level < MinCompressionLevel || c.Level > MaxCompressionLevel {
		return ErrInvalidCompressionLevel
	}

	// Type validation (if provided)
	if c.Type != "" {
		c.Type = strings.ToLower(c.Type)
		if c.Type != CompressionGzip && c.Type != CompressionBrotli {
			return ErrInvalidCompressionType
		}
	} else {
		c.Type = DefaultCompressionType // Default
	}

	return nil
}
