package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Compression struct {
	Compression bool   `hcl:"compression,optional"`
	Level       int    `hcl:"compression_level,optional"` // 1-11, default 5
	Type        string `hcl:"type,optional"`              // "gzip" (default) or "brotli"
}

func (c *Compression) Validate() error {
	if !c.Compression {
		return nil // No validation needed if compression is disabled
	}

	// Level validation
	if c.Level < 0 || c.Level > 11 {
		return errors.New("compression_level must be between 0 and 11")
	}

	// Type validation (if provided)
	if c.Type != "" {
		c.Type = strings.ToLower(c.Type)
		if c.Type != "gzip" && c.Type != "brotli" {
			return errors.New("compression type must be 'gzip' or 'brotli'")
		}
	} else {
		c.Type = "gzip" // Default
	}

	return nil
}
