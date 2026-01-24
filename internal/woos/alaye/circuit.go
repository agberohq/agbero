package alaye

import (
	"time"

	"github.com/olekukonko/errors"
)

type CircuitBreaker struct {
	Threshold int           `hcl:"threshold,optional"`
	Duration  time.Duration `hcl:"duration,optional"`
}

func (c *CircuitBreaker) Validate() error {
	// Threshold validation (if provided)
	if c.Threshold < 0 {
		return errors.New("threshold cannot be negative")
	}
	if c.Threshold == 0 {
		c.Threshold = 5 // Default
	}

	// Duration validation (if provided)
	if c.Duration < 0 {
		return errors.New("duration cannot be negative")
	}
	if c.Duration == 0 {
		c.Duration = 30 * time.Second // Default
	}

	return nil
}
