package alaye

import (
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

type CircuitBreaker struct {
	Enabled   expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Threshold int             `hcl:"threshold,attr" json:"threshold"`
	Duration  expect.Duration `hcl:"duration,attr" json:"duration"`
}

// Validate checks that threshold and duration are non-negative when circuit breaker is enabled.
func (c *CircuitBreaker) Validate() error {
	if !c.Enabled.Active() {
		return nil
	}
	if c.Threshold < 0 {
		return def.ErrNegativeThreshold
	}
	if c.Duration < 0 {
		return def.ErrNegativeDuration
	}
	return nil
}

func (c CircuitBreaker) IsZero() bool {
	return c.Enabled.IsZero() && c.Threshold == 0 && c.Duration == 0
}
