package alaye

import (
	"time"
)

type CircuitBreaker struct {
	Threshold int           `hcl:"threshold,optional" json:"threshold"`
	Duration  time.Duration `hcl:"duration,optional" json:"duration"`
}

func (c *CircuitBreaker) Validate() error {
	// Threshold validation (if provided)
	if c.Threshold < 0 {
		return ErrNegativeThreshold
	}
	if c.Threshold == 0 {
		c.Threshold = DefaultCircuitBreakerThreshold // Default
	}

	// Duration validation (if provided)
	if c.Duration < 0 {
		return ErrNegativeDuration
	}
	if c.Duration == 0 {
		c.Duration = DefaultCircuitBreakerDuration // Default
	}

	return nil
}
