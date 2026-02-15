package alaye

import "time"

type CircuitBreaker struct {
	Status    Status        `hcl:"enabled,optional" json:"enabled"`
	Threshold int           `hcl:"threshold,optional" json:"threshold"`
	Duration  time.Duration `hcl:"duration,optional" json:"duration"`
}

func (c *CircuitBreaker) Validate() error {
	if !c.Status.Enabled() {
		return nil
	}
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
		c.Duration = DefaultCircuitBreakerDuration
	}

	return nil
}
