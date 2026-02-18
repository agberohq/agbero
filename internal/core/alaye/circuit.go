package alaye

import "time"

type CircuitBreaker struct {
	Enabled   Enabled       `hcl:"enabled,optional" json:"enabled"`
	Threshold int           `hcl:"threshold,optional" json:"threshold"`
	Duration  time.Duration `hcl:"duration,optional" json:"duration"`
}

func (c *CircuitBreaker) Validate() error {
	if !c.Enabled.Active() {
		return nil
	}
	// Threshold validation (if provided)
	if c.Threshold < 0 {
		return ErrNegativeThreshold
	}

	// Duration validation (if provided)
	if c.Duration < 0 {
		return ErrNegativeDuration
	}

	return nil
}
