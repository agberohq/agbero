package alaye

type CircuitBreaker struct {
	Enabled   Enabled  `hcl:"enabled,attr" json:"enabled"`
	Threshold int      `hcl:"threshold,attr" json:"threshold"`
	Duration  Duration `hcl:"duration,attr" json:"duration"`
}

// Validate checks that threshold and duration are non-negative when circuit breaker is enabled.
func (c *CircuitBreaker) Validate() error {
	if !c.Enabled.Active() {
		return nil
	}
	if c.Threshold < 0 {
		return ErrNegativeThreshold
	}
	if c.Duration < 0 {
		return ErrNegativeDuration
	}
	return nil
}
