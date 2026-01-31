package alaye

import (
	"time"
)

type Timeout struct {
	Read       time.Duration `hcl:"read,optional"`
	Write      time.Duration `hcl:"write,optional"`
	Idle       time.Duration `hcl:"idle,optional"`
	ReadHeader time.Duration `hcl:"read_header,optional"`
}

func (t *Timeout) Validate() error {
	// All timeouts are optional, but if set they must be positive

	if t.Read < 0 {
		return ErrNegativeReadTimeout
	}
	if t.Write < 0 {
		return ErrNegativeWriteTimeout
	}
	if t.Idle < 0 {
		return ErrNegativeIdleTimeout
	}
	if t.ReadHeader < 0 {
		return ErrNegativeReadHeaderTimeout
	}

	// Set defaults if not provided (caller will apply defaults later)
	return nil
}

type TimeoutRoute struct {
	Request time.Duration `hcl:"request,optional"`
}

func (t *TimeoutRoute) Validate() error {
	// Request timeout validation (if provided)
	if t.Request < 0 {
		return ErrNegativeRequestTimeout
	}
	return nil
}
