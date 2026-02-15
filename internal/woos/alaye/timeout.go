package alaye

import "time"

type Timeout struct {
	Enabled    Enabled       `hcl:"enabled,optional" json:"enabled"`
	Read       time.Duration `hcl:"read,optional" json:"read"`
	Write      time.Duration `hcl:"write,optional" json:"write"`
	Idle       time.Duration `hcl:"idle,optional" json:"idle"`
	ReadHeader time.Duration `hcl:"read_header,optional" json:"read_header"`
}

func (t *Timeout) Validate() error {
	if t.Enabled.No() {
		return nil
	}

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
	Enabled Enabled       `hcl:"enabled,optional" json:"enabled"`
	Request time.Duration `hcl:"request,optional" json:"request"`
}

func (t *TimeoutRoute) Validate() error {
	if t.Enabled.No() {
		return nil
	}
	// Request timeout validation (if provided)
	if t.Request < 0 {
		return ErrNegativeRequestTimeout
	}
	return nil
}
