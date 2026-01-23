package alaye

import (
	"time"

	"github.com/olekukonko/errors"
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
		return errors.New("read timeout cannot be negative")
	}
	if t.Write < 0 {
		return errors.New("write timeout cannot be negative")
	}
	if t.Idle < 0 {
		return errors.New("idle timeout cannot be negative")
	}
	if t.ReadHeader < 0 {
		return errors.New("read_header timeout cannot be negative")
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
		return errors.New("request timeout cannot be negative")
	}
	return nil
}
