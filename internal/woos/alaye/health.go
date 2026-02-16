package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type HealthCheck struct {
	Enabled   Enabled       `hcl:"enabled,optional" json:"enabled"`
	Path      string        `hcl:"path" json:"path"`
	Interval  time.Duration `hcl:"interval,optional" json:"interval"`
	Timeout   time.Duration `hcl:"timeout,optional" json:"timeout"`
	Threshold int           `hcl:"threshold,optional" json:"threshold"`
}

func (h *HealthCheck) Validate() error {
	if !h.Enabled.Active() {
		return nil
	}
	// Path validation
	if h.Path == "" {
		return ErrHealthPathRequired
	}
	if !strings.HasPrefix(h.Path, Slash) {
		return errors.Newf(" %w: path %q must start with '/'", ErrHealthPathInvalid, h.Path)
	}

	// Interval validation (if provided)
	if h.Interval < 0 {
		return ErrNegativeInterval
	}
	if h.Interval == 0 {
		h.Interval = DefaultHealthInterval
	}

	// Timeout validation (if provided)
	if h.Timeout < 0 {
		return ErrNegativeTimeout
	}
	if h.Timeout == 0 {
		h.Timeout = DefaultHealthTimeout
	}
	if h.Timeout > h.Interval {
		return ErrTimeoutExceedsInterval
	}

	// Threshold validation (if provided)
	if h.Threshold < 0 {
		return ErrNegativeThreshold
	}
	if h.Threshold == 0 {
		h.Threshold = DefaultHealthThreshold // Default
	}

	return nil
}
