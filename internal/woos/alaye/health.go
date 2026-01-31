package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type HealthCheck struct {
	Path      string        `hcl:"path"`
	Interval  time.Duration `hcl:"interval,optional"`
	Timeout   time.Duration `hcl:"timeout,optional"`
	Threshold int           `hcl:"threshold,optional"`
}

func (h *HealthCheck) Validate() error {
	// Path validation
	if h.Path == "" {
		return ErrHealthPathRequired
	}
	if !strings.HasPrefix(h.Path, "/") {
		return errors.Newf(" %w: path %q must start with '/'", ErrHealthPathInvalid, h.Path)
	}

	// Interval validation (if provided)
	if h.Interval < 0 {
		return ErrNegativeInterval
	}
	if h.Interval == 0 {
		h.Interval = DefaultHealthInterval // Default
	}

	// Timeout validation (if provided)
	if h.Timeout < 0 {
		return ErrNegativeTimeout
	}
	if h.Timeout == 0 {
		h.Timeout = DefaultHealthTimeout // Default
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
