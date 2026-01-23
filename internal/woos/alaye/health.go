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
		return errors.New("path is required for health_check")
	}
	if !strings.HasPrefix(h.Path, "/") {
		return errors.Newf("path %q must start with '/'", h.Path)
	}

	// Interval validation (if provided)
	if h.Interval < 0 {
		return errors.New("interval cannot be negative")
	}
	if h.Interval == 0 {
		h.Interval = 10 * time.Second // Default
	}

	// Timeout validation (if provided)
	if h.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}
	if h.Timeout == 0 {
		h.Timeout = 5 * time.Second // Default
	}
	if h.Timeout > h.Interval {
		return errors.New("timeout cannot be greater than interval")
	}

	// Threshold validation (if provided)
	if h.Threshold < 0 {
		return errors.New("threshold cannot be negative")
	}
	if h.Threshold == 0 {
		h.Threshold = 3 // Default
	}

	return nil
}
