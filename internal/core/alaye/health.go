package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type HealthCheck struct {
	Enabled   expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Path      string        `hcl:"path,attr" json:"path"`
	Interval  Duration      `hcl:"interval,attr" json:"interval"`
	Timeout   Duration      `hcl:"timeout,attr" json:"timeout"`
	Threshold int           `hcl:"threshold,attr" json:"threshold"`

	Method         string            `hcl:"method,attr" json:"method"`
	Headers        map[string]string `hcl:"headers,attr" json:"headers"`
	ExpectedStatus []int             `hcl:"expected_status,attr" json:"expected_status"`
	ExpectedBody   string            `hcl:"expected_body,attr" json:"expected_body"`

	LatencyBaselineMs     int32   `hcl:"latency_baseline_ms,attr" json:"latency_baseline_ms"`
	LatencyDegradedFactor float64 `hcl:"latency_degraded_factor,attr" json:"latency_degraded_factor"`
	AcceleratedProbing    bool    `hcl:"accelerated_probing,attr" json:"accelerated_probing"`
	SyntheticWhenIdle     bool    `hcl:"synthetic_when_idle,attr" json:"synthetic_when_idle"`
}

// Validate checks path format, interval/timeout relationship, threshold, and method.
// It does not set defaults — all defaults are applied by woos.defaultHealthCheck.
func (h *HealthCheck) Validate() error {
	if !h.Enabled.Active() {
		return nil
	}

	if h.Path == "" {
		return ErrHealthPathRequired
	}
	if !strings.HasPrefix(h.Path, Slash) {
		return errors.Newf(" %w: path %q must start with '/'", ErrHealthPathInvalid, h.Path)
	}
	if h.Interval < 0 {
		return ErrNegativeInterval
	}
	if h.Timeout < 0 {
		return ErrNegativeTimeout
	}
	if h.Timeout > h.Interval {
		return ErrTimeoutExceedsInterval
	}
	if h.Threshold < 0 {
		return ErrNegativeThreshold
	}

	if h.Method != "" {
		switch strings.ToUpper(h.Method) {
		case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH":
		default:
			return errors.Newf("invalid health check method: %s", h.Method)
		}
	}

	return nil
}
