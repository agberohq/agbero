package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type HealthCheck struct {
	Enabled   expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Path      string          `hcl:"path,attr" json:"path"`
	Interval  expect.Duration `hcl:"interval,attr" json:"interval"`
	Timeout   expect.Duration `hcl:"timeout,attr" json:"timeout"`
	Threshold int             `hcl:"threshold,attr" json:"threshold"`

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
		return def.ErrHealthPathRequired
	}
	if !strings.HasPrefix(h.Path, def.Slash) {
		return errors.Newf(" %w: path %q must start with '/'", def.ErrHealthPathInvalid, h.Path)
	}
	if h.Interval < 0 {
		return def.ErrNegativeInterval
	}
	if h.Timeout < 0 {
		return def.ErrNegativeTimeout
	}
	if h.Timeout > h.Interval {
		return def.ErrTimeoutExceedsInterval
	}
	if h.Threshold < 0 {
		return def.ErrNegativeThreshold
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

func (h HealthCheck) IsZero() bool {
	return h.Enabled.IsZero() &&
		h.Path == "" &&
		h.Interval == 0 &&
		h.Timeout == 0 &&
		h.Threshold == 0 &&
		h.Method == "" &&
		len(h.Headers) == 0 &&
		len(h.ExpectedStatus) == 0 &&
		h.ExpectedBody == "" &&
		h.LatencyBaselineMs == 0 &&
		h.LatencyDegradedFactor == 0 &&
		!h.AcceleratedProbing &&
		!h.SyntheticWhenIdle
}

type HealthCheckProtocol struct {
	Enabled  expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Interval expect.Duration `hcl:"interval,attr" json:"interval"`
	Timeout  expect.Duration `hcl:"timeout,attr" json:"timeout"`
	Send     expect.Encoded  `hcl:"send,attr" json:"send"`
	Expect   expect.Encoded  `hcl:"expect,attr" json:"expect"`
}

func (t *HealthCheckProtocol) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	switch {
	case t.Interval < 0:
		return errors.New("health_check.interval cannot be negative")
	case t.Timeout < 0:
		return errors.New("health_check.timeout cannot be negative")
	}
	return nil
}

func (t HealthCheckProtocol) IsZero() bool {
	return t.Enabled.IsZero() &&
		t.Interval == 0 &&
		t.Timeout == 0 &&
		t.Send.Empty() &&
		t.Expect.Empty()
}
