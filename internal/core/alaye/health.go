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

	// New Advanced Fields
	Method         string            `hcl:"method,optional" json:"method"`
	Headers        map[string]string `hcl:"headers,optional" json:"headers"`
	ExpectedStatus []int             `hcl:"expected_status,optional" json:"expected_status"`
	ExpectedBody   string            `hcl:"expected_body,optional" json:"expected_body"`
}

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
	if h.Interval == 0 {
		h.Interval = DefaultHealthInterval
	}

	if h.Timeout < 0 {
		return ErrNegativeTimeout
	}
	if h.Timeout == 0 {
		h.Timeout = DefaultHealthTimeout
	}
	if h.Timeout > h.Interval {
		return ErrTimeoutExceedsInterval
	}

	if h.Threshold < 0 {
		return ErrNegativeThreshold
	}
	if h.Threshold == 0 {
		h.Threshold = DefaultHealthThreshold
	}

	if h.Method != "" {
		h.Method = strings.ToUpper(h.Method)
		switch h.Method {
		case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH":
		default:
			return errors.Newf("invalid health check method: %s", h.Method)
		}
	} else {
		h.Method = "GET"
	}

	return nil
}
