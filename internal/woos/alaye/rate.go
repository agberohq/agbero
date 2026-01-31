package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Rate struct {
	TTL          time.Duration `hcl:"ttl,optional"`
	MaxEntries   int64         `hcl:"max_entries,optional"`
	AuthPrefixes []string      `hcl:"auth_prefixes,optional"`
	Global       RatePolicy    `hcl:"global,block"`
	Auth         RatePolicy    `hcl:"auth,block"`
}

func (r *Rate) Validate() error {
	// TTL validation (if provided)
	if r.TTL < 0 {
		return ErrProxyRouteNegativeTTL
	}

	// Max entries validation (if provided)
	if r.MaxEntries < 0 {
		return ErrProxyRouteNegativeMaxEntries
	}

	// Auth prefixes validation (if provided)
	for i, prefix := range r.AuthPrefixes {
		if prefix == "" {
			return errors.Newf("%w: [%d]: cannot be empty", ErrProxyRouteInvalidAuthPrefix, i)
		}
		if !strings.HasPrefix(prefix, "/") {
			return errors.Newf("%w [%d]: %q must start with '/'", ErrProxyRouteInvalidAuthPrefix, i, prefix)
		}
	}

	// Global policy validation
	if err := r.Global.Validate(); err != nil {
		return errors.Newf("global: %w", err)
	}

	// Auth policy validation
	if err := r.Auth.Validate(); err != nil {
		return errors.Newf("auth: %w", err)
	}

	return nil
}

type RatePolicy struct {
	Requests  int           `hcl:"requests"`
	Burst     int           `hcl:"burst,optional"`
	Window    time.Duration `hcl:"window"`
	KeyHeader string        `hcl:"key_header,optional"`
}

func (r *RatePolicy) Validate() error {
	// All fields are required for a policy to be active
	// But an empty/zero policy is valid (means no rate limiting)

	if r.Requests < 0 {
		return ErrRateLimitNegativeRequests
	}
	if r.Requests == 0 {
		// Zero requests means no rate limiting, which is valid
		return nil
	}

	if r.Window <= 0 {
		return ErrRateLimitInvalidWindow
	}

	if r.Burst < 0 {
		return ErrRateLimitNegativeBurst
	}
	if r.Burst == 0 {
		r.Burst = r.Requests // Default burst to requests
	}
	if r.Burst < r.Requests {
		return ErrRateLimitBurstTooSmall
	}

	if r.KeyHeader != "" && strings.Contains(r.KeyHeader, " ") {
		return ErrRateLimitInvalidKeyHeader
	}

	return nil
}

func (r *RatePolicy) Policy() (requests int, window time.Duration, burst int, ok bool) {
	if r.Requests <= 0 {
		return 0, 0, 0, false
	}
	b := r.Burst
	if b <= 0 {
		b = r.Requests
	}
	return r.Requests, r.Window, b, true
}
