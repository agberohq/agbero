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
		return errors.New("ttl cannot be negative")
	}

	// Max entries validation (if provided)
	if r.MaxEntries < 0 {
		return errors.New("max_entries cannot be negative")
	}

	// Auth prefixes validation (if provided)
	for i, prefix := range r.AuthPrefixes {
		if prefix == "" {
			return errors.Newf("auth_prefixes[%d]: cannot be empty", i)
		}
		if !strings.HasPrefix(prefix, "/") {
			return errors.Newf("auth_prefixes[%d]: %q must start with '/'", i, prefix)
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
	Requests int           `hcl:"requests"`
	Burst    int           `hcl:"burst,optional"`
	Window   time.Duration `hcl:"window"`
}

func (r *RatePolicy) Validate() error {
	// All fields are required for a policy to be active
	// But an empty/zero policy is valid (means no rate limiting)

	if r.Requests < 0 {
		return errors.New("requests cannot be negative")
	}
	if r.Requests == 0 {
		// Zero requests means no rate limiting, which is valid
		return nil
	}

	if r.Window <= 0 {
		return errors.New("window must be positive when requests > 0")
	}

	if r.Burst < 0 {
		return errors.New("burst cannot be negative")
	}
	if r.Burst == 0 {
		r.Burst = r.Requests // Default burst to requests
	}
	if r.Burst < r.Requests {
		return errors.New("burst cannot be less than requests")
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
