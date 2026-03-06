package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

// GlobalRate defines the global registry and default rules.
type GlobalRate struct {
	Enabled    Enabled       `hcl:"enabled,optional" json:"enabled"`
	TTL        time.Duration `hcl:"ttl,optional" json:"ttl"`
	MaxEntries int           `hcl:"max_entries,optional" json:"max_entries"`

	// Default rules applied to all routes (unless ignored)
	Rules []RateRule `hcl:"rule,block" json:"rules"`

	// Named policies that routes can opt-in to
	Policies []RatePolicy `hcl:"policy,block" json:"policies"`
}

func (g *GlobalRate) Validate() error {
	if !g.Enabled.Active() {
		return nil
	}

	if g.TTL < 0 {
		return ErrProxyRouteNegativeTTL
	}
	if g.MaxEntries < 0 {
		return ErrProxyRouteNegativeMaxEntries
	}

	for i, rule := range g.Rules {
		if err := rule.Validate(); err != nil {
			return errors.Newf("global rule[%d]: %w", i, err)
		}
	}

	for _, pol := range g.Policies {
		if err := pol.Validate(); err != nil {
			return errors.Newf("policy %q: %w", pol.Name, err)
		}
	}

	return nil
}

// RouteRate defines rate limiting for a specific route.
type RouteRate struct {
	Enabled      Enabled  `hcl:"enabled,optional" json:"enabled"`
	IgnoreGlobal bool     `hcl:"ignore_global,optional" json:"ignore_global"` // Stop global rules processing
	UsePolicy    string   `hcl:"use_policy,optional" json:"use_policy"`       // Reference a named policy
	Rule         RateRule `hcl:"rule,block" json:"rule"`                      // Ad-hoc definition
}

func (r *RouteRate) Validate() error {
	if !r.Enabled.Active() {
		return nil
	}

	if err := r.Rule.Validate(); err != nil {
		return errors.Newf("ad-hoc rule: %w", err)
	}

	return nil
}

// RatePolicy is a named configuration in the global scope.
type RatePolicy struct {
	Name     string        `hcl:"name,label" json:"name"`
	Requests int           `hcl:"requests" json:"requests"`
	Window   time.Duration `hcl:"window" json:"window"`
	Burst    int           `hcl:"burst,optional" json:"burst"`
	Key      string        `hcl:"key,optional" json:"key"` // "ip", "header:X", etc.
}

func (p *RatePolicy) Validate() error {
	if p.Name == "" {
		return errors.New("policy name is required")
	}
	// Re-use logic by casting to RateRule for validation
	rr := RateRule{
		Requests: p.Requests,
		Window:   p.Window,
		Burst:    p.Burst,
	}
	return rr.Validate()
}

// RateRule is a specific rule application (matching path/method).
type RateRule struct {
	Enabled  Enabled  `hcl:"enabled,optional" json:"enabled"`
	Name     string   `hcl:"name,label,optional" json:"name"` // Optional label for logging
	Prefixes []string `hcl:"prefixes,optional" json:"prefixes"`
	Methods  []string `hcl:"methods,optional" json:"methods"`

	Requests int           `hcl:"requests" json:"requests"`
	Window   time.Duration `hcl:"window" json:"window"`
	Burst    int           `hcl:"burst,optional" json:"burst"`
	Key      string        `hcl:"key,optional" json:"key"`
}

func (r *RateRule) Validate() error {
	if !r.Enabled.Active() {
		return nil
	}

	if r.Requests <= 0 {
		return ErrRateLimitNegativeRequests
	}

	if r.Window <= 0 {
		return ErrRateLimitInvalidWindow
	}

	if r.Burst < 0 {
		return ErrRateLimitNegativeBurst
	}
	if r.Burst == 0 {
		r.Burst = r.Requests
	}
	if r.Burst < r.Requests {
		return ErrRateLimitBurstTooSmall
	}

	if strings.Contains(r.Key, " ") {
		return ErrRateLimitInvalidKeyHeader
	}

	for i, m := range r.Methods {
		r.Methods[i] = strings.ToUpper(m)
	}

	return nil
}
