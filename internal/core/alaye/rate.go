package alaye

import (
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type RateGlobal struct {
	Enabled    expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	TTL        expect.Duration `hcl:"ttl,attr" json:"ttl"`
	MaxEntries int             `hcl:"max_entries,attr" json:"max_entries"`

	Rules    []RateRule   `hcl:"rule,block" json:"rules"`
	Policies []RatePolicy `hcl:"policy,block" json:"policies"`
}

// Validate checks TTL, max_entries, and all nested rules and policies.
func (g *RateGlobal) Validate() error {
	if !g.Enabled.Active() {
		return nil
	}
	if g.TTL < 0 {
		return def.ErrProxyRouteNegativeTTL
	}
	if g.MaxEntries < 0 {
		return def.ErrProxyRouteNegativeMaxEntries
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

func (r RateRoute) IsZero() bool {
	return r.Enabled.IsZero() &&
		!r.IgnoreGlobal &&
		r.UsePolicy == "" &&
		r.Rule.IsZero()
}

type RateRoute struct {
	Enabled      expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	IgnoreGlobal bool          `hcl:"ignore_global,attr" json:"ignore_global"`
	UsePolicy    string        `hcl:"use_policy,attr" json:"use_policy"`
	Rule         RateRule      `hcl:"rule,block" json:"rule"`
}

// Validate checks the ad-hoc rule when route-level rate limiting is enabled.
func (r *RateRoute) Validate() error {
	if !r.Enabled.Active() {
		return nil
	}
	if err := r.Rule.Validate(); err != nil {
		return errors.Newf("ad-hoc rule: %w", err)
	}
	return nil
}

type RatePolicy struct {
	Name     string          `hcl:"name,label" json:"name"`
	Requests int             `hcl:"requests,attr" json:"requests"`
	Window   expect.Duration `hcl:"window,attr" json:"window"`
	Burst    int             `hcl:"burst,attr" json:"burst"`
	Key      string          `hcl:"key,attr" json:"key"`
}

// Validate checks requests, window, and burst values for a named policy.
func (p *RatePolicy) Validate() error {
	if p.Name == "" {
		return errors.New("policy name is required")
	}
	rr := RateRule{
		Requests: p.Requests,
		Window:   p.Window,
		Burst:    p.Burst,
	}
	return rr.Validate()
}

type RateRule struct {
	Enabled  expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Name     string          `hcl:"name,label" json:"name"`
	Prefixes []string        `hcl:"prefixes,attr" json:"prefixes"`
	Methods  []string        `hcl:"methods,attr" json:"methods"`
	Requests int             `hcl:"requests,attr" json:"requests"`
	Window   expect.Duration `hcl:"window,attr" json:"window"`
	Burst    int             `hcl:"burst,attr" json:"burst"`
	Key      string          `hcl:"key,attr" json:"key"`
}

// Validate checks requests, window, burst, and key format for a rate rule.
// It does not set defaults — all defaults are applied by woos.defaultRateLimit.
func (r *RateRule) Validate() error {
	if !r.Enabled.Active() {
		return nil
	}
	if r.Requests <= 0 {
		return def.ErrRateLimitNegativeRequests
	}
	if r.Window <= 0 {
		return def.ErrRateLimitInvalidWindow
	}
	if r.Burst < 0 {
		return def.ErrRateLimitNegativeBurst
	}
	if r.Burst < r.Requests {
		return def.ErrRateLimitBurstTooSmall
	}
	if len(r.Key) > 0 {
		for _, ch := range r.Key {
			if ch == ' ' {
				return def.ErrRateLimitInvalidKeyHeader
			}
		}
	}
	return nil
}

func (r RateRule) IsZero() bool {
	return r.Enabled.IsZero() &&
		r.Name == "" &&
		len(r.Prefixes) == 0 &&
		len(r.Methods) == 0 &&
		r.Requests == 0 &&
		r.Window == 0 &&
		r.Burst == 0 &&
		r.Key == ""
}
