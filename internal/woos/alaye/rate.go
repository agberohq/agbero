package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Rate struct {
	Enabled    bool          `hcl:"enabled,optional"`
	TTL        time.Duration `hcl:"ttl,optional"`
	MaxEntries int64         `hcl:"max_entries,optional"`
	Rules      []RateRule    `hcl:"rule,block"`
}

type RateRule struct {
	Name     string   `hcl:"name,label"`
	Prefixes []string `hcl:"prefixes,optional"`
	Methods  []string `hcl:"methods,optional"`

	Requests int           `hcl:"requests"`
	Window   time.Duration `hcl:"window"`
	Burst    int           `hcl:"burst,optional"`

	// "ip", "header:X-API-Key", "cookie:SessionID"
	Key string `hcl:"key,optional"`
}

func (r *Rate) Validate() error {
	if !r.Enabled {
		return nil
	}

	if r.TTL < 0 {
		return errors.New("ttl cannot be negative")
	}

	if r.MaxEntries < 0 {
		return errors.New("max_entries cannot be negative")
	}

	for i, rule := range r.Rules {
		if err := rule.Validate(); err != nil {
			return errors.Newf("rule[%d] %q: %w", i, rule.Name, err)
		}
	}

	return nil
}

func (r *RateRule) Validate() error {
	if r.Requests <= 0 {
		return errors.New("requests must be positive")
	}

	if r.Window <= 0 {
		return errors.New("window must be positive")
	}

	if r.Burst < 0 {
		return errors.New("burst cannot be negative")
	}
	if r.Burst == 0 {
		r.Burst = r.Requests
	}
	if r.Burst < r.Requests {
		return errors.New("burst cannot be less than requests")
	}

	for _, p := range r.Prefixes {
		if !strings.HasPrefix(p, "/") {
			return errors.Newf("prefix %q must start with '/'", p)
		}
	}

	for i, m := range r.Methods {
		r.Methods[i] = strings.ToUpper(m)
	}

	return nil
}
