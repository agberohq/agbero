package alaye

import (
	"fmt"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/olekukonko/errors"
)

type Route struct {
	Path string `hcl:"path,label" json:"path"`

	StripPrefixes []string `hcl:"strip_prefixes,optional" json:"strip_prefixes"`
	AllowedIPs    []string `hcl:"allowed_ips,optional" json:"allowed_ips"`

	Web Web `hcl:"web,block" json:"web"`

	Backends Backend `hcl:"backend,block" json:"backends"`

	HealthCheck    *HealthCheck    `hcl:"health_check,block" json:"health_check"`
	CircuitBreaker *CircuitBreaker `hcl:"circuit_breaker,block" json:"circuit_breaker"`
	Timeouts       *TimeoutRoute   `hcl:"timeouts,block" json:"timeouts"`

	BasicAuth   *BasicAuth   `hcl:"basic_auth,block" json:"basic_auth"`
	ForwardAuth *ForwardAuth `hcl:"forward_auth,block" json:"forward_auth"`
	JWTAuth     *JWTAuth     `hcl:"jwt_auth,block" json:"jwt_auth"`
	OAuth       *OAuth       `hcl:"o_auth,block" json:"oauth"`

	Headers   *Headers   `hcl:"headers,block" json:"headers"`
	Wasm      *Wasm      `hcl:"wasm,block" json:"wasm"`
	RateLimit *RouteRate `hcl:"rate_limit,block" json:"rate_limit"`

	CompressionConfig Compression `hcl:"compression,block" json:"compression_config"`
}

func (r *Route) Key() string {
	w := xxhash.New()

	w.WriteString(r.Path)
	w.WriteString(strings.ToLower(strings.TrimSpace(r.Backends.LBStrategy)))

	for _, b := range r.Backends.Servers {
		w.WriteString(b.Address)
		w.WriteString(fmt.Sprint(b.Weight))
	}

	for _, p := range r.StripPrefixes {
		w.WriteString(p)
	}

	for _, ip := range r.AllowedIPs {
		w.WriteString(ip)
	}

	if r.HealthCheck != nil {
		w.WriteString(r.HealthCheck.Path)
		w.WriteString(fmt.Sprint(r.HealthCheck.Interval))
		w.WriteString(fmt.Sprint(r.HealthCheck.Timeout))
		w.WriteString(fmt.Sprint(r.HealthCheck.Threshold))
	}

	if r.CircuitBreaker != nil {
		w.WriteString(fmt.Sprint(r.CircuitBreaker.Threshold))
		w.WriteString(fmt.Sprint(r.CircuitBreaker.Duration))
	}

	if r.Timeouts != nil {
		w.WriteString(fmt.Sprint(r.Timeouts.Request))
	}

	if r.CompressionConfig.Enabled {
		w.WriteString(r.CompressionConfig.Type)
		w.WriteString(fmt.Sprint(r.CompressionConfig.Level))
	}

	if r.Headers != nil {
		w.WriteString("hd")
	}

	if r.BasicAuth != nil {
		for _, u := range r.BasicAuth.Users {
			w.WriteString(u)
		}
	}

	if r.ForwardAuth != nil {
		w.WriteString(r.ForwardAuth.URL)
	}

	if r.JWTAuth != nil {
		w.WriteString(r.JWTAuth.Secret.String())
	}

	if r.OAuth != nil {
		w.WriteString(r.OAuth.Provider)
		w.WriteString(r.OAuth.ClientID)
	}

	if r.Web.Root.IsSet() {
		w.WriteString(r.Web.Root.String())
		w.WriteString(r.Web.Index)
		if r.Web.Listing {
			w.WriteString("ls")
		}
		if r.Web.PHP.Enabled {
			w.WriteString("php")
			w.WriteString(r.Web.PHP.Address)
		}
	}

	if r.Wasm != nil {
		w.WriteString(r.Wasm.Module)
		for k, v := range r.Wasm.Config {
			w.WriteString(k)
			w.WriteString(v)
		}
	}

	if r.RateLimit != nil && r.RateLimit.Enabled {
		w.WriteString("rl_on")
		if r.RateLimit.IgnoreGlobal {
			w.WriteString("ig")
		}
		w.WriteString(r.RateLimit.UsePolicy)
		if rule := r.RateLimit.Rule; rule != nil {
			w.WriteString(rule.Name)
			w.WriteString(fmt.Sprint(rule.Requests))
			w.WriteString(fmt.Sprint(rule.Window))
			w.WriteString(fmt.Sprint(rule.Burst))
			w.WriteString(rule.Key)
			for _, p := range rule.Prefixes {
				w.WriteString(p)
			}
			for _, m := range rule.Methods {
				w.WriteString(m)
			}
		}
	}

	return fmt.Sprintf("%x", w.Sum64())
}

func (r *Route) Validate() error {
	if r.Path == "" {
		return ErrRoutePathRequired
	}
	if !strings.HasPrefix(r.Path, Slash) {
		return errors.Newf("%w: path %q must start with '/'", ErrRouteInvalidPrefix, r.Path)
	}

	hasBackends := len(r.Backends.Servers) > 0
	hasWeb := r.Web.Root.IsSet()

	if !hasBackends && !hasWeb {
		return ErrRouteNoBackendOrWeb
	}
	if hasBackends && hasWeb {
		return ErrRouteBothBackendAndWeb
	}

	if r.RateLimit != nil {
		if err := r.RateLimit.Validate(); err != nil {
			return errors.Newf("rate_limit: %w", err)
		}
	}

	if hasBackends {
		return r.validateProxyRoute()
	}
	return r.validateWebRoute()
}

func (r *Route) validateWebRoute() error {
	if !r.Web.Root.IsSet() {
		return ErrWebRouteRootRequired
	}

	if err := r.Web.Validate(); err != nil {
		return errors.Newf("web: %w", err)
	}

	if r.Backends.LBStrategy != "" && r.Backends.LBStrategy != StrategyRoundRobin {
		return ErrWebRouteUnsupportedLB
	}

	if r.HealthCheck != nil {
		return ErrWebRouteHealthCheck
	}
	if r.CircuitBreaker != nil {
		return ErrWebRouteCircuitBreaker
	}

	if r.Timeouts != nil {
		if err := r.Timeouts.Validate(); err != nil {
			return errors.Newf("timeouts: %w", err)
		}
	}

	if r.BasicAuth != nil {
		if err := r.BasicAuth.Validate(); err != nil {
			return errors.Newf("basic_auth: %w", err)
		}
	}

	if r.ForwardAuth != nil {
		if err := r.ForwardAuth.Validate(); err != nil {
			return errors.Newf("forward_auth: %w", err)
		}
	}

	if r.Headers != nil {
		if err := r.Headers.Validate(); err != nil {
			return errors.Newf("headers: %w", err)
		}
	}

	if r.CompressionConfig.Enabled {
		if err := r.CompressionConfig.Validate(); err != nil {
			return errors.Newf("compression: %w", err)
		}
	}

	return nil
}

func (r *Route) validateProxyRoute() error {
	if len(r.Backends.Servers) == 0 {
		return ErrProxyRouteNoBackends
	}

	for i, b := range r.Backends.Servers {
		if err := b.Validate(); err != nil {
			return errors.Newf("backend[%d]: %w", i, err)
		}
	}

	for i, prefix := range r.StripPrefixes {
		if prefix == "" {
			return errors.Newf("%w [%d]: cannot be empty", ErrProxyRouteInvalidStrip, i)
		}
		if !strings.HasPrefix(prefix, Slash) {
			return errors.Newf("%w [%d]: %q must start with '/'", ErrProxyRouteInvalidStrip, i, prefix)
		}
	}

	if r.Backends.LBStrategy != "" {
		s := strings.ToLower(strings.TrimSpace(r.Backends.LBStrategy))

		switch s {
		case StrategyRoundRobin,
			StrategyLeastConn,
			StrategyRandom,
			StrategyIPHash,
			StrategyURLHash,
			StrategyWeightedLeastConn:
		default:
			return errors.Newf(
				`%w %q must be one of: %s, %s, %s, %s, %s`,
				ErrProxyRouteInvalidLBStrategy,
				s,
				StrategyRoundRobin,
				StrategyLeastConn,
				StrategyRandom,
				StrategyIPHash,
				StrategyURLHash,
			)
		}
	}

	if r.HealthCheck != nil {
		if err := r.HealthCheck.Validate(); err != nil {
			return errors.Newf("health_check: %w", err)
		}
	}

	if r.CircuitBreaker != nil {
		if err := r.CircuitBreaker.Validate(); err != nil {
			return errors.Newf("circuit_breaker: %w", err)
		}
	}

	if r.Timeouts != nil {
		if err := r.Timeouts.Validate(); err != nil {
			return errors.Newf("timeouts: %w", err)
		}
	}

	if r.BasicAuth != nil {
		if err := r.BasicAuth.Validate(); err != nil {
			return errors.Newf("basic_auth: %w", err)
		}
	}

	if r.ForwardAuth != nil {
		if err := r.ForwardAuth.Validate(); err != nil {
			return errors.Newf("forward_auth: %w", err)
		}
	}

	if r.Headers != nil {
		if err := r.Headers.Validate(); err != nil {
			return errors.Newf("headers: %w", err)
		}
	}

	if r.CompressionConfig.Enabled {
		if err := r.CompressionConfig.Validate(); err != nil {
			return errors.Newf("compression: %w", err)
		}
	}

	return nil
}
