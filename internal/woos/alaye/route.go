package alaye

import (
	"fmt"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/olekukonko/errors"
)

type Route struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Path    string  `hcl:"path,label" json:"path"`

	StripPrefixes []string `hcl:"strip_prefixes,optional" json:"strip_prefixes"`
	AllowedIPs    []string `hcl:"allowed_ips,optional" json:"allowed_ips"`

	Web      Web     `hcl:"web,block" json:"web,omitempty"`
	Backends Backend `hcl:"backend,block" json:"backends,omitempty"`

	HealthCheck    HealthCheck    `hcl:"health_check,block" json:"health_check,omitempty"`
	CircuitBreaker CircuitBreaker `hcl:"circuit_breaker,block" json:"circuit_breaker,omitempty"`
	Timeouts       TimeoutRoute   `hcl:"timeouts,block" json:"timeouts,omitempty"`

	BasicAuth   BasicAuth   `hcl:"basic_auth,block" json:"basic_auth,omitempty"`
	ForwardAuth ForwardAuth `hcl:"forward_auth,block" json:"forward_auth,omitempty"`
	JWTAuth     JWTAuth     `hcl:"jwt_auth,block" json:"jwt_auth,omitempty"`
	OAuth       OAuth       `hcl:"o_auth,block" json:"oauth,omitempty"`

	Headers           Headers       `hcl:"headers,block" json:"headers,omitempty"`
	Wasm              Wasm          `hcl:"wasm,block" json:"wasm,omitempty"`
	RateLimit         RouteRate     `hcl:"rate_limit,block" json:"rate_limit,omitempty"`
	Firewall          FirewallRoute `hcl:"firewall,block" json:"firewall,omitempty"`
	CompressionConfig Compression   `hcl:"compression,block" json:"compression_config,omitempty"`
}

func (r *Route) Key() string {
	w := xxhash.New()

	w.WriteString(r.Path)

	if r.Backends.Enabled.Active() {
		w.WriteString(strings.ToLower(strings.TrimSpace(r.Backends.Strategy)))
		for _, b := range r.Backends.Servers {
			w.WriteString(b.Address)
			w.WriteString(fmt.Sprint(b.Weight))
		}
	}

	for _, p := range r.StripPrefixes {
		w.WriteString(p)
	}

	for _, ip := range r.AllowedIPs {
		w.WriteString(ip)
	}

	if r.HealthCheck.Enabled.Active() {
		w.WriteString(r.HealthCheck.Path)
		w.WriteString(fmt.Sprint(r.HealthCheck.Interval))
		w.WriteString(fmt.Sprint(r.HealthCheck.Timeout))
		w.WriteString(fmt.Sprint(r.HealthCheck.Threshold))
	}

	if r.CircuitBreaker.Enabled.Active() {
		w.WriteString(fmt.Sprint(r.CircuitBreaker.Threshold))
		w.WriteString(fmt.Sprint(r.CircuitBreaker.Duration))
	}

	if r.Timeouts.Enabled.Active() {
		w.WriteString(fmt.Sprint(r.Timeouts.Request))
	}

	if r.CompressionConfig.Enabled.Active() {
		w.WriteString(r.CompressionConfig.Type)
		w.WriteString(fmt.Sprint(r.CompressionConfig.Level))
	}

	if r.Headers.Enabled.Active() {
		w.WriteString("hd")
	}

	if r.BasicAuth.Enabled.Active() {
		for _, u := range r.BasicAuth.Users {
			w.WriteString(u)
		}
	}

	if r.ForwardAuth.Enabled.Active() {
		w.WriteString(r.ForwardAuth.URL)
	}

	if r.JWTAuth.Enabled.Active() {
		w.WriteString(r.JWTAuth.Secret.String())
	}

	if r.OAuth.Enabled.Active() {
		w.WriteString(r.OAuth.Provider)
		w.WriteString(r.OAuth.ClientID)
	}

	if r.Web.Root.IsSet() {
		w.WriteString(r.Web.Root.String())
		w.WriteString(r.Web.Index)
		if r.Web.Listing {
			w.WriteString("ls")
		}
		if r.Web.PHP.Status.Active() {
			w.WriteString("php")
			w.WriteString(r.Web.PHP.Address)
		}
	}

	if r.Wasm.Enabled.Active() {
		w.WriteString(r.Wasm.Module)
		for k, v := range r.Wasm.Config {
			w.WriteString(k)
			w.WriteString(v)
		}
	}

	if r.RateLimit.Enabled.Active() {
		w.WriteString("rl_on")
		if r.RateLimit.IgnoreGlobal {
			w.WriteString("ig")
		}
		w.WriteString(r.RateLimit.UsePolicy)
		if rule := r.RateLimit.Rule; rule.Enabled.Active() {
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

	if r.Firewall.Status.Active() {
		w.WriteString("fw_on")
		if r.Firewall.IgnoreGlobal {
			w.WriteString("ig")
		}
		for _, rule := range r.Firewall.Rules {
			w.WriteString(rule.Name)
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

	if err := r.RateLimit.Validate(); err != nil {
		return errors.Newf("rate_limit: %w", err)
	}

	if r.Firewall.Status.Active() {
		// Validate ad-hoc rules
		for i, rule := range r.Firewall.Rules {
			if rule.Name == "" {
				rule.Name = "route_adhoc_" + r.Path
			}
			if err := rule.Validate(); err != nil {
				return errors.Newf("route firewall rule[%d]: %w", i, err)
			}
		}
	}

	if hasBackends {
		return r.validateProxyRoute()
	}
	return r.validateWebRoute()
}

func (r *Route) validateAuth() error {
	if err := r.BasicAuth.Validate(); err != nil {
		return errors.Newf("basic_auth: %w", err)
	}
	if err := r.ForwardAuth.Validate(); err != nil {
		return errors.Newf("forward_auth: %w", err)
	}
	if err := r.JWTAuth.Validate(); err != nil {
		return errors.Newf("jwt_auth: %w", err)
	}
	if err := r.OAuth.Validate(); err != nil {
		return errors.Newf("o_auth: %w", err)
	}
	return nil
}

func (r *Route) validatePlugins() error {
	if err := r.Headers.Validate(); err != nil {
		return errors.Newf("headers: %w", err)
	}
	if err := r.Wasm.Validate(); err != nil {
		return errors.Newf("wasm: %w", err)
	}
	if err := r.CompressionConfig.Validate(); err != nil {
		return errors.Newf("compression: %w", err)
	}
	return nil
}

func (r *Route) validateWebRoute() error {
	if !r.Web.Root.IsSet() {
		return ErrWebRouteRootRequired
	}

	if err := r.Web.Validate(); err != nil {
		return errors.Newf("web: %w", err)
	}

	if r.Backends.Strategy != "" && r.Backends.Strategy != StrategyRoundRobin {
		return ErrWebRouteUnsupportedLB
	}

	if r.HealthCheck.Enabled.Active() {
		return ErrWebRouteHealthCheck
	}
	if r.CircuitBreaker.Enabled.Active() {
		return ErrWebRouteCircuitBreaker
	}

	if r.Timeouts.Enabled.Active() {
		if err := r.Timeouts.Validate(); err != nil {
			return errors.Newf("timeouts: %w", err)
		}
	}

	if err := r.validateAuth(); err != nil {
		return err
	}

	if err := r.validatePlugins(); err != nil {
		return err
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

	if r.Backends.Strategy != "" && !ValidateStrategy(r.Backends.Strategy) {
		return errors.Newf("invalid strategy %q", r.Backends.Strategy)
	}

	if err := r.HealthCheck.Validate(); err != nil {
		return errors.Newf("health_check: %w", err)
	}

	if err := r.CircuitBreaker.Validate(); err != nil {
		return errors.Newf("circuit_breaker: %w", err)
	}

	if err := r.Timeouts.Validate(); err != nil {
		return errors.Newf("timeouts: %w", err)
	}

	if err := r.validateAuth(); err != nil {
		return err
	}

	if err := r.validatePlugins(); err != nil {
		return err
	}

	return nil
}
