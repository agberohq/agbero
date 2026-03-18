package alaye

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/olekukonko/errors"
)

type Route struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`
	Path    string  `hcl:"path,label" json:"path"`

	StripPrefixes []string  `hcl:"strip_prefixes,attr" json:"strip_prefixes"`
	AllowedIPs    []string  `hcl:"allowed_ips,attr" json:"allowed_ips"`
	Rewrites      []Rewrite `hcl:"rewrite,block" json:"rewrites"`

	Web      Web     `hcl:"web,block" json:"web"`
	Backends Backend `hcl:"backend,block" json:"backends"`

	HealthCheck    HealthCheck    `hcl:"health_check,block" json:"health_check"`
	CircuitBreaker CircuitBreaker `hcl:"circuit_breaker,block" json:"circuit_breaker"`
	Timeouts       TimeoutRoute   `hcl:"timeouts,block" json:"timeouts"`

	BasicAuth   BasicAuth   `hcl:"basic_auth,block" json:"basic_auth"`
	ForwardAuth ForwardAuth `hcl:"forward_auth,block" json:"forward_auth"`
	JWTAuth     JWTAuth     `hcl:"jwt_auth,block" json:"jwt_auth"`
	OAuth       OAuth       `hcl:"o_auth,block" json:"oauth"`

	Headers           Headers       `hcl:"headers,block" json:"headers"`
	CORS              CORS          `hcl:"cors,block" json:"cors"`
	Cache             Cache         `hcl:"cache,block" json:"cache"`
	ErrorPages        ErrorPages    `hcl:"error_pages,block" json:"error_pages"`
	Wasm              Wasm          `hcl:"wasm,block" json:"wasm"`
	RateLimit         RouteRate     `hcl:"rate_limit,block" json:"rate_limit"`
	Firewall          FirewallRoute `hcl:"firewall,block" json:"firewall"`
	CompressionConfig Compression   `hcl:"compression,block" json:"compression_config"`
	Fallback          Fallback      `hcl:"fallback,block" json:"fallback"`
}

// Validate checks the route path, backend/web exclusivity, and all nested blocks.
// It does not set defaults — call woos.DefaultRoute before Validate.
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
	if err := r.CORS.Validate(); err != nil {
		return errors.Newf("cors: %w", err)
	}
	if err := r.Cache.Validate(); err != nil {
		return errors.Newf("cache: %w", err)
	}
	if err := r.ErrorPages.Validate(); err != nil {
		return errors.Newf("route error_pages: %w", err)
	}
	for i, rw := range r.Rewrites {
		if err := rw.Validate(); err != nil {
			return errors.Newf("rewrite[%d]: %w", i, err)
		}
	}
	if r.Firewall.Status.Active() {
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

	if err := r.Fallback.Validate(); err != nil {
		return errors.Newf("fallback: %w", err)
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
	return r.validatePlugins()
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
	return r.validatePlugins()
}

// Key produces a stable hash of the route's configuration for change detection.
func (r *Route) Key() string {
	w := xxhash.New()

	w.WriteString(r.Path)

	if r.Backends.Enabled.Active() {
		w.WriteString(strings.ToLower(strings.TrimSpace(r.Backends.Strategy)))
		for _, b := range r.Backends.Servers {
			w.WriteString(b.Address.String())
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
		for _, idx := range r.Web.Index {
			w.WriteString(idx)
		}
		if r.Web.Listing {
			w.WriteString("ls")
		}
		if r.Web.PHP.Enabled.Active() {
			w.WriteString("php")
			w.WriteString(r.Web.PHP.Address)
		}
	}

	if r.Wasm.Enabled.Active() {
		w.WriteString(r.Wasm.Module)
		keys := make([]string, 0, len(r.Wasm.Config))
		for k := range r.Wasm.Config {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.WriteString(k)
			w.WriteString(r.Wasm.Config[k])
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

	if r.CORS.Enabled.Active() {
		w.WriteString("cors")
		for _, o := range r.CORS.AllowedOrigins {
			w.WriteString(o)
		}
	}

	for _, rw := range r.Rewrites {
		w.WriteString(rw.Pattern)
		w.WriteString(rw.Target)
	}

	for _, sp := range r.StripPrefixes {
		w.WriteString(sp)
	}

	if r.Cache.Enabled.Active() {
		w.WriteString("cache")
		w.WriteString(r.Cache.Driver)
		w.WriteString(r.Cache.TTL.String())
	}

	return fmt.Sprintf("%x", w.Sum64())
}

// BackendKey provides a deterministic identifier for routing observability.
func (r *Route) BackendKey(domain, backendAddr string) BackendKey {
	if domain == "" {
		domain = "*"
	}
	path := r.Path
	if path == "" {
		path = "/"
	}
	return BackendKey{
		Protocol: "http",
		Domain:   domain,
		Path:     path,
		Addr:     backendAddr,
	}
}
