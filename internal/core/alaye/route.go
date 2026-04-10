package alaye

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/cespare/xxhash/v2"
	"github.com/olekukonko/errors"
)

type Route struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Path    string        `hcl:"path,label" json:"path"`

	Env map[string]expect.Value `hcl:"env,attr" json:"env"`

	StripPrefixes []string  `hcl:"strip_prefixes,attr" json:"strip_prefixes"`
	AllowedIPs    []string  `hcl:"allowed_ips,attr" json:"allowed_ips"`
	Rewrites      []Rewrite `hcl:"rewrite,block" json:"rewrites"`

	Web        Web        `hcl:"web,block,omitempty" json:"web"`
	Backends   Backend    `hcl:"backend,block,omitempty" json:"backends"`
	Serverless Serverless `hcl:"serverless,block,omitempty" json:"serverless"`

	HealthCheck    HealthCheck    `hcl:"health_check,block,omitempty" json:"health_check"`
	CircuitBreaker CircuitBreaker `hcl:"circuit_breaker,block,omitempty" json:"circuit_breaker"`
	Timeouts       TimeoutRoute   `hcl:"timeouts,block,omitempty" json:"timeouts"`

	BasicAuth   BasicAuth   `hcl:"basic_auth,block,omitempty" json:"basic_auth"`
	ForwardAuth ForwardAuth `hcl:"forward_auth,block,omitempty" json:"forward_auth"`
	JWTAuth     JWTAuth     `hcl:"jwt_auth,block,omitempty" json:"jwt_auth"`
	OAuth       OAuth       `hcl:"o_auth,block,omitempty" json:"oauth"`

	Headers     Headers       `hcl:"headers,block,omitempty" json:"headers"`
	CORS        CORS          `hcl:"cors,block,omitempty" json:"cors"`
	Cache       Cache         `hcl:"cache,block,omitempty" json:"cache"`
	ErrorPages  ErrorPages    `hcl:"error_pages,block,omitempty" json:"error_pages"`
	Wasm        Wasm          `hcl:"wasm,block,omitempty" json:"wasm"`
	RateLimit   RouteRate     `hcl:"rate_limit,block,omitempty" json:"rate_limit"`
	Firewall    FirewallRoute `hcl:"firewall,block,omitempty" json:"firewall"`
	Compression Compression   `hcl:"compression,block,omitempty" json:"compression"`
	Fallback    Fallback      `hcl:"fallback,block,omitempty" json:"fallback"`
}

func (r *Route) Validate() error {
	if r.Path == "" {
		return ErrRoutePathRequired
	}
	if !strings.HasPrefix(r.Path, Slash) {
		return errors.Newf("%w: path %q must start with '/'", ErrRouteInvalidPrefix, r.Path)
	}

	isWeb := r.Web.Root.IsSet() || (r.Web.Git.Enabled.Active() && !r.Serverless.Enabled.Active())
	isBackend := len(r.Backends.Servers) > 0
	isServerless := r.Serverless.Enabled.Active()

	engines := 0
	if isWeb {
		engines++
	}
	if isBackend {
		engines++
	}
	if isServerless {
		engines++
	}

	if engines > 1 {
		return fmt.Errorf("route %q: engine conflict. Choose one: web, backend, or serverless", r.Path)
	}

	if engines == 0 {
		return ErrRouteNoBackendOrWeb
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
	if err := r.Fallback.Validate(); err != nil {
		return errors.Newf("fallback: %w", err)
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

	if isServerless {
		return r.Serverless.Validate()
	}

	if isBackend {
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
	if err := r.Compression.Validate(); err != nil {
		return errors.Newf("compression: %w", err)
	}
	return nil
}

func (r *Route) validateWebRoute() error {
	if !r.Web.Root.IsSet() && !r.Web.Git.Enabled.Active() {
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

	if r.Compression.Enabled.Active() {
		w.WriteString(r.Compression.Type)
		w.WriteString(fmt.Sprint(r.Compression.Level))
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
		if r.Web.Listing.Active() {
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

	if r.Serverless.Enabled.Active() {
		w.WriteString("sl")
		for _, rp := range r.Serverless.Replay {
			w.WriteString(rp.Name)
			w.WriteString(rp.URL)
			for _, m := range rp.Methods {
				w.WriteString(m)
			}
			for k, v := range rp.Headers {
				w.WriteString(k)
				w.WriteString(v)
			}
			for _, d := range rp.AllowedDomains {
				w.WriteString(d)
			}
			w.WriteString(rp.Timeout.String())
			w.WriteString(rp.RefererMode)
			w.WriteString(fmt.Sprint(rp.StripHeaders))
			if rp.Cache.Enabled.Active() {
				w.WriteString(rp.Cache.Driver)
				w.WriteString(rp.Cache.TTL.String())
			}
		}
		for _, wk := range r.Serverless.Workers {
			w.WriteString(wk.Name)
			for _, c := range wk.Command {
				w.WriteString(c)
			}
			w.WriteString(wk.Schedule)
			w.WriteString(wk.Restart)
			w.WriteString(fmt.Sprint(wk.Background))
			w.WriteString(fmt.Sprint(wk.RunOnce))
		}
	}

	return fmt.Sprintf("%x", w.Sum64())
}

func (r *Route) BackendKey(domain, backendAddr string) BackendKey {
	return r.backendKey("http", domain, backendAddr)
}

func (r *Route) ReplayBackendKey(domain, replayName string) BackendKey {
	return r.backendKey("serverless", domain, replayName)
}

func (r *Route) WorkerBackendKey(domain, workerName string) BackendKey {
	return r.backendKey("worker", domain, workerName)
}

func (r *Route) backendKey(protocol, domain, addr string) BackendKey {
	if domain == "" {
		domain = "*"
	}
	path := r.Path
	if path == "" {
		path = "/"
	}
	return BackendKey{
		Protocol: protocol,
		Domain:   domain,
		Path:     path,
		Addr:     addr,
	}
}
