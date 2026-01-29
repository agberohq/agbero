package alaye

import (
	"fmt"
	"strings"

	"github.com/olekukonko/errors"
)

type Route struct {
	// Routing Core
	Path string `hcl:"path,label"`

	StripPrefixes []string `hcl:"strip_prefixes,optional"`

	// web hosting (Value type)
	Web Web `hcl:"web,block"`

	// CHANGED: Structured Backends
	Backends Backend `hcl:"backend,block"`

	// High-Availability Configs
	HealthCheck    *HealthCheck    `hcl:"health_check,block"`
	CircuitBreaker *CircuitBreaker `hcl:"circuit_breaker,block"`
	Timeouts       *TimeoutRoute   `hcl:"timeouts,block"`

	// Middleware Configs
	JWTAuth     *JWTAuth     `hcl:"jwt_auth,block"`
	BasicAuth   *BasicAuth   `hcl:"basic_auth,block"`
	ForwardAuth *ForwardAuth `hcl:"forward_auth,block"`
	Headers     *Headers     `hcl:"headers,block"`
	Wasm        *Wasm        `hcl:"wasm,block"`
	RateLimit   *Rate        `hcl:"rate_limit,block"`

	CompressionConfig Compression `hcl:"compression,block"`
}

func (r *Route) Key() string {
	var sb strings.Builder
	sb.Grow(256)

	sb.WriteString("p=")
	sb.WriteString(r.Path)
	sb.WriteString("|s=")
	sb.WriteString(strings.ToLower(strings.TrimSpace(r.Backends.LBStrategy)))

	sb.WriteString("|b=")
	for i, b := range r.Backends.Servers {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(b.String())
		sb.WriteString(fmt.Sprintf("(w:%d)", b.Weight))
	}

	sb.WriteString("|sp=")
	for i, p := range r.StripPrefixes {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(p)
	}

	if r.HealthCheck != nil {
		sb.WriteString("|hc=")
		sb.WriteString(r.HealthCheck.Path)
		sb.WriteString(fmt.Sprint(r.HealthCheck.Interval))
		sb.WriteString(fmt.Sprint(r.HealthCheck.Timeout))
		sb.WriteString(fmt.Sprint(r.HealthCheck.Threshold))
	}

	if r.CircuitBreaker != nil {
		sb.WriteString("|cb=")
		sb.WriteString(fmt.Sprint(r.CircuitBreaker.Threshold))
		sb.WriteString(fmt.Sprint(r.CircuitBreaker.Duration))
	}

	if r.Timeouts != nil {
		sb.WriteString("|to=")
		sb.WriteString(fmt.Sprint(r.Timeouts.Request))
	}

	if r.CompressionConfig.Compression {
		sb.WriteString("|comp=")
		sb.WriteString(r.CompressionConfig.Type)
		sb.WriteString(fmt.Sprint(r.CompressionConfig.Level))
	}

	if r.Headers != nil {
		sb.WriteString("|hd=1")
	}

	if r.BasicAuth != nil {
		sb.WriteString("|ba=")
		sb.WriteByte(byte(len(r.BasicAuth.Users)))
	}

	if r.ForwardAuth != nil {
		sb.WriteString("|fa=")
		sb.WriteString(r.ForwardAuth.URL)
	}

	// Web route check (Root.IsSet is the signal)
	if r.Web.Root.IsSet() || r.Web.Index != "" {
		sb.WriteString("|w=")
		sb.WriteString(r.Web.Root.String())
		if r.Web.Index != "" {
			sb.WriteString("|i=")
			sb.WriteString(r.Web.Index)
		}
	}

	if r.RateLimit != nil {
		sb.WriteString("|rl=")
		if r.RateLimit.Enabled {
			sb.WriteString("on")
			// Iterate through rules to ensure config changes trigger reloads
			for _, rule := range r.RateLimit.Rules {
				sb.WriteString(";")
				sb.WriteString(rule.Name)
				sb.WriteString(":")
				sb.WriteString(fmt.Sprint(rule.Requests))
				sb.WriteString("/")
				sb.WriteString(fmt.Sprint(rule.Window))
				sb.WriteString("/")
				sb.WriteString(fmt.Sprint(rule.Burst))
				sb.WriteString("@")
				sb.WriteString(rule.Key)
				// Include length of matchers to detect structural changes
				sb.WriteString("#p")
				sb.WriteString(fmt.Sprint(len(rule.Prefixes)))
				sb.WriteString("#m")
				sb.WriteString(fmt.Sprint(len(rule.Methods)))
			}
		} else {
			sb.WriteString("off")
		}
	}

	return sb.String()
}

func (r *Route) Validate() error {
	if r.Path == "" {
		return ErrRoutePathRequired
	}
	if !strings.HasPrefix(r.Path, "/") {
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

	if len(r.StripPrefixes) > 0 {
		return ErrWebRouteStripPrefixes
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

	if r.CompressionConfig.Compression {
		if err := r.CompressionConfig.Validate(); err != nil {
			return errors.Newf("compression: %w", err)
		}
	}

	return nil
}

func (r *Route) validateProxyRoute() error {
	// Backend validation
	if len(r.Backends.Servers) == 0 {
		return ErrProxyRouteNoBackends
	}

	for i, b := range r.Backends.Servers {
		if err := b.Validate(); err != nil {
			return errors.Newf("backend[%d]: %w", i, err)
		}
	}

	// Strip prefixes validation (if provided)
	for i, prefix := range r.StripPrefixes {
		if prefix == "" {
			return errors.Newf("%w [%d]: cannot be empty", ErrProxyRouteInvalidStrip, i)
		}
		if !strings.HasPrefix(prefix, "/") {
			return errors.Newf("%w [%d]: %q must start with '/'", ErrProxyRouteInvalidStrip, i, prefix)
		}
	}

	// Load balancing strategy validation (if provided)
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

	// Health check validation (if provided)
	if r.HealthCheck != nil {
		if err := r.HealthCheck.Validate(); err != nil {
			return errors.Newf("health_check: %w", err)
		}
	}

	// Circuit breaker validation (if provided)
	if r.CircuitBreaker != nil {
		if err := r.CircuitBreaker.Validate(); err != nil {
			return errors.Newf("circuit_breaker: %w", err)
		}
	}

	// Timeouts validation (if provided)
	if r.Timeouts != nil {
		if err := r.Timeouts.Validate(); err != nil {
			return errors.Newf("timeouts: %w", err)
		}
	}

	// Basic auth validation (if provided)
	if r.BasicAuth != nil {
		if err := r.BasicAuth.Validate(); err != nil {
			return errors.Newf("basic_auth: %w", err)
		}
	}

	// Forward auth validation (if provided)
	if r.ForwardAuth != nil {
		if err := r.ForwardAuth.Validate(); err != nil {
			return errors.Newf("forward_auth: %w", err)
		}
	}

	// Headers validation (if provided)
	if r.Headers != nil {
		if err := r.Headers.Validate(); err != nil {
			return errors.Newf("headers: %w", err)
		}
	}

	// Compression validation (if provided)
	if r.CompressionConfig.Compression {
		if err := r.CompressionConfig.Validate(); err != nil {
			return errors.Newf("compression: %w", err)
		}
	}

	return nil
}
