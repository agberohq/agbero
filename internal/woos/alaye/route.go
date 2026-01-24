// internal/woos/route.go
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
	LBStrategy    string   `hcl:"lb_strategy,optional"`

	// web hosting
	Web      Web      `hcl:"web,block,optional"`
	Backends []string `hcl:"backends,optional"`

	// High-Availability Configs
	HealthCheck    *HealthCheck    `hcl:"health_check,block"`
	CircuitBreaker *CircuitBreaker `hcl:"circuit_breaker,block"`
	Timeouts       *TimeoutRoute   `hcl:"timeouts,block"`

	// Middleware Configs
	BasicAuth   *BasicAuth   `hcl:"basic_auth,block"`
	ForwardAuth *ForwardAuth `hcl:"forward_auth,block"`
	Headers     *Headers     `hcl:"headers,block"`

	CompressionConfig Compression `hcl:"compression,block"`
}

func (r *Route) Key() string {
	var sb strings.Builder
	sb.Grow(256)

	sb.WriteString("p=")
	sb.WriteString(r.Path)
	sb.WriteString("|s=")
	sb.WriteString(strings.ToLower(strings.TrimSpace(r.LBStrategy)))

	sb.WriteString("|b=")
	for i, b := range r.Backends {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strings.TrimSpace(b))
	}

	sb.WriteString("|sp=")
	for i, p := range r.StripPrefixes {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(p)
	}

	// High Availability
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

	// Middlewares
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

	// Web route (presence must be semantic, not String())
	if r.Web.Root.IsSet() || r.Web.Index != "" {
		sb.WriteString("|w=")
		sb.WriteString(r.Web.Root.String())
		if r.Web.Index != "" {
			sb.WriteString("|i=")
			sb.WriteString(r.Web.Index)
		}
	}

	return sb.String()
}

func (r *Route) Validate() error {
	if r.Path == "" {
		return errors.New("path is required")
	}
	if !strings.HasPrefix(r.Path, "/") {
		return errors.Newf("path %q must start with '/'", r.Path)
	}

	hasBackends := len(r.Backends) > 0

	// Presence must use semantic fields (never String()).
	// Root.IsSet() is the main signal; Index is a secondary signal.
	hasWeb := r.Web.Root.IsSet() || r.Web.Index != ""

	if !hasBackends && !hasWeb {
		return errors.New("route must have either 'backends' or 'web' block")
	}
	if hasBackends && hasWeb {
		return errors.New("route cannot have both 'backends' and 'web' block")
	}

	if hasBackends {
		return r.validateProxyRoute()
	}
	return r.validateWebRoute()
}

func (r *Route) validateWebRoute() error {
	// Web root must be explicitly set
	if !r.Web.Root.IsSet() {
		return errors.New("web root cannot be empty")
	}

	if err := r.Web.Validate(); err != nil {
		return errors.Newf("web: %w", err)
	}

	if len(r.StripPrefixes) > 0 {
		return errors.New("web routes cannot have strip_prefixes")
	}

	if r.LBStrategy != "" && r.LBStrategy != StrategyRoundRobin {
		return errors.New("web routes only support default load balancing")
	}

	if r.HealthCheck != nil {
		return errors.New("web routes cannot have health_check")
	}
	if r.CircuitBreaker != nil {
		return errors.New("web routes cannot have circuit_breaker")
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
	// Backends validation
	if len(r.Backends) == 0 {
		return errors.New("backends cannot be empty for proxy route")
	}
	for i, backend := range r.Backends {
		backend = strings.TrimSpace(backend)
		if backend == "" {
			return errors.Newf("backends[%d]: cannot be empty", i)
		}
		// Basic URL validation
		if !strings.HasPrefix(backend, "http://") && !strings.HasPrefix(backend, "https://") {
			return errors.Newf("backends[%d]: %q must start with http:// or https://", i, backend)
		}
		r.Backends[i] = backend // Normalize
	}

	// Strip prefixes validation (if provided)
	for i, prefix := range r.StripPrefixes {
		if prefix == "" {
			return errors.Newf("strip_prefixes[%d]: cannot be empty", i)
		}
		if !strings.HasPrefix(prefix, "/") {
			return errors.Newf("strip_prefixes[%d]: %q must start with '/'", i, prefix)
		}
	}

	// Load balancing strategy validation (if provided)
	if r.LBStrategy != "" {
		r.LBStrategy = strings.ToLower(r.LBStrategy)
		switch r.LBStrategy {
		case StrategyRoundRobin, StrategyLeastConn, StrategyRandom:
			// Valid
		default:
			return errors.Newf("lb_strategy %q must be one of: %s, %s, %s",
				r.LBStrategy, StrategyRoundRobin, StrategyLeastConn, StrategyRandom)
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
