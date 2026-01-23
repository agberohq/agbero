package woos

import "strings"

type Route struct {
	// Routing Core
	Path          string   `hcl:"path,label"`
	Backends      []string `hcl:"backends"`
	StripPrefixes []string `hcl:"strip_prefixes,optional"`
	LBStrategy    string   `hcl:"lb_strategy,optional"`

	// High-Availability Configs
	HealthCheck    *HealthCheckConfig    `hcl:"health_check,block"`
	CircuitBreaker *CircuitBreakerConfig `hcl:"circuit_breaker,block"`
	Timeouts       *RouteTimeouts        `hcl:"timeouts,block"`

	// Middleware Configs
	BasicAuth   *BasicAuthConfig   `hcl:"basic_auth,block"`
	ForwardAuth *ForwardAuthConfig `hcl:"forward_auth,block"`
	Headers     *HeadersConfig     `hcl:"headers,block"`
	Compression bool               `hcl:"compression,optional"`
}

func (route *Route) Key() string {
	var sb strings.Builder
	sb.Grow(256)

	sb.WriteString("p=")
	sb.WriteString(route.Path)
	sb.WriteString("|s=")
	sb.WriteString(strings.ToLower(strings.TrimSpace(route.LBStrategy)))

	sb.WriteString("|b=")
	for i, b := range route.Backends {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strings.TrimSpace(b))
	}

	sb.WriteString("|sp=")
	for i, p := range route.StripPrefixes {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(p)
	}

	// High Availability
	if route.HealthCheck != nil {
		sb.WriteString("|hc=")
		sb.WriteString(route.HealthCheck.Path)
		sb.WriteString(route.HealthCheck.Interval.String())
		sb.WriteString(route.HealthCheck.Timeout.String())
	}

	if route.CircuitBreaker != nil {
		sb.WriteString("|cb=")
		sb.WriteByte(byte(route.CircuitBreaker.Threshold))
	}

	if route.Timeouts != nil {
		sb.WriteString("|to=")
		sb.WriteString(route.Timeouts.Request.String())
	}

	// Middlewares
	if route.Compression {
		sb.WriteString("|gz=1")
	}

	if route.Headers != nil {
		sb.WriteString("|hd=1")
		// Optimization: We assume if the pointer is non-nil, headers are active.
		// For perfect cache busting on content change, we would need to hash the map keys/values.
		// Given the frequency of config changes, this simple check is usually sufficient
		// unless you modify header values in-place without changing other config.
	}

	if route.BasicAuth != nil {
		sb.WriteString("|ba=")
		sb.WriteByte(byte(len(route.BasicAuth.Users)))
	}

	if route.ForwardAuth != nil {
		sb.WriteString("|fa=")
		sb.WriteString(route.ForwardAuth.URL)
	}

	return sb.String()
}
