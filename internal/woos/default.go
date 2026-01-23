package woos

import "time"

// ApplyDefaults sets defaults ONLY when config did not provide values.
func ApplyDefaults(g *GlobalConfig) {
	// Timeouts defaults
	if g.Timeouts.Read == 0 {
		g.Timeouts.Read = DefaultReadTimeout
	}
	if g.Timeouts.Write == 0 {
		g.Timeouts.Write = DefaultWriteTimeout
	}
	if g.Timeouts.Idle == 0 {
		g.Timeouts.Idle = DefaultIdleTimeout
	}
	if g.Timeouts.ReadHeader == 0 {
		g.Timeouts.ReadHeader = DefaultReadHeaderTimeout
	}

	// Rate limit container defaults
	if g.RateLimits.TTL == 0 {
		g.RateLimits.TTL = 30 * time.Minute
	}
	if g.RateLimits.MaxEntries <= 0 {
		g.RateLimits.MaxEntries = 100000
	}
	if len(g.RateLimits.AuthPrefixes) == 0 {
		g.RateLimits.AuthPrefixes = []string{"/login", "/otp", "/auth"}
	}

	// Global policy defaults
	if g.RateLimits.Global.Requests <= 0 {
		g.RateLimits.Global.Requests = 120
	}
	if g.RateLimits.Global.Window == 0 {
		g.RateLimits.Global.Window = 1 * time.Second
	}
	if g.RateLimits.Global.Burst <= 0 {
		g.RateLimits.Global.Burst = 240
	}

	// Auth policy defaults
	if g.RateLimits.Auth.Requests <= 0 {
		g.RateLimits.Auth.Requests = 10
	}
	if g.RateLimits.Auth.Window == 0 {
		g.RateLimits.Auth.Window = 1 * time.Minute
	}
	if g.RateLimits.Auth.Burst <= 0 {
		g.RateLimits.Auth.Burst = 10
	}
}

// ParseRatePolicy parses a RatePolicyConfig into primitives (config must not depend on proxy types).
func ParseRatePolicy(rc RatePolicyConfig) (requests int, window time.Duration, burst int, ok bool) {
	if rc.Requests <= 0 {
		return 0, 0, 0, false
	}
	b := rc.Burst
	if b <= 0 {
		b = rc.Requests
	}
	return rc.Requests, rc.Window, b, true
}
