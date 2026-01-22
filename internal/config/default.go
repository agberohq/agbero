package config

import "time"

// ApplyDefaults sets defaults ONLY when config did not provide values.
func ApplyDefaults(g *GlobalConfig) {
	// Timeouts defaults
	if g.Timeouts.Read == "" {
		g.Timeouts.Read = DefaultReadTimeout.String()
	}
	if g.Timeouts.Write == "" {
		g.Timeouts.Write = DefaultWriteTimeout.String()
	}
	if g.Timeouts.Idle == "" {
		g.Timeouts.Idle = DefaultIdleTimeout.String()
	}
	if g.Timeouts.ReadHeader == "" {
		g.Timeouts.ReadHeader = DefaultReadHeaderTimeout.String()
	}

	// Rate limit container defaults
	if g.RateLimits.TTL == "" {
		g.RateLimits.TTL = "30m"
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
	if g.RateLimits.Global.Window == "" {
		g.RateLimits.Global.Window = "1s"
	}
	if g.RateLimits.Global.Burst <= 0 {
		g.RateLimits.Global.Burst = 240
	}

	// Auth policy defaults
	if g.RateLimits.Auth.Requests <= 0 {
		g.RateLimits.Auth.Requests = 10
	}
	if g.RateLimits.Auth.Window == "" {
		g.RateLimits.Auth.Window = "1m"
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
	w, err := time.ParseDuration(rc.Window)
	if err != nil || w <= 0 {
		return 0, 0, 0, false
	}
	b := rc.Burst
	if b <= 0 {
		b = rc.Requests
	}
	return rc.Requests, w, b, true
}
