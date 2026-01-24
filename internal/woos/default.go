package woos

import (
	"os"
	"path/filepath"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

// ApplyDefaults sets defaults ONLY when config did not provide values.
func ApplyDefaults(g *alaye.Global, configAbsPath string) {
	// --- 1. Timeout Defaults (unchanged) ---
	if g.Timeouts.Read == 0 {
		g.Timeouts.Read = alaye.DefaultReadTimeout
	}
	if g.Timeouts.Write == 0 {
		g.Timeouts.Write = alaye.DefaultWriteTimeout
	}
	if g.Timeouts.Idle == 0 {
		g.Timeouts.Idle = alaye.DefaultIdleTimeout
	}
	if g.Timeouts.ReadHeader == 0 {
		g.Timeouts.ReadHeader = alaye.DefaultReadHeaderTimeout
	}

	// --- 2. Rate Limit Defaults (unchanged) ---
	if g.RateLimits.TTL == 0 {
		g.RateLimits.TTL = 30 * time.Minute
	}
	if g.RateLimits.MaxEntries <= 0 {
		g.RateLimits.MaxEntries = 100000
	}
	if len(g.RateLimits.AuthPrefixes) == 0 {
		g.RateLimits.AuthPrefixes = []string{"/login", "/otp", "/auth"}
	}
	if g.RateLimits.Global.Requests <= 0 {
		g.RateLimits.Global.Requests = 120
	}
	if g.RateLimits.Global.Window == 0 {
		g.RateLimits.Global.Window = 1 * time.Second
	}
	if g.RateLimits.Global.Burst <= 0 {
		g.RateLimits.Global.Burst = 240
	}
	if g.RateLimits.Auth.Requests <= 0 {
		g.RateLimits.Auth.Requests = 10
	}
	if g.RateLimits.Auth.Window == 0 {
		g.RateLimits.Auth.Window = 1 * time.Minute
	}
	if g.RateLimits.Auth.Burst <= 0 {
		g.RateLimits.Auth.Burst = 10
	}

	// --- 3. Path Resolution (The Fix) ---
	// This replaces the duplicated logic in helpers.go and avoids OS nonsense here.

	// If we don't have a config path (e.g. testing), default to CWD
	baseDir := "."
	if configAbsPath != "" {
		baseDir = filepath.Dir(configAbsPath)
	}

	// Resolve HostsDir
	if g.HostsDir == "" {
		g.HostsDir = filepath.Join(baseDir, DefaultHostDirName)
	} else if !filepath.IsAbs(g.HostsDir) {
		g.HostsDir = filepath.Join(baseDir, g.HostsDir)
	}

	// Resolve CertsDir
	if g.CertsDir == "" {
		g.CertsDir = filepath.Join(baseDir, DefaultCertDirName)
	} else if !filepath.IsAbs(g.CertsDir) {
		g.CertsDir = filepath.Join(baseDir, g.CertsDir)
	}

	// Resolve TLSStorageDir
	if g.TLSStorageDir == "" {
		// Try standard location or fallback to user home
		if home, err := os.UserHomeDir(); err == nil {
			// Check ~/.cert (legacy/common)
			legacy := filepath.Join(home, ".cert")
			if _, err := os.Stat(legacy); err == nil {
				g.TLSStorageDir = legacy
			} else {
				// Default: ~/.config/agbero/data
				g.TLSStorageDir = filepath.Join(home, ".config", Name, DefaultDataDirName)
			}
		} else {
			// Fallback if no home dir: ./data
			g.TLSStorageDir = filepath.Join(baseDir, DefaultDataDirName)
		}
	}
}

// ParseRatePolicy parses a RatePolicy into primitives (config must not depend on proxy types).
func ParseRatePolicy(rc alaye.RatePolicy) (requests int, window time.Duration, burst int, ok bool) {
	if rc.Requests <= 0 {
		return 0, 0, 0, false
	}
	b := rc.Burst
	if b <= 0 {
		b = rc.Requests
	}
	return rc.Requests, rc.Window, b, true
}
