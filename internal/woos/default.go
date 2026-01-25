package woos

import (
	"path/filepath"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

// DefaultApply sets defaults ONLY when config did not provide values.
func DefaultApply(g *alaye.Global, configAbsPath string) {
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
	if g.Storage.HostsDir == "" {
		g.Storage.HostsDir = filepath.Join(baseDir, HostDir.Name())
	} else if !filepath.IsAbs(g.Storage.HostsDir) {
		g.Storage.HostsDir = filepath.Join(baseDir, g.Storage.HostsDir)
	}

	// Resolve CertsDir
	if g.Storage.CertsDir == "" {
		g.Storage.CertsDir = filepath.Join(baseDir, CertDir.Name())
	} else if !filepath.IsAbs(g.Storage.CertsDir) {
		g.Storage.CertsDir = filepath.Join(baseDir, g.Storage.CertsDir)
	}

	// Resolve DataDir
	if g.Storage.DataDir == "" {
		g.Storage.DataDir = filepath.Join(baseDir, DataDir.Name())
	} else if !filepath.IsAbs(g.Storage.DataDir) {
		g.Storage.DataDir = filepath.Join(baseDir, g.Storage.DataDir)
	}
}
