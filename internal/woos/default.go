package woos

import (
	"path/filepath"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

// DefaultApply sets defaults ONLY when config did not provide values.
func DefaultApply(g *alaye.Global, configAbsPath string) {
	// --- 1. Timeout Defaults ---
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

	// --- 2. Rate Limit Defaults ---
	if g.RateLimits.Enabled {
		if g.RateLimits.TTL == 0 {
			g.RateLimits.TTL = 30 * time.Minute
		}
		if g.RateLimits.MaxEntries <= 0 {
			g.RateLimits.MaxEntries = 100000
		}
		// Note: We no longer inject default Global/Auth policies here.
		// If the user enables rate limiting, they must define 'rule' blocks in the config.
	}

	// --- 3. Directory Defaults ---
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
