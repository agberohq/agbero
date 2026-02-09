package woos

import (
	"path/filepath"
	"strings"
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
	}

	// --- 3. Directory Defaults ---
	baseDir := "."
	if configAbsPath != "" {
		baseDir = filepath.Dir(configAbsPath)
	}

	if g.Storage.HostsDir == "" {
		g.Storage.HostsDir = filepath.Join(baseDir, HostDir.Name())
	} else if !filepath.IsAbs(g.Storage.HostsDir) {
		g.Storage.HostsDir = filepath.Join(baseDir, g.Storage.HostsDir)
	}

	if g.Storage.CertsDir == "" {
		g.Storage.CertsDir = filepath.Join(baseDir, CertDir.Name())
	} else if !filepath.IsAbs(g.Storage.CertsDir) {
		g.Storage.CertsDir = filepath.Join(baseDir, g.Storage.CertsDir)
	}

	if g.Storage.DataDir == "" {
		g.Storage.DataDir = filepath.Join(baseDir, DataDir.Name())
	} else if !filepath.IsAbs(g.Storage.DataDir) {
		g.Storage.DataDir = filepath.Join(baseDir, g.Storage.DataDir)
	}

	// --- 4. Logging Defaults ---
	// Logic:
	// 1. Empty? -> Default to logs.d/agbero.log
	// 2. Relative? -> Prepend logs.d directory to keep it organized.
	//    (e.g., "server.log" -> "logs.d/server.log")
	// 3. Absolute? -> Use as is.

	logDir := filepath.Join(baseDir, LogDir.Name())

	if g.Logging.File == "" {
		g.Logging.File = filepath.Join(logDir, DefaultLogName)
	} else if !filepath.IsAbs(g.Logging.File) {
		// Clean the path to handle "./agbero.log" -> "agbero.log"
		cleanName := filepath.Clean(g.Logging.File)

		// If it's just a filename (no dir separators), or a relative path, enforce logs.d
		// This handles the case where template had `file = "./agbero.log"`
		// We want to force it into logs.d unless the user broke out with "../"
		if !strings.HasPrefix(cleanName, "..") {
			g.Logging.File = filepath.Join(logDir, filepath.Base(cleanName))
		} else {
			// User explicitly trying to go up a dir, respect relative from base
			g.Logging.File = filepath.Join(baseDir, g.Logging.File)
		}
	}
}
