package woos

import (
	"path/filepath"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func DefaultApply(g *alaye.Global, configAbsPath string) {
	g.Build = Version

	// Timeouts is a struct (not a pointer), so we can access fields directly.
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

	if g.General.MaxHeaderBytes == 0 {
		g.General.MaxHeaderBytes = alaye.DefaultMaxHeaderBytes
	}

	// RateLimits is a pointer. Must check nil before accessing Active or fields.
	if g.RateLimits.Enabled.Yes() {
		if g.RateLimits.TTL == 0 {
			g.RateLimits.TTL = DefaultRateLimitTTL
		}
		if g.RateLimits.MaxEntries <= 0 {
			g.RateLimits.MaxEntries = 100000
		}
	}

	resolvePaths(g, configAbsPath)
}

func resolvePaths(g *alaye.Global, configAbsPath string) {
	baseDir := "."
	if configAbsPath != "" {
		baseDir = filepath.Dir(configAbsPath)
	}

	setDefaultPath(&g.Storage.HostsDir, baseDir, HostDir.Name())
	setDefaultPath(&g.Storage.CertsDir, baseDir, CertDir.Name())
	setDefaultPath(&g.Storage.DataDir, baseDir, DataDir.Name())

	logDir := filepath.Join(baseDir, LogDir.Name())

	// Logging is a pointer. Check before access.
	if g.Logging.Enabled.Yes() {
		if g.Logging.File == "" {
			g.Logging.File = filepath.Join(logDir, DefaultLogName)
		} else if !filepath.IsAbs(g.Logging.File) {
			cleanName := filepath.Clean(g.Logging.File)
			if !strings.HasPrefix(cleanName, "..") {
				g.Logging.File = filepath.Join(logDir, filepath.Base(cleanName))
			} else {
				g.Logging.File = filepath.Join(baseDir, g.Logging.File)
			}
		}
	} else {
		// If nil, we can optionally initialize it or leave it nil.
		// Leaving it nil implies disabled logging, which is safer if logic respects nil.
		// However, to set a default file path in case it gets enabled later:
		// But strictly for defaults, we usually only touch what exists.
	}
}

func setDefaultPath(field *string, baseDir, defaultName string) {
	if *field == "" {
		*field = filepath.Join(baseDir, defaultName)
	} else if !filepath.IsAbs(*field) {
		*field = filepath.Join(baseDir, *field)
	}
}
