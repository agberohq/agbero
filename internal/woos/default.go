package woos

import (
	"path/filepath"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func DefaultApply(g *alaye.Global, configAbsPath string) {
	// set the build version
	g.Build = Version

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

	if g.RateLimits.Enabled {
		if g.RateLimits.TTL == 0 {
			g.RateLimits.TTL = 30 * time.Minute
		}
		if g.RateLimits.MaxEntries <= 0 {
			g.RateLimits.MaxEntries = 100000
		}
	}

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

	logDir := filepath.Join(baseDir, LogDir.Name())

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
}
