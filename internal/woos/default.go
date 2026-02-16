package woos

import (
	"path/filepath"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func DefaultApply(g *alaye.Global, configAbsPath string) {
	if g.Build == "" {
		g.Build = Version
	}

	// Timeouts
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

	// General
	if g.General.MaxHeaderBytes == 0 {
		g.General.MaxHeaderBytes = alaye.DefaultMaxHeaderBytes
	}

	// Rate Limits
	if g.RateLimits.Enabled.Active() {
		if g.RateLimits.TTL == 0 {
			g.RateLimits.TTL = DefaultRateLimitTTL
		}
		if g.RateLimits.MaxEntries <= 0 {
			g.RateLimits.MaxEntries = DefaultRateLimitMaxEntries
		}
	}

	// Firewall Defaults
	if g.Security.Firewall.Status.Active() {
		fw := &g.Security.Firewall
		if fw.MaxInspectBytes == 0 {
			fw.MaxInspectBytes = 8192
		}
		if len(fw.InspectContentTypes) == 0 {
			fw.InspectContentTypes = []string{
				"application/json",
				"application/xml",
				"application/x-www-form-urlencoded",
				"text/plain",
			}
		}
		if fw.Mode == "" {
			fw.Mode = "active"
		}
	}

	// Admin Defaults
	if g.Admin.Enabled.Active() {
		if g.Admin.Address == "" {
			g.Admin.Address = ":9090"
		}
	}

	// Gossip Defaults
	if g.Gossip.Enabled.Active() {
		if g.Gossip.Port == 0 {
			g.Gossip.Port = DefaultGossipPort
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

	if g.Logging.Enabled.Active() {
		if g.Logging.Level == "" {
			g.Logging.Level = "info"
		}
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
}

func setDefaultPath(field *string, baseDir, defaultName string) {
	if *field == "" {
		*field = filepath.Join(baseDir, defaultName)
	} else if !filepath.IsAbs(*field) {
		*field = filepath.Join(baseDir, *field)
	}
}
