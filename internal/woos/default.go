package woos

import (
	"path/filepath"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func DefaultApply(g *alaye.Global, configAbsPath string) {
	g.Build = Version

	// Enable features by default
	//if g.Admin.Status.Default() {
	//	g.Admin.Status. = alaye.Success
	//}
	//
	//if g.Timeouts.Status.Default() {
	//	g.Timeouts.Status = alaye.Success
	//}
	//if g.Logging.Status.Default() {
	//	g.Logging.Status = alaye.Success
	//}
	//if g.LetsEncrypt.Status.Default() {
	//	g.LetsEncrypt.Status = alaye.Success
	//}

	// Set default timeouts
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

	// Other defaults
	if g.General.MaxHeaderBytes == 0 {
		g.General.MaxHeaderBytes = alaye.DefaultMaxHeaderBytes
	}

	if g.RateLimits.Status.Default() {
		if g.RateLimits.TTL == 0 {
			g.RateLimits.TTL = DefaultRateLimitTTL
		}
		if g.RateLimits.MaxEntries <= 0 {
			g.RateLimits.MaxEntries = 100000
		}
	}

	// Path resolution (this part is unavoidably complex due to business logic)
	resolvePaths(g, configAbsPath)
}

func resolvePaths(g *alaye.Global, configAbsPath string) {
	baseDir := "."
	if configAbsPath != "" {
		baseDir = filepath.Dir(configAbsPath)
	}

	// Storage dirs
	setDefaultPath(&g.Storage.HostsDir, baseDir, HostDir.Name())
	setDefaultPath(&g.Storage.CertsDir, baseDir, CertDir.Name())
	setDefaultPath(&g.Storage.DataDir, baseDir, DataDir.Name())

	// Log file (special case)
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

func setDefaultPath(field *string, baseDir, defaultName string) {
	if *field == "" {
		*field = filepath.Join(baseDir, defaultName)
	} else if !filepath.IsAbs(*field) {
		*field = filepath.Join(baseDir, *field)
	}
}
