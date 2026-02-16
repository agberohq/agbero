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

	applyGlobalImplicit(g)
	applyNumericDefaults(g)
	resolvePaths(g, configAbsPath)
}

func ApplyHost(h *alaye.Host) {
	// Normalize domains first
	for i := range h.Domains {
		h.Domains[i] = strings.ToLower(strings.TrimSpace(h.Domains[i]))
	}

	// Apply defaults to HTTP Routes
	for i := range h.Routes {
		applyRouteDefaults(&h.Routes[i])
	}

	// Apply defaults to TCP Proxies
	for i := range h.Proxies {
		applyProxyDefaults(&h.Proxies[i])
	}
}

func applyGlobalImplicit(g *alaye.Global) {
	if g.Logging.Enabled.Default() {
		if g.Logging.File != "" || g.Logging.Level != "" || g.Logging.Victoria.Enabled.Active() {
			g.Logging.Enabled = alaye.Active
		}
	}

	if g.Admin.Enabled.Default() {
		if g.Admin.Address != "" {
			g.Admin.Enabled = alaye.Active
		}
	}

	if g.Security.Enabled.Default() {
		if len(g.Security.TrustedProxies) > 0 || g.Security.Firewall.Status.Active() || len(g.Security.Firewall.Rules) > 0 {
			g.Security.Enabled = alaye.Active
		}
	}

	if g.Security.Firewall.Status.Default() {
		if len(g.Security.Firewall.Actions) > 0 || len(g.Security.Firewall.Rules) > 0 {
			g.Security.Firewall.Status = alaye.Active
		}
	}

	if g.Gossip.Enabled.Default() {
		if len(g.Gossip.Seeds) > 0 || g.Gossip.SecretKey != "" {
			g.Gossip.Enabled = alaye.Active
		}
	}

	if g.RateLimits.Enabled.Default() {
		if len(g.RateLimits.Rules) > 0 || len(g.RateLimits.Policies) > 0 {
			g.RateLimits.Enabled = alaye.Active
		}
	}

	if g.LetsEncrypt.Enabled.Default() {
		if g.LetsEncrypt.Email != "" {
			g.LetsEncrypt.Enabled = alaye.Active
		}
	}
}

func applyNumericDefaults(g *alaye.Global) {
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

	if g.Admin.Enabled.Active() && g.Admin.Address == "" {
		g.Admin.Address = ":9090"
	}

	if g.RateLimits.Enabled.Active() {
		if g.RateLimits.TTL == 0 {
			g.RateLimits.TTL = DefaultRateLimitTTL
		}
		if g.RateLimits.MaxEntries <= 0 {
			g.RateLimits.MaxEntries = DefaultRateLimitMaxEntries
		}
	}

	if g.Gossip.Enabled.Active() && g.Gossip.Port == 0 {
		g.Gossip.Port = alaye.DefaultGossipPort
	}

	fw := &g.Security.Firewall
	if fw.Status.Active() {
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
}

func applyRouteDefaults(r *alaye.Route) {
	if r.Enabled.Default() {
		r.Enabled = alaye.Active
	}

	// Backends
	if r.Backends.Enabled.Default() && len(r.Backends.Servers) > 0 {
		r.Backends.Enabled = alaye.Active
	}

	// Backend Streaming
	if r.Backends.Enabled.Active() {
		for i := range r.Backends.Servers {
			srv := &r.Backends.Servers[i]
			if srv.Streaming.Enabled.Default() && srv.Streaming.FlushInterval > 0 {
				srv.Streaming.Enabled = alaye.Active
			}
		}
	}

	// Web & PHP
	if r.Web.Enabled.Default() {
		if r.Web.Root.IsSet() || r.Web.Index != "" || r.Web.Listing {
			r.Web.Enabled = alaye.Active
		}
	}

	if r.Web.PHP.Status.Default() {
		if r.Web.PHP.Address != "" {
			r.Web.PHP.Status = alaye.Active
		}
	}

	// Rate Limits
	if r.RateLimit.Enabled.Default() {
		if r.RateLimit.Rule.Requests > 0 || r.RateLimit.UsePolicy != "" || r.RateLimit.IgnoreGlobal {
			r.RateLimit.Enabled = alaye.Active
		}
	}

	// Firewall
	if r.Firewall.Status.Default() {
		if len(r.Firewall.Rules) > 0 || len(r.Firewall.ApplyRules) > 0 || r.Firewall.IgnoreGlobal {
			r.Firewall.Status = alaye.Active
		}
	}

	// Health Check
	if r.HealthCheck.Enabled.Default() && r.HealthCheck.Path != "" {
		r.HealthCheck.Enabled = alaye.Active
	}

	// Circuit Breaker
	if r.CircuitBreaker.Enabled.Default() {
		if r.CircuitBreaker.Threshold > 0 || r.CircuitBreaker.Duration > 0 {
			r.CircuitBreaker.Enabled = alaye.Active
		}
	}

	// Timeouts
	if r.Timeouts.Enabled.Default() && r.Timeouts.Request > 0 {
		r.Timeouts.Enabled = alaye.Active
	}

	// Auth Modules
	if r.BasicAuth.Enabled.Default() && len(r.BasicAuth.Users) > 0 {
		r.BasicAuth.Enabled = alaye.Active
	}
	if r.ForwardAuth.Enabled.Default() && r.ForwardAuth.URL != "" {
		r.ForwardAuth.Enabled = alaye.Active
	}
	if r.JWTAuth.Enabled.Default() && r.JWTAuth.Secret != "" {
		r.JWTAuth.Enabled = alaye.Active
	}
	if r.OAuth.Enabled.Default() && r.OAuth.Provider != "" {
		r.OAuth.Enabled = alaye.Active
	}

	// Headers
	if r.Headers.Enabled.Default() {
		req := r.Headers.Request
		res := r.Headers.Response
		if len(req.Set) > 0 || len(req.Add) > 0 || len(req.Remove) > 0 ||
			len(res.Set) > 0 || len(res.Add) > 0 || len(res.Remove) > 0 {
			r.Headers.Enabled = alaye.Active
		}
	}

	// Compression
	if r.CompressionConfig.Enabled.Default() {
		if r.CompressionConfig.Level > 0 || r.CompressionConfig.Type != "" {
			r.CompressionConfig.Enabled = alaye.Active
		}
	}

	// Wasm
	if r.Wasm.Enabled.Default() && r.Wasm.Module != "" {
		r.Wasm.Enabled = alaye.Active
	}
}

func applyProxyDefaults(t *alaye.TCPRoute) {
	if t.Enabled.Default() {
		t.Enabled = alaye.Active
	}

	if t.HealthCheck.Enabled.Default() {
		if t.HealthCheck.Interval > 0 || t.HealthCheck.Send != "" {
			t.HealthCheck.Enabled = alaye.Active
		}
	}
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
