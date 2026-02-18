package woos

import (
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
)

// DefaultApply applies all defaults to global configuration
func DefaultApply(g *alaye.Global, configPath string) {
	// === GLOBAL LEVEL ===
	defaultGlobal(g, configPath)

	// === HOST LEVEL (via Global.Storage.HostsDir) ===
	// Host defaults are applied when each host is loaded in discovery.Host.loadOne
	// which calls DefaultHost(&hostConfig)
}

func defaultGlobal(g *alaye.Global, configPath string) {
	// Version
	if g.Version == 0 {
		g.Version = ConfigFormatVersion
	}

	// General
	if g.General.MaxHeaderBytes == 0 {
		g.General.MaxHeaderBytes = alaye.DefaultMaxHeaderBytes
	}

	// Bind defaults
	if g.Bind.Redirect == alaye.Unknown {
		g.Bind.Redirect = alaye.Active
	}

	// Timeouts - auto-enable if any timeout configured, or apply defaults
	defaultTimeout(&g.Timeouts)

	// Storage - derive from config path if not set
	defaultStorage(&g.Storage, configPath)

	// Admin - auto-enable if address configured
	defaultAdmin(&g.Admin)

	// Logging - auto-enable if output configured
	defaultLogging(&g.Logging)

	// Security - auto-enable if firewall rules exist
	defaultSecurity(&g.Security)

	// RateLimits - auto-enable if policies/rules exist
	defaultRateLimits(&g.RateLimits)

	// Gossip - auto-enable if port/seeds configured
	defaultGossip(&g.Gossip)

	// LetsEncrypt - auto-enable if email configured
	defaultLetsEncrypt(&g.LetsEncrypt)

	// Fallback - set global fallback option
	defaultFallback(&g.Fallback)
}

// DefaultHost applies defaults to a host configuration
func DefaultHost(h *alaye.Host) {
	// TLS - auto-detect mode from domains if not set
	defaultTLS(&h.TLS, h.Domains)

	// Limits
	defaultLimits(&h.Limits)

	// Headers
	defaultHeaders(&h.Headers)

	// Routes
	for i := range h.Routes {
		DefaultRoute(&h.Routes[i])
	}

	// Proxies (TCP)
	for i := range h.Proxies {
		defaultTCPRoute(&h.Proxies[i])
	}
}

// DefaultRoute applies defaults to a route configuration
func DefaultRoute(r *alaye.Route) {
	// Enabled: Active unless explicitly disabled
	if r.Enabled == alaye.Unknown {
		r.Enabled = alaye.Active
	}

	// Web vs Proxy detection for defaults
	hasWeb := r.Web.Root.IsSet()
	hasBackends := len(r.Backends.Servers) > 0

	if hasWeb {
		defaultWebRoute(r)
	} else if hasBackends {
		defaultProxyRoute(r)
	}

	defaultFallback(&r.Fallback)
}

func defaultWebRoute(r *alaye.Route) {
	// Web root defaults
	if r.Web.Enabled == alaye.Unknown {
		r.Web.Enabled = alaye.Active
	}
	if r.Web.Index == "" {
		r.Web.Index = "index.html"
	}

	// PHP defaults
	defaultPHP(&r.Web.PHP)

	// Compression inheritance happens at Host level
	defaultCompression(&r.CompressionConfig)

	// Headers
	defaultHeaders(&r.Headers)

	// Auth - auto-enable if configured
	defaultBasicAuth(&r.BasicAuth)
	defaultJWTAuth(&r.JWTAuth)
	defaultForwardAuth(&r.ForwardAuth)
	defaultOAuth(&r.OAuth)
}

func defaultProxyRoute(r *alaye.Route) {
	// Backends
	defaultBackend(&r.Backends)

	// HealthCheck - auto-enable if path configured
	defaultHealthCheck(&r.HealthCheck)

	// CircuitBreaker - auto-enable if threshold configured
	defaultCircuitBreaker(&r.CircuitBreaker)

	// Timeouts - auto-enable if request timeout configured
	defaultTimeoutRoute(&r.Timeouts)

	// Same as web route for these
	defaultCompression(&r.CompressionConfig)
	defaultHeaders(&r.Headers)
	defaultBasicAuth(&r.BasicAuth)
	defaultJWTAuth(&r.JWTAuth)
	defaultForwardAuth(&r.ForwardAuth)
	defaultOAuth(&r.OAuth)
	defaultRateLimit(&r.RateLimit)
	defaultWasm(&r.Wasm)
	defaultFirewallRoute(&r.Firewall)
}

// === COMPONENT DEFAULTERS ===

func defaultTimeout(t *alaye.Timeout) {
	hasAnyTimeout := t.Read > 0 || t.Write > 0 || t.Idle > 0 || t.ReadHeader > 0

	if t.Enabled == alaye.Unknown && hasAnyTimeout {
		t.Enabled = alaye.Active
	}
	if t.Enabled == alaye.Active || t.Enabled == alaye.Unknown {
		t.Enabled = alaye.Active
		if t.Read == 0 {
			t.Read = alaye.DefaultReadTimeout
		}
		if t.Write == 0 {
			t.Write = alaye.DefaultWriteTimeout
		}
		if t.Idle == 0 {
			t.Idle = alaye.DefaultIdleTimeout
		}
		if t.ReadHeader == 0 {
			t.ReadHeader = alaye.DefaultReadHeaderTimeout
		}
	}
}

func defaultStorage(s *alaye.Storage, configPath string) {
	// Derive from config file location if not set
	if s.HostsDir == "" {
		s.HostsDir = filepath.Join(filepath.Dir(configPath), HostDir.String())
	}
	if s.CertsDir == "" {
		s.CertsDir = filepath.Join(filepath.Dir(configPath), CertDir.String())
	}
	if s.DataDir == "" {
		s.DataDir = filepath.Join(filepath.Dir(configPath), DataDir.String())
	}
}

func defaultAdmin(a *alaye.Admin) {
	// Auto-enable if address is configured
	if a.Enabled == alaye.Unknown && a.Address != "" {
		a.Enabled = alaye.Active
	}

	if a.Enabled == alaye.Active {
		// Auto-enable auth methods if configured
		defaultBasicAuth(&a.BasicAuth)
		defaultJWTAuth(&a.JWTAuth)
		defaultForwardAuth(&a.ForwardAuth)
		defaultOAuth(&a.OAuth)
	}
}

func defaultLogging(l *alaye.Logging) {
	// Auto-enable if file or victoria URL configured
	if l.Enabled == alaye.Unknown && (l.File != "" || l.Victoria.URL != "") {
		l.Enabled = alaye.Active
	}
	if l.Level == "" {
		l.Level = LogLevelInfo
	}

	// Victoria defaults
	if l.Victoria.Enabled == alaye.Unknown && l.Victoria.URL != "" {
		l.Victoria.Enabled = alaye.Active
	}
	if l.Victoria.BatchSize == 0 {
		l.Victoria.BatchSize = DefaultVictoriaBatch
	}

	if l.Prometheus.Enabled == alaye.Unknown {
		l.Prometheus.Enabled = alaye.Inactive
	}
	if l.Prometheus.Path == "" {
		l.Prometheus.Path = "/metrics"
	}
}

func defaultSecurity(s *alaye.Security) {
	// Auto-enable if firewall rules exist
	hasRules := len(s.Firewall.Rules) > 0

	if s.Enabled == alaye.Unknown && hasRules {
		s.Enabled = alaye.Active
	}

	defaultFirewall(&s.Firewall)
}

func defaultFirewall(f *alaye.Firewall) {
	// Auto-enable if rules configured
	if f.Status == alaye.Unknown && len(f.Rules) > 0 {
		f.Status = alaye.Active
	}
	if f.Mode == "" {
		f.Mode = "active"
	}
	if f.MaxInspectBytes == 0 {
		f.MaxInspectBytes = 8192
	}
	if len(f.InspectContentTypes) == 0 {
		f.InspectContentTypes = []string{
			"application/json",
			"application/xml",
			"application/x-www-form-urlencoded",
			"text/plain",
		}
	}

	// Default actions
	for i := range f.Actions {
		if f.Actions[i].Mitigation == "" {
			f.Actions[i].Mitigation = "add"
		}
	}

	// Compile regex patterns
	for i := range f.Rules {
		for j := range f.Rules[i].Match.Any {
			compileCondition(&f.Rules[i].Match.Any[j])
		}
		for j := range f.Rules[i].Match.All {
			compileCondition(&f.Rules[i].Match.All[j])
		}
		for j := range f.Rules[i].Match.None {
			compileCondition(&f.Rules[i].Match.None[j])
		}
		if f.Rules[i].Match.Extract != nil {
			compileExtract(f.Rules[i].Match.Extract)
		}
	}
}

func defaultRateLimits(rl *alaye.GlobalRate) {
	// Auto-enable if policies or rules exist
	hasConfig := len(rl.Policies) > 0 || len(rl.Rules) > 0

	if rl.Enabled == alaye.Unknown && hasConfig {
		rl.Enabled = alaye.Active
	}

	if rl.TTL == 0 {
		rl.TTL = 30 * time.Minute
	}
	if rl.MaxEntries == 0 {
		rl.MaxEntries = 100_000
	}

	// Default policy values
	for i := range rl.Policies {
		if rl.Policies[i].Burst == 0 {
			rl.Policies[i].Burst = rl.Policies[i].Requests
		}
		if rl.Policies[i].Key == "" {
			rl.Policies[i].Key = "ip"
		}
	}
}

func defaultGossip(g *alaye.Gossip) {
	// Auto-enable if port or seeds configured
	if g.Enabled == alaye.Unknown && (g.Port > 0 || len(g.Seeds) > 0) {
		g.Enabled = alaye.Active
	}

	if g.Enabled == alaye.Active {
		if g.Port == 0 {
			g.Port = alaye.DefaultGossipPort
		}
		if g.TTL == 0 {
			g.TTL = 30 // seconds
		}
	}
}

func defaultLetsEncrypt(le *alaye.LetsEncrypt) {
	// Auto-enable if email configured
	if le.Enabled == alaye.Unknown && le.Email != "" {
		le.Enabled = alaye.Active
	}
}

func defaultTLS(t *alaye.TLS, domains []string) {
	// Auto-detect mode from domains if not set
	if t.Mode == "" && len(domains) > 0 {
		allLocal := true
		for _, d := range domains {
			if !IsLocalhost(d) {
				allLocal = false
				break
			}
		}
		if allLocal {
			t.Mode = alaye.ModeLocalAuto
		} else {
			t.Mode = alaye.ModeLetsEncrypt
		}
	}

	// Apply mode-specific defaults
	switch t.Mode {
	case alaye.ModeLocalCert:
		// Nothing to default, paths required
	case alaye.ModeLetsEncrypt:
		defaultLetsEncrypt(&t.LetsEncrypt)
	case alaye.ModeCustomCA:
		if t.CustomCA.Enabled == alaye.Unknown && t.CustomCA.Root != "" {
			t.CustomCA.Enabled = alaye.Active
		}
	}
}

func defaultLimits(l *alaye.Limit) {
	// MaxBodySize: 0 means unlimited, no default needed
}

func defaultHeaders(h *alaye.Headers) {
	// Auto-enable if any header operations configured
	hasOps := len(h.Request.Set) > 0 || len(h.Request.Add) > 0 || len(h.Request.Remove) > 0 ||
		len(h.Response.Set) > 0 || len(h.Response.Add) > 0 || len(h.Response.Remove) > 0

	if h.Enabled == alaye.Unknown && hasOps {
		h.Enabled = alaye.Active
	}

	// Request/Response auto-enable
	if h.Request.Enabled == alaye.Unknown && (len(h.Request.Set) > 0 || len(h.Request.Add) > 0 || len(h.Request.Remove) > 0) {
		h.Request.Enabled = alaye.Active
	}
	if h.Response.Enabled == alaye.Unknown && (len(h.Response.Set) > 0 || len(h.Response.Add) > 0 || len(h.Response.Remove) > 0) {
		h.Response.Enabled = alaye.Active
	}
}

func defaultBackend(b *alaye.Backend) {
	// Auto-enable if servers configured
	if b.Enabled == alaye.Unknown && len(b.Servers) > 0 {
		b.Enabled = alaye.Active
	}

	// Strategy: default for multi-server
	if b.Strategy == "" && len(b.Servers) > 1 {
		b.Strategy = alaye.StrategyRoundRobin
	}

	// Server weights
	for i := range b.Servers {
		if b.Servers[i].Weight == 0 {
			b.Servers[i].Weight = 1
		}
	}
}

func defaultHealthCheck(hc *alaye.HealthCheck) {
	// Auto-enable if path configured
	if hc.Enabled == alaye.Unknown && hc.Path != "" {
		hc.Enabled = alaye.Active
	}

	if hc.Enabled == alaye.Active {
		if hc.Interval == 0 {
			hc.Interval = alaye.DefaultHealthInterval
		}
		if hc.Timeout == 0 {
			hc.Timeout = alaye.DefaultHealthTimeout
		}
		if hc.Threshold == 0 {
			hc.Threshold = alaye.DefaultHealthThreshold
		}
	}
}

func defaultCircuitBreaker(cb *alaye.CircuitBreaker) {
	// Auto-enable if threshold configured
	if cb.Enabled == alaye.Unknown && cb.Threshold > 0 {
		cb.Enabled = alaye.Active
	}

	if cb.Enabled == alaye.Active {
		if cb.Threshold == 0 {
			cb.Threshold = alaye.DefaultCircuitBreakerThreshold
		}
		if cb.Duration == 0 {
			cb.Duration = alaye.DefaultCircuitBreakerDuration
		}
	}
}

func defaultTimeoutRoute(t *alaye.TimeoutRoute) {
	// Auto-enable if request timeout configured
	if t.Enabled == alaye.Unknown && t.Request > 0 {
		t.Enabled = alaye.Active
	}
}

func defaultCompression(c *alaye.Compression) {
	// Auto-enable if type configured
	if c.Enabled == alaye.Unknown && c.Type != "" {
		c.Enabled = alaye.Active
	}

	if c.Enabled == alaye.Active {
		if c.Type == "" {
			c.Type = alaye.CompressionGzip
		}
		if c.Level == 0 {
			c.Level = 5 // middle ground
		}
	}
}

func defaultBasicAuth(ba *alaye.BasicAuth) {
	// Auto-enable if users configured
	if ba.Enabled == alaye.Unknown && len(ba.Users) > 0 {
		ba.Enabled = alaye.Active
	}
	if ba.Realm == "" {
		ba.Realm = "Restricted"
	}
}

func defaultJWTAuth(ja *alaye.JWTAuth) {
	// Auto-enable if secret configured
	if ja.Enabled == alaye.Unknown && ja.Secret != "" {
		ja.Enabled = alaye.Active
	}
}

func defaultForwardAuth(fa *alaye.ForwardAuth) {
	// Auto-enable if URL configured
	if fa.Enabled == alaye.Unknown && fa.URL != "" {
		fa.Enabled = alaye.Active
	}

	if fa.Enabled == alaye.Active {
		if fa.Timeout == 0 {
			fa.Timeout = 5 * time.Second
		}
		if fa.OnFailure == "" {
			fa.OnFailure = "deny"
		}

		// Request defaults
		if fa.Request.Enabled == alaye.Unknown {
			// Auto-enable if any request setting configured
			if len(fa.Request.Headers) > 0 || fa.Request.ForwardMethod || fa.Request.ForwardURI || fa.Request.ForwardIP {
				fa.Request.Enabled = alaye.Active
			}
		}

		// Response defaults
		if fa.Response.Enabled == alaye.Unknown && fa.Response.CacheTTL > 0 {
			fa.Response.Enabled = alaye.Active
		}
	}
}

func defaultOAuth(oa *alaye.OAuth) {
	// Auto-enable if provider configured
	if oa.Enabled == alaye.Unknown && oa.Provider != "" {
		oa.Enabled = alaye.Active
	}

	if oa.Enabled == alaye.Active {
		// Default scopes
		if len(oa.Scopes) == 0 {
			switch oa.Provider {
			case alaye.ProviderGoogle, alaye.ProviderOIDC:
				oa.Scopes = []string{alaye.ScopeOpenID, alaye.ScopeProfile, alaye.ScopeEmail}
			case alaye.ProviderGitHub:
				oa.Scopes = []string{"user:email"}
			}
		}
	}
}

func defaultPHP(p *alaye.PHP) {
	// Auto-enable if address configured
	if p.Status == alaye.Unknown && p.Address != "" {
		p.Status = alaye.Active
	}
	if p.Status == alaye.Active && p.Index == "" {
		p.Index = "index.php"
	}
}

func defaultRateLimit(rl *alaye.RouteRate) {
	// Auto-enable if policy or rule configured
	if rl.Enabled == alaye.Unknown && (rl.UsePolicy != "" || rl.Rule.Requests > 0) {
		rl.Enabled = alaye.Active
	}

	// Default rule values
	if rl.Rule.Enabled == alaye.Unknown && rl.Rule.Requests > 0 {
		rl.Rule.Enabled = alaye.Active
	}
	if rl.Rule.Burst == 0 && rl.Rule.Requests > 0 {
		rl.Rule.Burst = rl.Rule.Requests
	}
}

func defaultWasm(w *alaye.Wasm) {
	// Auto-enable if module configured
	if w.Enabled == alaye.Unknown && w.Module != "" {
		w.Enabled = alaye.Active
	}
}

func defaultFirewallRoute(fr *alaye.FirewallRoute) {
	// Auto-enable if rules configured
	if fr.Status == alaye.Unknown && len(fr.Rules) > 0 {
		fr.Status = alaye.Active
	}

	// Apply rule defaults
	for i := range fr.Rules {
		if fr.Rules[i].Name == "" {
			fr.Rules[i].Name = "route_rule_" + strconv.Itoa(i)
		}
	}
}

func defaultTCPRoute(t *alaye.TCPRoute) {
	// Auto-enable if listen configured
	if t.Enabled == alaye.Unknown && t.Listen != "" {
		t.Enabled = alaye.Active
	}

	if t.Enabled == alaye.Active {
		if t.Strategy == "" {
			t.Strategy = alaye.StrategyRoundRobin
		}

		// Server weights
		for i := range t.Backends {
			if t.Backends[i].Weight == 0 {
				t.Backends[i].Weight = 1
			}
		}

		// Health check defaults
		defaultTCPHealthCheck(&t.HealthCheck)
	}
}

func defaultTCPHealthCheck(thc *alaye.TCPHealthCheck) {
	// Auto-enable if send/expect configured
	if thc.Enabled == alaye.Unknown && (thc.Send != "" || thc.Expect != "") {
		thc.Enabled = alaye.Active
	}

	if thc.Enabled == alaye.Active {
		if thc.Interval == 0 {
			thc.Interval = TCPHealthCheckInterval
		}
		if thc.Timeout == 0 {
			thc.Timeout = TCPHealthCheckTimeout
		}
	}
}

func defaultFallback(f *alaye.Fallback) {
	if f.Enabled == alaye.Unknown {
		f.Enabled = alaye.Inactive // Disabled by default globally
	}
	if f.Enabled.Active() {
		if f.Type == "" {
			f.Type = "static"
		}
		if f.StatusCode == 0 {
			switch f.Type {
			case "redirect":
				f.StatusCode = 307
			case "proxy":
				f.StatusCode = 200
			default:
				f.StatusCode = 503
			}
		}
		if f.ContentType == "" && f.Type == "static" {
			f.ContentType = "application/json"
		}
	}
}

// Helper: compile regex in conditions
func compileCondition(c *alaye.Condition) {
	if c.Pattern != "" && c.Compiled == nil {
		c.Compiled = regexp.MustCompile(c.Pattern)
	}
}

func compileExtract(e *alaye.Extract) {
	if e.Pattern != "" && e.Regex == nil {
		e.Regex = regexp.MustCompile(e.Pattern)
	}
}
