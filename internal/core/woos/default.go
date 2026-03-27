package woos

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// Defaults provides a zero-state receiver for applying configuration defaults.
// Use the package-level D variable: woos.D.Firewall(cfg), woos.D.Route(r), etc.
// All methods are safe to call on a zero-value Defaults.
type Defaults struct{}

// D is the package-level Defaults receiver for applying configuration defaults.
var D = Defaults{}

// Global applies all global configuration defaults before validation.
func (Defaults) Global(g *alaye.Global, configPath string) {
	defaultGlobal(g, configPath)
}

// Host applies all host configuration defaults before validation.
func (Defaults) Host(h *alaye.Host) {

	if h.Protected == alaye.Unknown {
		h.Protected = alaye.Inactive
	}
	defaultTLS(&h.TLS, h.Domains)
	defaultLimits(&h.Limits)
	defaultHeaders(&h.Headers)
	for i := range h.Routes {
		defaultRouteAll(&h.Routes[i])
	}
	for i := range h.Proxies {
		defaultTCPRoute(&h.Proxies[i])
	}
}

// Route applies defaults to a single route and all its nested blocks.
func (Defaults) Route(r *alaye.Route) {
	defaultRouteAll(r)
}

// Firewall applies all firewall configuration defaults before validation.
func (Defaults) Firewall(f *alaye.Firewall) {
	defaultFirewall(f)
}

// Cache applies cache configuration defaults before validation.
func (Defaults) Cache(c *alaye.Cache) {
	defaultCache(c)
}

// BasicAuth applies basic auth configuration defaults before validation.
func (Defaults) BasicAuth(ba *alaye.BasicAuth) {
	defaultBasicAuth(ba)
}

// ForwardAuth applies forward auth configuration defaults before validation.
func (Defaults) ForwardAuth(fa *alaye.ForwardAuth) {
	defaultForwardAuth(fa)
}

// CORS applies CORS configuration defaults before validation.
func (Defaults) CORS(c *alaye.CORS) {
	defaultCORS(c)
}

// Compression applies compression configuration defaults before validation.
func (Defaults) Compression(c *alaye.Compression) {
	defaultCompression(c)
}

// RateLimit applies route rate limit configuration defaults before validation.
func (Defaults) RateLimit(rl *alaye.RouteRate) {
	defaultRateLimit(rl)
}

// Wasm applies wasm configuration defaults before validation.
func (Defaults) Wasm(w *alaye.Wasm) {
	defaultWasm(w)
}

// HealthCheck applies health check configuration defaults before validation.
func (Defaults) HealthCheck(hc *alaye.HealthCheck) {
	defaultHealthCheck(hc)
}

// DefaultApply applies all global configuration defaults before validation.
// Kept for backwards compatibility with existing production call sites.
func DefaultApply(g *alaye.Global, configPath string) {
	D.Global(g, configPath)
}

// DefaultHost applies all host configuration defaults before validation.
// Kept for backwards compatibility with existing production call sites.
func DefaultHost(h *alaye.Host) {
	D.Host(h)
}

// DefaultRoute applies defaults to a single route and all its nested blocks.
// Kept for backwards compatibility with existing production call sites.
func DefaultRoute(r *alaye.Route) {
	D.Route(r)
}

func defaultGlobal(g *alaye.Global, configPath string) {
	if g.Version == 0 {
		g.Version = ConfigFormatVersion
	}
	if g.General.MaxHeaderBytes == 0 {
		g.General.MaxHeaderBytes = alaye.DefaultMaxHeaderBytes
	}
	if g.Bind.Redirect == alaye.Unknown && len(g.Bind.HTTPS) > 0 {
		g.Bind.Redirect = alaye.Active
	}
	defaultTimeout(&g.Timeouts)
	defaultStorage(&g.Storage, configPath)
	defaultAdmin(&g.Admin)
	defaultLogging(&g.Logging)
	defaultSecurity(&g.Security)
	defaultRateLimits(&g.RateLimits)
	defaultGossip(&g.Gossip)
	defaultLetsEncrypt(&g.LetsEncrypt)
	defaultFallback(&g.Fallback)

}

func defaultRouteAll(r *alaye.Route) {
	if r.Enabled == alaye.Unknown {
		r.Enabled = alaye.Active
	}
	hasWeb := r.Web.Root.IsSet() || r.Web.Git.Enabled.Active()
	hasBackends := len(r.Backends.Servers) > 0
	if hasWeb {
		defaultWebRoute(r)
	} else if hasBackends {
		defaultProxyRoute(r)
	}
	defaultCORS(&r.CORS)
	defaultCache(&r.Cache)
	defaultFallback(&r.Fallback)
}

func defaultWebRoute(r *alaye.Route) {
	if r.Web.Enabled == alaye.Unknown {
		r.Web.Enabled = alaye.Active
	}
	if len(r.Web.Index) == 0 {
		r.Web.Index = []string{"index.html"}
	}
	defaultPHP(&r.Web.PHP)
	defaultCompression(&r.CompressionConfig)
	defaultHeaders(&r.Headers)
	defaultBasicAuth(&r.BasicAuth)
	defaultJWTAuth(&r.JWTAuth)
	defaultForwardAuth(&r.ForwardAuth)
	defaultOAuth(&r.OAuth)
}

func defaultProxyRoute(r *alaye.Route) {
	defaultBackend(&r.Backends)
	defaultHealthCheck(&r.HealthCheck)
	defaultCircuitBreaker(&r.CircuitBreaker)
	defaultTimeoutRoute(&r.Timeouts)
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

func defaultTimeout(t *alaye.Timeout) {
	hasAnyTimeout := t.Read > 0 || t.Write > 0 || t.Idle > 0 || t.ReadHeader > 0
	if t.Enabled == alaye.Unknown && hasAnyTimeout {
		t.Enabled = alaye.Active
	}
	if t.Enabled == alaye.Active || t.Enabled == alaye.Unknown {
		t.Enabled = alaye.Active
		if t.Read == 0 {
			t.Read = alaye.Duration(alaye.DefaultReadTimeout)
		}
		if t.Write == 0 {
			t.Write = alaye.Duration(alaye.DefaultWriteTimeout)
		}
		if t.Idle == 0 {
			t.Idle = alaye.Duration(alaye.DefaultIdleTimeout)
		}
		if t.ReadHeader == 0 {
			t.ReadHeader = alaye.Duration(alaye.DefaultReadHeaderTimeout)
		}
	}
}

func defaultStorage(s *alaye.Storage, configPath string) {
	if configPath == "" || configPath == "disabled" || configPath == "." {
		return
	}
	configDir := filepath.Dir(configPath)
	if s.HostsDir == "" {
		s.HostsDir = filepath.Join(configDir, HostDir.String())
	} else if !filepath.IsAbs(s.HostsDir) {
		s.HostsDir = filepath.Join(configDir, s.HostsDir)
	}
	if s.CertsDir == "" {
		s.CertsDir = filepath.Join(configDir, CertDir.String())
	} else if !filepath.IsAbs(s.CertsDir) {
		s.CertsDir = filepath.Join(configDir, s.CertsDir)
	}
	if s.DataDir == "" {
		s.DataDir = filepath.Join(configDir, DataDir.String())
	} else if !filepath.IsAbs(s.DataDir) {
		s.DataDir = filepath.Join(configDir, s.DataDir)
	}
	if s.WorkDir == "" {
		s.WorkDir = filepath.Join(configDir, WorkDir.String())
	} else if !filepath.IsAbs(s.WorkDir) {
		s.WorkDir = filepath.Join(configDir, s.WorkDir)
	}
}

func defaultAdmin(a *alaye.Admin) {
	if a.Enabled == alaye.Unknown && a.Address != "" {
		a.Enabled = alaye.Active
	}
	if a.Enabled == alaye.Active {
		defaultBasicAuth(&a.BasicAuth)
		defaultJWTAuth(&a.JWTAuth)
		defaultForwardAuth(&a.ForwardAuth)
		defaultOAuth(&a.OAuth)
		defaultTelemetry(&a.Telemetry)
	}

	if a.TOTP.Enabled.Active() {

		if a.TOTP.Issuer == "" {
			a.TOTP.Issuer = strings.ToUpper(Name)
		}

		if a.TOTP.Digits == 0 {
			a.TOTP.Digits = 6
		}

		if a.TOTP.Period == 0 {
			a.TOTP.Period = 30
		}

		if a.TOTP.Algorithm == "" {
			a.TOTP.Algorithm = "SHA1"
		}
	}
}

func defaultLogging(l *alaye.Logging) {
	if l.Enabled.Inactive() {
		l.File.Enabled = alaye.Inactive
		l.Victoria.Enabled = alaye.Inactive
		l.Prometheus.Enabled = alaye.Inactive
		return
	}
	if l.Deduplicate == alaye.Unknown {
		l.Deduplicate = alaye.Active
	}
	if l.Truncate == alaye.Unknown {
		l.Truncate = alaye.Active
	}
	if l.BotChecker == alaye.Unknown {
		l.BotChecker = alaye.Active
	}
	hasConfig := l.File.Path != "" || l.Victoria.URL != ""
	if l.Enabled == alaye.Unknown && hasConfig {
		l.Enabled = alaye.Active
	}
	if l.Level == "" {
		l.Level = "info"
	}
	if l.File.Enabled == alaye.Unknown && l.File.Path != "" {
		l.File.Enabled = alaye.Active
	}
	if l.File.BatchSize <= 0 {
		l.File.BatchSize = DefaultVictoriaBatch
	}
	if l.File.RotateSize <= 0 {
		l.File.RotateSize = DefaultLogRotateSize
	}
	if l.Victoria.Enabled == alaye.Unknown && l.Victoria.URL != "" {
		l.Victoria.Enabled = alaye.Active
	}
	if l.Victoria.BatchSize <= 0 {
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
	if s.Enabled == alaye.Unknown && len(s.Firewall.Rules) > 0 {
		s.Enabled = alaye.Active
	}
	defaultFirewall(&s.Firewall)
}

func defaultFirewall(f *alaye.Firewall) {
	if f.Status == alaye.Unknown && len(f.Rules) > 0 {
		f.Status = alaye.Active
	}
	if f.Mode == "" {
		f.Mode = "active"
	}
	if f.MaxInspectBytes == 0 {
		f.MaxInspectBytes = DefaultFirewallMaxInspectBytes
	}
	if len(f.InspectContentTypes) == 0 {
		f.InspectContentTypes = []string{
			"application/json",
			"application/xml",
			"application/x-www-form-urlencoded",
			"text/plain",
		}
	}
	for i := range f.Actions {
		if f.Actions[i].Mitigation == "" {
			f.Actions[i].Mitigation = "add"
		}
	}
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
	hasConfig := len(rl.Policies) > 0 || len(rl.Rules) > 0
	if rl.Enabled == alaye.Unknown && hasConfig {
		rl.Enabled = alaye.Active
	}
	if rl.TTL == 0 {
		rl.TTL = alaye.Duration(DefaultRateLimitTTL)
	}
	if rl.MaxEntries == 0 {
		rl.MaxEntries = DefaultRateLimitMaxEntries
	}
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
	if g.Enabled == alaye.Unknown && (g.Port > 0 || len(g.Seeds) > 0) {
		g.Enabled = alaye.Active
	}
	if g.Enabled == alaye.Active {
		if g.Port == 0 {
			g.Port = alaye.DefaultGossipPort
		}
		if g.TTL == 0 {
			g.TTL = DefaultGossipTTL
		}
	}
}

func defaultLetsEncrypt(le *alaye.LetsEncrypt) {
	if le.Enabled == alaye.Unknown && le.Email != "" {
		le.Enabled = alaye.Active
	}
}

func defaultTLS(t *alaye.TLS, domains []string) {
	if t.Mode == "" && len(domains) > 0 {
		allLocal := true
		for _, d := range domains {
			if !IsLocalContext(d) {
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
	switch t.Mode {
	case alaye.ModeLocalCert:
	case alaye.ModeLetsEncrypt:
		defaultLetsEncrypt(&t.LetsEncrypt)
	case alaye.ModeCustomCA:
		if t.CustomCA.Enabled == alaye.Unknown && t.CustomCA.Root != "" {
			t.CustomCA.Enabled = alaye.Active
		}
	}
}

// defaultLimits applies default values to the Limit configuration block.
// MaxBodySize default is enforced at dispatch level via alaye.DefaultMaxBodySize; add per-field defaults here as alaye.Limit grows.
func defaultLimits(_ *alaye.Limit) {}

func defaultHeaders(h *alaye.Headers) {
	hasOps := len(h.Request.Set) > 0 || len(h.Request.Add) > 0 || len(h.Request.Remove) > 0 ||
		len(h.Response.Set) > 0 || len(h.Response.Add) > 0 || len(h.Response.Remove) > 0
	if h.Enabled == alaye.Unknown && hasOps {
		h.Enabled = alaye.Active
	}
	if h.Request.Enabled == alaye.Unknown && (len(h.Request.Set) > 0 || len(h.Request.Add) > 0 || len(h.Request.Remove) > 0) {
		h.Request.Enabled = alaye.Active
	}
	if h.Response.Enabled == alaye.Unknown && (len(h.Response.Set) > 0 || len(h.Response.Add) > 0 || len(h.Response.Remove) > 0) {
		h.Response.Enabled = alaye.Active
	}
}

func defaultBackend(b *alaye.Backend) {
	if b.Enabled == alaye.Unknown && len(b.Servers) > 0 {
		b.Enabled = alaye.Active
	}
	if b.Strategy == "" && len(b.Servers) > 1 {
		b.Strategy = alaye.StrategyRoundRobin
	}
	for i := range b.Servers {
		if b.Servers[i].Weight == 0 {
			b.Servers[i].Weight = 1
		}
	}
}

func defaultHealthCheck(hc *alaye.HealthCheck) {
	if hc.Enabled == alaye.Unknown && hc.Path != "" {
		hc.Enabled = alaye.Active
	}
	if hc.Enabled == alaye.Active {
		if hc.Interval == 0 {
			hc.Interval = alaye.Duration(alaye.DefaultHealthInterval)
		}
		if hc.Timeout == 0 {
			hc.Timeout = alaye.Duration(alaye.DefaultHealthTimeout)
		}
		if hc.Threshold == 0 {
			hc.Threshold = alaye.DefaultHealthThreshold
		}
		if hc.Method == "" {
			hc.Method = "GET"
		}
	}
}

func defaultCircuitBreaker(cb *alaye.CircuitBreaker) {
	if cb.Enabled == alaye.Unknown && cb.Threshold > 0 {
		cb.Enabled = alaye.Active
	}
	if cb.Enabled == alaye.Active {
		if cb.Threshold == 0 {
			cb.Threshold = alaye.DefaultCircuitBreakerThreshold
		}
		if cb.Duration == 0 {
			cb.Duration = alaye.Duration(alaye.DefaultCircuitBreakerDuration)
		}
	}
}

func defaultTimeoutRoute(t *alaye.TimeoutRoute) {
	if t.Enabled == alaye.Unknown && t.Request > 0 {
		t.Enabled = alaye.Active
	}
}

func defaultCompression(c *alaye.Compression) {
	if c.Enabled == alaye.Unknown && c.Type != "" {
		c.Enabled = alaye.Active
	}
	if c.Enabled == alaye.Active {
		if c.Type == "" {
			c.Type = alaye.CompressionGzip
		}
		if c.Level == 0 {
			c.Level = DefaultCompressionLevel
		}
	}
}

func defaultBasicAuth(ba *alaye.BasicAuth) {
	if ba.Enabled == alaye.Unknown && len(ba.Users) > 0 {
		ba.Enabled = alaye.Active
	}
	if ba.Realm == "" {
		ba.Realm = Realm
	}
}

func defaultJWTAuth(ja *alaye.JWTAuth) {
	if ja.Enabled == alaye.Unknown && ja.Secret != "" {
		ja.Enabled = alaye.Active
	}
}

func defaultForwardAuth(fa *alaye.ForwardAuth) {
	if fa.Enabled == alaye.Unknown && fa.URL != "" {
		fa.Enabled = alaye.Active
	}
	if fa.Enabled == alaye.Active {
		if fa.Timeout == 0 {
			fa.Timeout = alaye.Duration(DefaultForwardAuthTimeout)
		}
		if fa.OnFailure == "" {
			fa.OnFailure = Allow
		}
		if fa.Request.Enabled == alaye.Unknown {
			if len(fa.Request.Headers) > 0 || fa.Request.ForwardMethod || fa.Request.ForwardURI || fa.Request.ForwardIP {
				fa.Request.Enabled = alaye.Active
			}
		}
		if fa.Request.BodyMode == "" {
			fa.Request.BodyMode = "none"
		}
		if fa.Response.Enabled == alaye.Unknown && fa.Response.CacheTTL > 0 {
			fa.Response.Enabled = alaye.Active
		}
	}
}

func defaultOAuth(oa *alaye.OAuth) {
	if oa.Enabled == alaye.Unknown && oa.Provider != "" {
		oa.Enabled = alaye.Active
	}
	if oa.Enabled == alaye.Active {
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
	if p.Enabled == alaye.Unknown && p.Address != "" {
		p.Enabled = alaye.Active
	}
}

func defaultRateLimit(rl *alaye.RouteRate) {
	if rl.Enabled == alaye.Unknown && (rl.UsePolicy != "" || rl.Rule.Requests > 0) {
		rl.Enabled = alaye.Active
	}
	if rl.Rule.Enabled == alaye.Unknown && rl.Rule.Requests > 0 {
		rl.Rule.Enabled = alaye.Active
	}
	if rl.Rule.Burst == 0 && rl.Rule.Requests > 0 {
		rl.Rule.Burst = rl.Rule.Requests
	}
}

func defaultWasm(w *alaye.Wasm) {
	if w.Enabled == alaye.Unknown && w.Module != "" {
		w.Enabled = alaye.Active
	}
}

func defaultFirewallRoute(fr *alaye.FirewallRoute) {
	if fr.Status == alaye.Unknown && len(fr.Rules) > 0 {
		fr.Status = alaye.Active
	}
	for i := range fr.Rules {
		if fr.Rules[i].Name == "" {
			fr.Rules[i].Name = "route_rule_" + strconv.Itoa(i)
		}
	}
}

func defaultTCPRoute(t *alaye.Proxy) {
	if t.Enabled == alaye.Unknown && t.Listen != "" {
		t.Enabled = alaye.Active
	}
	if t.Enabled == alaye.Active {
		if t.Strategy == "" {
			t.Strategy = alaye.StrategyRoundRobin
		}
		for i := range t.Backends {
			if t.Backends[i].Weight == 0 {
				t.Backends[i].Weight = 1
			}
		}
		defaultTCPHealthCheck(&t.HealthCheck)
	}
}

func defaultTCPHealthCheck(thc *alaye.TCPHealthCheck) {
	if thc.Enabled == alaye.Unknown && (thc.Send != "" || thc.Expect != "") {
		thc.Enabled = alaye.Active
	}
	if thc.Enabled == alaye.Active {
		if thc.Interval == 0 {
			thc.Interval = alaye.Duration(TCPHealthCheckInterval)
		}
		if thc.Timeout == 0 {
			thc.Timeout = alaye.Duration(TCPHealthCheckTimeout)
		}
	}
}

func defaultFallback(f *alaye.Fallback) {
	if f.Enabled == alaye.Unknown {
		f.Enabled = alaye.Inactive
	}
	if f.Enabled.Active() {
		if f.Type == "" {
			f.Type = "static"
		}
		if f.StatusCode == 0 {
			switch f.Type {
			case "redirect":
				f.StatusCode = DefaultFallbackRedirectCode
			case "proxy":
				f.StatusCode = DefaultFallbackProxyCode
			default:
				f.StatusCode = DefaultFallbackStaticCode
			}
		}
		if f.ContentType == "" && f.Type == "static" {
			f.ContentType = MimeJSON
		}
	}
}

func defaultCORS(c *alaye.CORS) {
	if c.Enabled.NotActive() {
		if len(c.AllowedOrigins) > 0 {
			c.Enabled = alaye.Active
		} else {
			return
		}
	}
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = []string{"*"}
	}
	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	if len(c.AllowedHeaders) == 0 {
		c.AllowedHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"}
	}
	if c.MaxAge == 0 {
		c.MaxAge = DefaultCORSMaxAge
	}
}

func defaultCache(c *alaye.Cache) {
	if c.Enabled.NotActive() {
		return
	}
	if c.TTL == 0 {
		c.TTL = alaye.Duration(DefaultCacheTTL)
	}
	if len(c.Methods) == 0 {
		c.Methods = []string{"GET", "HEAD"}
	}
	if c.Driver == "" {
		c.Driver = "memory"
	}
	if c.Driver == "memory" && c.Memory == nil {
		c.Memory = &alaye.MemoryCache{MaxItems: DefaultCacheMaxItems}
	}
	if c.Driver == "redis" && c.Redis == nil {
		c.Redis = &alaye.RedisCache{Host: LocalhostIPv4, Port: DefaultRedisPort}
	}
}

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

func defaultTelemetry(t *alaye.Telemetry) {

	if t.Enabled == alaye.Unknown {
		t.Enabled = alaye.Inactive
	}
}
