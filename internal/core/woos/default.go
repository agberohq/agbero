package woos

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
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

	if h.Protected == expect.Unknown {
		h.Protected = expect.Inactive
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
	if g.Bind.Redirect == expect.Unknown && len(g.Bind.HTTPS) > 0 {
		g.Bind.Redirect = expect.Active
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
	if r.Enabled == expect.Unknown {
		r.Enabled = expect.Active
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
	if r.Web.Enabled == expect.Unknown {
		r.Web.Enabled = expect.Active
	}
	if len(r.Web.Index) == 0 {
		r.Web.Index = []string{"index.html"}
	}
	defaultPHP(&r.Web.PHP)
	defaultCompression(&r.Compression)
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
	defaultCompression(&r.Compression)
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
	if t.Enabled == expect.Unknown && hasAnyTimeout {
		t.Enabled = expect.Active
	}
	if t.Enabled == expect.Active || t.Enabled == expect.Unknown {
		t.Enabled = expect.Active
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
	configDir := expect.NewFolder(configPath)

	// resolve returns an expect.Folder with the final path
	resolve := func(field expect.Folder, defaultSub string) expect.Folder {
		if !field.IsSet() {
			return configDir.Sub(defaultSub)
		}
		if filepath.IsAbs(field.String()) {
			return field
		}
		return configDir.Sub(field)
	}

	s.HostsDir = resolve(s.HostsDir, HostDir)
	s.CertsDir = resolve(s.CertsDir, CertDir)
	s.DataDir = resolve(s.DataDir, DataDir)
	s.WorkDir = resolve(s.WorkDir, WorkDir)
}

func defaultAdmin(a *alaye.Admin) {
	if a.Enabled == expect.Unknown && a.Address != "" {
		a.Enabled = expect.Active
	}
	if a.Enabled == expect.Active {
		// defaultBasicAuth(&a.BasicAuth)
		// defaultJWTAuth(&a.JWTAuth)
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
		l.File.Enabled = expect.Inactive
		l.Victoria.Enabled = expect.Inactive
		l.Prometheus.Enabled = expect.Inactive
		return
	}
	if l.Deduplicate == expect.Unknown {
		l.Deduplicate = expect.Active
	}
	if l.Truncate == expect.Unknown {
		l.Truncate = expect.Active
	}
	if l.BotChecker == expect.Unknown {
		l.BotChecker = expect.Active
	}
	hasConfig := l.File.Path != "" || l.Victoria.URL != ""
	if l.Enabled == expect.Unknown && hasConfig {
		l.Enabled = expect.Active
	}
	if l.Level == "" {
		l.Level = "info"
	}
	if l.File.Enabled == expect.Unknown && l.File.Path != "" {
		l.File.Enabled = expect.Active
	}
	if l.File.BatchSize <= 0 {
		l.File.BatchSize = DefaultVictoriaBatch
	}
	if l.File.RotateSize <= 0 {
		l.File.RotateSize = DefaultLogRotateSize
	}
	if l.Victoria.Enabled == expect.Unknown && l.Victoria.URL != "" {
		l.Victoria.Enabled = expect.Active
	}
	if l.Victoria.BatchSize <= 0 {
		l.Victoria.BatchSize = DefaultVictoriaBatch
	}
	if l.Prometheus.Enabled == expect.Unknown {
		l.Prometheus.Enabled = expect.Inactive
	}
	if l.Prometheus.Path == "" {
		l.Prometheus.Path = "/metrics"
	}
}

func defaultSecurity(s *alaye.Security) {
	if s.Enabled == expect.Unknown && len(s.Firewall.Rules) > 0 {
		s.Enabled = expect.Active
	}
	defaultFirewall(&s.Firewall)
}

func defaultFirewall(f *alaye.Firewall) {
	if f.Status == expect.Unknown && len(f.Rules) > 0 {
		f.Status = expect.Active
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
	if rl.Enabled == expect.Unknown && hasConfig {
		rl.Enabled = expect.Active
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
	if g.Enabled == expect.Unknown && (g.Port > 0 || len(g.Seeds) > 0) {
		g.Enabled = expect.Active
	}
	if g.Enabled == expect.Active {
		if g.Port == 0 {
			g.Port = alaye.DefaultGossipPort
		}
		if g.TTL == 0 {
			g.TTL = DefaultGossipTTL
		}
	}
}

func defaultLetsEncrypt(le *alaye.LetsEncrypt) {
	if le.Enabled == expect.Unknown && le.Email != "" {
		le.Enabled = expect.Active
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
		if t.CustomCA.Enabled == expect.Unknown && t.CustomCA.Root != "" {
			t.CustomCA.Enabled = expect.Active
		}
	}
}

// defaultLimits applies default values to the Limit configuration block.
// MaxBodySize default is enforced at dispatch level via alaye.DefaultMaxBodySize; add per-field defaults here as alaye.Limit grows.
func defaultLimits(_ *alaye.Limit) {}

func defaultHeaders(h *alaye.Headers) {
	hasOps := len(h.Request.Set) > 0 || len(h.Request.Add) > 0 || len(h.Request.Remove) > 0 ||
		len(h.Response.Set) > 0 || len(h.Response.Add) > 0 || len(h.Response.Remove) > 0
	if h.Enabled == expect.Unknown && hasOps {
		h.Enabled = expect.Active
	}
	if h.Request.Enabled == expect.Unknown && (len(h.Request.Set) > 0 || len(h.Request.Add) > 0 || len(h.Request.Remove) > 0) {
		h.Request.Enabled = expect.Active
	}
	if h.Response.Enabled == expect.Unknown && (len(h.Response.Set) > 0 || len(h.Response.Add) > 0 || len(h.Response.Remove) > 0) {
		h.Response.Enabled = expect.Active
	}
}

func defaultBackend(b *alaye.Backend) {
	if b.Enabled == expect.Unknown && len(b.Servers) > 0 {
		b.Enabled = expect.Active
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
	if hc.Enabled == expect.Unknown && hc.Path != "" {
		hc.Enabled = expect.Active
	}
	if hc.Enabled == expect.Active {
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
	if cb.Enabled == expect.Unknown && cb.Threshold > 0 {
		cb.Enabled = expect.Active
	}
	if cb.Enabled == expect.Active {
		if cb.Threshold == 0 {
			cb.Threshold = alaye.DefaultCircuitBreakerThreshold
		}
		if cb.Duration == 0 {
			cb.Duration = alaye.Duration(alaye.DefaultCircuitBreakerDuration)
		}
	}
}

func defaultTimeoutRoute(t *alaye.TimeoutRoute) {
	if t.Enabled == expect.Unknown && t.Request > 0 {
		t.Enabled = expect.Active
	}
}

func defaultCompression(c *alaye.Compression) {
	if c.Enabled == expect.Unknown && c.Type != "" {
		c.Enabled = expect.Active
	}
	if c.Enabled == expect.Active {
		if c.Type == "" {
			c.Type = alaye.CompressionGzip
		}
		if c.Level == 0 {
			c.Level = DefaultCompressionLevel
		}
	}
}

func defaultBasicAuth(ba *alaye.BasicAuth) {
	if ba.Enabled == expect.Unknown && len(ba.Users) > 0 {
		ba.Enabled = expect.Active
	}
	if ba.Realm == "" {
		ba.Realm = Realm
	}
}

func defaultJWTAuth(ja *alaye.JWTAuth) {
	if ja.Enabled == expect.Unknown && ja.Secret != "" {
		ja.Enabled = expect.Active
	}
}

func defaultForwardAuth(fa *alaye.ForwardAuth) {
	if fa.Enabled == expect.Unknown && fa.URL != "" {
		fa.Enabled = expect.Active
	}
	if fa.Enabled == expect.Active {
		if fa.Timeout == 0 {
			fa.Timeout = alaye.Duration(DefaultForwardAuthTimeout)
		}
		if fa.OnFailure == "" {
			fa.OnFailure = Allow
		}
		if fa.Request.Enabled == expect.Unknown {
			if len(fa.Request.Headers) > 0 || fa.Request.ForwardMethod || fa.Request.ForwardURI || fa.Request.ForwardIP {
				fa.Request.Enabled = expect.Active
			}
		}
		if fa.Request.BodyMode == "" {
			fa.Request.BodyMode = "none"
		}
		if fa.Response.Enabled == expect.Unknown && fa.Response.CacheTTL > 0 {
			fa.Response.Enabled = expect.Active
		}
	}
}

func defaultOAuth(oa *alaye.OAuth) {
	if oa.Enabled == expect.Unknown && oa.Provider != "" {
		oa.Enabled = expect.Active
	}
	if oa.Enabled == expect.Active {
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
	if p.Enabled == expect.Unknown && p.Address != "" {
		p.Enabled = expect.Active
	}
}

func defaultRateLimit(rl *alaye.RouteRate) {
	if rl.Enabled == expect.Unknown && (rl.UsePolicy != "" || rl.Rule.Requests > 0) {
		rl.Enabled = expect.Active
	}
	if rl.Rule.Enabled == expect.Unknown && rl.Rule.Requests > 0 {
		rl.Rule.Enabled = expect.Active
	}
	if rl.Rule.Burst == 0 && rl.Rule.Requests > 0 {
		rl.Rule.Burst = rl.Rule.Requests
	}
}

func defaultWasm(w *alaye.Wasm) {
	if w.Enabled == expect.Unknown && w.Module != "" {
		w.Enabled = expect.Active
	}
}

func defaultFirewallRoute(fr *alaye.FirewallRoute) {
	if fr.Status == expect.Unknown && len(fr.Rules) > 0 {
		fr.Status = expect.Active
	}
	for i := range fr.Rules {
		if fr.Rules[i].Name == "" {
			fr.Rules[i].Name = "route_rule_" + strconv.Itoa(i)
		}
	}
}

func defaultTCPRoute(t *alaye.Proxy) {
	if t.Enabled == expect.Unknown && t.Listen != "" {
		t.Enabled = expect.Active
	}
	if t.Enabled == expect.Active {
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
	if thc.Enabled == expect.Unknown && (thc.Send != "" || thc.Expect != "") {
		thc.Enabled = expect.Active
	}
	if thc.Enabled == expect.Active {
		if thc.Interval == 0 {
			thc.Interval = alaye.Duration(TCPHealthCheckInterval)
		}
		if thc.Timeout == 0 {
			thc.Timeout = alaye.Duration(TCPHealthCheckTimeout)
		}
	}
}

func defaultFallback(f *alaye.Fallback) {
	if f.Enabled == expect.Unknown {
		f.Enabled = expect.Inactive
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
			c.Enabled = expect.Active
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

	if t.Enabled == expect.Unknown {
		t.Enabled = expect.Inactive
	}
}
