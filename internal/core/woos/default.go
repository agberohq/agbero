package woos

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

type Defaults struct{}

var D = Defaults{}

func (Defaults) Global(g *alaye.Global, configPath string) {
	defaultGlobal(g, configPath)
}

func (Defaults) Host(h *alaye.Host) {

	if h.Protected == expect.Unknown {
		h.Protected = expect.Inactive
	}

	if len(h.Routes) > 0 {
		defaultTLS(&h.TLS, h.Domains)
	}
	defaultLimits(&h.Limits)
	defaultHeaders(&h.Headers)
	for i := range h.Routes {
		defaultRouteAll(&h.Routes[i])
	}
	for i := range h.Proxies {
		if h.Proxies[i].IsUDP() {
			defaultUDPProxy(&h.Proxies[i])
		} else {
			defaultTCPRoute(&h.Proxies[i])
		}
	}
}

func (Defaults) Route(r *alaye.Route) {
	defaultRouteAll(r)
}

func (Defaults) Firewall(f *alaye.Firewall) {
	defaultFirewall(f)
}

func (Defaults) Cache(c *alaye.Cache) {
	defaultCache(c)
}

func (Defaults) BasicAuth(ba *alaye.BasicAuth) {
	defaultBasicAuth(ba)
}

func (Defaults) ForwardAuth(fa *alaye.ForwardAuth) {
	defaultForwardAuth(fa)
}

func (Defaults) CORS(c *alaye.CORS) {
	defaultCORS(c)
}

func (Defaults) Compression(c *alaye.Compression) {
	defaultCompression(c)
}

func (Defaults) RateLimit(rl *alaye.RateRoute) {
	defaultRateLimit(rl)
}

func (Defaults) Wasm(w *alaye.Wasm) {
	defaultWasm(w)
}

func (Defaults) HealthCheck(hc *alaye.HealthCheck) {
	defaultHealthCheck(hc)
}

func DefaultApply(g *alaye.Global, configPath string) {
	D.Global(g, configPath)
}

func DefaultHost(h *alaye.Host) {
	D.Host(h)
}

func DefaultRoute(r *alaye.Route) {
	D.Route(r)
}

func defaultGlobal(g *alaye.Global, configPath string) {
	if g.Version == 0 {
		g.Version = def.ConfigFormatVersion
	}
	if g.General.MaxHeaderBytes == 0 {
		g.General.MaxHeaderBytes = def.DefaultMaxHeaderBytes
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
	hasServerless := r.Serverless.Enabled.Active()
	if hasWeb {
		defaultWebRoute(r)
	} else if hasBackends {
		defaultProxyRoute(r)
	}
	if hasServerless {
		defaultServerless(&r.Serverless)
	}
	defaultCORS(&r.CORS)
	defaultCache(&r.Cache)
	defaultFallback(&r.Fallback)
}

func defaultWebRoute(r *alaye.Route) {
	if r.Web.Enabled == expect.Unknown {
		r.Web.Enabled = expect.Active
	}
	defaultGit(&r.Web.Git)
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
			t.Read = expect.Duration(def.DefaultReadTimeout)
		}
		if t.Write == 0 {
			t.Write = expect.Duration(def.DefaultWriteTimeout)
		}
		if t.Idle == 0 {
			t.Idle = expect.Duration(def.DefaultIdleTimeout)
		}
		if t.ReadHeader == 0 {
			t.ReadHeader = expect.Duration(def.DefaultReadHeaderTimeout)
		}
	}
}

func defaultStorage(s *alaye.Storage, configPath string) {
	if configPath == "" || configPath == "disabled" || configPath == "." {
		return
	}
	configDir := expect.NewFolder(filepath.Dir(configPath))

	resolve := func(field expect.Folder, defaultSub string) expect.Folder {
		if !field.IsSet() {
			return configDir.Sub(defaultSub)
		}
		if filepath.IsAbs(field.String()) {
			return field
		}
		return configDir.Sub(field)
	}

	s.HostsDir = resolve(s.HostsDir, def.HostDir)
	s.CertsDir = resolve(s.CertsDir, def.CertDir)
	s.DataDir = resolve(s.DataDir, def.DataDir)
	s.WorkDir = resolve(s.WorkDir, def.WorkDir)
}

func defaultAdmin(a *alaye.Admin) {
	if a.Enabled == expect.Unknown && a.Address != "" {
		a.Enabled = expect.Active
	}
	if a.Enabled == expect.Active {

		defaultForwardAuth(&a.ForwardAuth)
		defaultOAuth(&a.OAuth)
		defaultTelemetry(&a.Telemetry)
	}

	if a.TOTP.Enabled.Active() {

		if a.TOTP.Issuer == "" {
			a.TOTP.Issuer = strings.ToUpper(def.Name)
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
		l.File.BatchSize = def.DefaultVictoriaBatch
	}
	if l.File.RotateSize <= 0 {
		l.File.RotateSize = def.DefaultLogRotateSize
	}
	if l.Victoria.Enabled == expect.Unknown && l.Victoria.URL != "" {
		l.Victoria.Enabled = expect.Active
	}
	if l.Victoria.BatchSize <= 0 {
		l.Victoria.BatchSize = def.DefaultVictoriaBatch
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
	defaultAllow(&s.Allow)
}

func defaultAllow(s *alaye.Allow) {
	if len(s.Commands) == 0 {
		s.Commands = []string{"echo"}
	}
}

func defaultFirewall(f *alaye.Firewall) {
	if f.Status == expect.Unknown && len(f.Rules) > 0 {
		f.Status = expect.Active
	}
	if f.Mode == "" {
		f.Mode = "active"
	}
	if f.MaxInspectBytes == 0 {
		f.MaxInspectBytes = def.DefaultFirewallMaxInspectBytes
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

func defaultRateLimits(rl *alaye.RateGlobal) {
	hasConfig := len(rl.Policies) > 0 || len(rl.Rules) > 0
	if rl.Enabled == expect.Unknown && hasConfig {
		rl.Enabled = expect.Active
	}
	if rl.TTL == 0 {
		rl.TTL = expect.Duration(def.DefaultRateLimitTTL)
	}
	if rl.MaxEntries == 0 {
		rl.MaxEntries = def.DefaultRateLimitMaxEntries
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
			g.Port = def.DefaultGossipPort
		}
		if g.TTL == 0 {
			g.TTL = def.DefaultGossipTTL
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
			t.Mode = def.ModeLocalAuto
		} else {
			t.Mode = def.ModeLetsEncrypt
		}
	}
	switch t.Mode {
	case def.ModeLocalCert:
	case def.ModeLetsEncrypt:
		defaultLetsEncrypt(&t.LetsEncrypt)
	case def.ModeCustomCA:
		if t.CustomCA.Enabled == expect.Unknown && t.CustomCA.Root != "" {
			t.CustomCA.Enabled = expect.Active
		}
	}
}

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
		b.Strategy = def.StrategyRoundRobin
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
			hc.Interval = expect.Duration(def.DefaultHealthInterval)
		}
		if hc.Timeout == 0 {
			hc.Timeout = expect.Duration(def.DefaultHealthTimeout)
		}
		if hc.Threshold == 0 {
			hc.Threshold = def.DefaultHealthThreshold
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
			cb.Threshold = def.DefaultCircuitBreakerThreshold
		}
		if cb.Duration == 0 {
			cb.Duration = expect.Duration(def.DefaultCircuitBreakerDuration)
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
			c.Type = def.CompressionGzip
		}
		if c.Level == 0 {
			c.Level = def.DefaultCompressionLevel
		}
	}
}

func defaultBasicAuth(ba *alaye.BasicAuth) {
	if ba.Enabled == expect.Unknown && len(ba.Users) > 0 {
		ba.Enabled = expect.Active
	}
	if ba.Realm == "" {
		ba.Realm = def.Realm
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
			fa.Timeout = expect.Duration(def.DefaultForwardAuthTimeout)
		}
		if fa.OnFailure == "" {
			fa.OnFailure = def.Allow
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
			case def.ProviderGoogle, def.ProviderOIDC:
				oa.Scopes = []string{def.ScopeOpenID, def.ScopeProfile, def.ScopeEmail}
			case def.ProviderGitHub:
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

func defaultRateLimit(rl *alaye.RateRoute) {
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
			t.Strategy = def.StrategyRoundRobin
		}
		for i := range t.Backends {
			if t.Backends[i].Enabled == expect.Unknown {
				t.Backends[i].Enabled = expect.Active
			}
			if t.Backends[i].Weight == 0 {
				t.Backends[i].Weight = 1
			}
		}
		defaultTCPHealthCheck(&t.HealthCheck)
	}
}

func defaultUDPProxy(t *alaye.Proxy) {
	if t.Enabled == expect.Unknown && t.Listen != "" {
		t.Enabled = expect.Active
	}
	if t.Enabled == expect.Active {
		if t.Strategy == "" {
			t.Strategy = def.StrategyRoundRobin
		}

		if t.SessionTTL == 0 {
			t.SessionTTL = expect.Duration(def.UDPDefaultSessionTTL)
		}
		if t.MaxSessions == 0 {
			t.MaxSessions = def.UDPDefaultMaxSessions
		}
		for i := range t.Backends {
			if t.Backends[i].Enabled == expect.Unknown {
				t.Backends[i].Enabled = expect.Active
			}
			if t.Backends[i].Weight == 0 {
				t.Backends[i].Weight = 1
			}
		}
		defaultUDPHealthCheck(&t.HealthCheck)
	}
}

func defaultUDPHealthCheck(thc *alaye.HealthCheckProtocol) {

	if thc.Enabled == expect.Unknown && (!thc.Send.Empty() || !thc.Expect.Empty()) {
		thc.Enabled = expect.Active
	}
	if thc.Enabled == expect.Active {
		if thc.Interval == 0 {
			thc.Interval = expect.Duration(def.UDPHealthCheckInterval)
		}
		if thc.Timeout == 0 {
			thc.Timeout = expect.Duration(def.UDPHealthCheckTimeout)
		}
	}
}

func defaultTCPHealthCheck(thc *alaye.HealthCheckProtocol) {
	if thc.Enabled == expect.Unknown && (!thc.Send.Empty() || !thc.Expect.Empty()) {
		thc.Enabled = expect.Active
	}
	if thc.Enabled == expect.Active {
		if thc.Interval == 0 {
			thc.Interval = expect.Duration(def.TCPHealthCheckInterval)
		}
		if thc.Timeout == 0 {
			thc.Timeout = expect.Duration(def.TCPHealthCheckTimeout)
		}
	}
}

func defaultServerless(s *alaye.Serverless) {
	defaultGit(&s.Git)
	for i := range s.Replay {
		defaultReplay(&s.Replay[i])
	}
	for i := range s.Workers {
		defaultWorker(&s.Workers[i])
	}
}

func defaultWorker(w *alaye.Work) {

	if w.Enabled == expect.Unknown {
		w.Enabled = expect.Active
	}

	if w.Timeout == 0 {
		w.Timeout = expect.Duration(def.DefaultWorkerTimeout)
	}

	if w.Landlock == expect.Unknown {
		w.Landlock = expect.Active
	}

	if w.Background && w.Restart == "" {
		w.Restart = def.DefaultWorkerRestart
	}

	if w.Cache.Enabled.Active() && w.Cache.Driver == "" {
		w.Cache.Driver = "memory"
	}
}

func defaultGit(g *alaye.Git) {
	if g.Enabled == expect.Unknown && g.URL != "" {
		g.Enabled = expect.Active
	}
	if g.Enabled.NotActive() {
		return
	}
	if g.Branch == "" {
		g.Branch = "main"
	}
	hasPull := g.Interval > 0
	hasPush := g.Secret.String() != ""
	switch {
	case hasPull && hasPush:
		g.Mode = def.GitModeBoth
	case hasPush:
		g.Mode = def.GitModePush
	case hasPull:
		g.Mode = def.GitModePull
	}
}

func defaultReplay(r *alaye.Replay) {

	if r.Enabled == expect.Unknown && (r.URL != "" || len(r.AllowedDomains) > 0) {
		r.Enabled = expect.Active
	}
	if r.Enabled == expect.Active {

		if r.Timeout == 0 {
			r.Timeout = expect.Duration(def.DefaultReplayTimeout)
		}

		if r.RefererMode == "" {
			r.RefererMode = "auto"
		}

		if r.Cache.Enabled.Active() && r.Cache.Driver == "" {
			r.Cache.Driver = "memory"
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
				f.StatusCode = def.DefaultFallbackRedirectCode
			case "proxy":
				f.StatusCode = def.DefaultFallbackProxyCode
			default:
				f.StatusCode = def.DefaultFallbackStaticCode
			}
		}
		if f.ContentType == "" && f.Type == "static" {
			f.ContentType = def.MimeJSON
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
		c.MaxAge = def.DefaultCORSMaxAge
	}
}

func defaultCache(c *alaye.Cache) {
	if c.Enabled.NotActive() {
		return
	}
	if c.TTL == 0 {
		c.TTL = expect.Duration(def.DefaultCacheTTL)
	}
	if len(c.Methods) == 0 {
		c.Methods = []string{"GET", "HEAD"}
	}
	if c.Driver == "" {
		c.Driver = "memory"
	}
	if c.Driver == "memory" && c.Memory == nil {
		c.Memory = &alaye.MemoryCache{MaxItems: def.DefaultCacheMaxItems}
	}
	if c.Driver == "redis" && c.Redis == nil {
		c.Redis = &alaye.RedisCache{Host: def.LocalhostIPv4, Port: def.DefaultRedisPort}
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
