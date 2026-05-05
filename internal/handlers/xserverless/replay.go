package xserverless

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/middleware/nonce"
	"github.com/agberohq/agbero/internal/pkg/stash"
)

const (
	defaultRESTTimeout = 30 * time.Second
)

var upstreamHeadersToStrip = map[string]struct{}{
	"access-control-allow-origin":         {},
	"access-control-allow-credentials":    {},
	"access-control-allow-headers":        {},
	"access-control-allow-methods":        {},
	"access-control-expose-headers":       {},
	"access-control-max-age":              {},
	"content-security-policy":             {},
	"content-security-policy-report-only": {},
	"x-frame-options":                     {},
	"x-content-type-options":              {},
	"x-xss-protection":                    {},
	"strict-transport-security":           {},
	"x-permitted-cross-domain-policies":   {},
}

type ReplayConfig struct {
	Resource   *resource.Resource
	Replay     alaye.Replay
	GlobalEnv  map[string]expect.Value
	RouteEnv   map[string]expect.Value
	NonceStore *nonce.Store
	Domain     string
	Route      alaye.Route
}

type Replay struct {
	res        *resource.Resource
	cfg        alaye.Replay
	globalEnv  map[string]expect.Value
	routeEnv   map[string]expect.Value
	client     *http.Client
	methods    []string
	nonceStore *nonce.Store
	cacheStore stash.Store
	statsKey   alaye.Key
}

func NewReplay(cfg ReplayConfig) *Replay {
	timeout := cfg.Replay.Timeout.StdDuration()
	if timeout <= 0 {
		timeout = defaultRESTTimeout
	}

	r := &Replay{
		res:        cfg.Resource,
		cfg:        cfg.Replay,
		globalEnv:  cfg.GlobalEnv,
		routeEnv:   cfg.RouteEnv,
		methods:    cfg.Replay.NormalisedMethods(),
		nonceStore: cfg.NonceStore,
		client:     &http.Client{Timeout: timeout},
	}

	if cfg.Replay.Cache.Enabled.Active() {
		maxItems := def.DefaultCacheMaxItems
		if cfg.Replay.Cache.Memory != nil && cfg.Replay.Cache.Memory.MaxItems > 0 {
			maxItems = cfg.Replay.Cache.Memory.MaxItems
		}

		storeCfg := &stash.Config{
			Driver:     cfg.Replay.Cache.Driver,
			DefaultTTL: cfg.Replay.Cache.TTL.StdDuration(),
			MaxItems:   maxItems,
			Redis:      cfg.Replay.Cache.Redis,
			Policy:     &cfg.Replay.Cache.TTLPolicy,
		}

		store, err := stash.NewStore(storeCfg)
		if err != nil {
			cfg.Resource.Logger.Fields("error", err).Error("serverless: failed to create cache store")
		} else {
			r.cacheStore = store
		}
	}

	r.statsKey = cfg.Route.KeyReplay(cfg.Domain, cfg.Replay.Name)
	// Pre-register so the key exists in metrics even before first request
	cfg.Resource.Metrics.GetOrRegister(r.statsKey)

	return r
}

func (h *Replay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cfg.IsReplayMode() && h.cfg.Auth.Enabled.Active() {
		var guard *nonce.Guard
		switch h.cfg.Auth.Method {
		case "meta":
			if h.nonceStore == nil {
				http.Error(w, "replay: nonce store not initialised", http.StatusInternalServerError)
				return
			}
			guard = nonce.NewMetaGuard(h.nonceStore)
		case "token":
			verifier := func(tok string) bool {
				secret := h.cfg.Auth.Secret.String()
				if secret == "" || tok == "" {
					return false
				}
				return subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1
			}
			guard = nonce.NewTokenGuard(verifier)
		case "direct":
			guard = nonce.NewDirectGuard()
		}
		if guard != nil {
			handled := false
			guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handled = true
				h.dispatch(w, r)
			})).ServeHTTP(w, r)
			if !handled {
				return
			}
			return
		}
	}
	h.dispatch(w, r)
}

func (h *Replay) dispatch(w http.ResponseWriter, r *http.Request) {
	if !h.methodAllowed(r.Method) {
		allowed := strings.Join(h.methods, ", ")
		w.Header().Set("Allow", allowed)
		h.res.Logger.Fields("replay", h.cfg.Name, "method", r.Method, "allowed", allowed, "remote", r.RemoteAddr).Warn("serverless: method not allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	h.res.Logger.Fields("replay", h.cfg.Name, "method", r.Method, "remote", r.RemoteAddr, "path", r.URL.Path).Debug("serverless: replay dispatch")

	if h.cfg.IsReplayMode() {
		h.serveReplay(w, r)
	} else {
		h.serveFixed(w, r)
	}
}

func (h *Replay) serveFixed(w http.ResponseWriter, r *http.Request) {
	targetURL, err := url.Parse(h.cfg.URL)
	if err != nil {
		h.res.Logger.Fields("url", h.cfg.URL, "err", err).Error("serverless: invalid rest url")
		http.Error(w, "Invalid Target URL", http.StatusInternalServerError)
		return
	}

	h.prepareURL(targetURL, r.URL.Query())

	method := h.cfg.UpstreamMethod(r.Method)
	proxyReq, err := http.NewRequestWithContext(r.Context(), method, targetURL.String(), r.Body)
	if err != nil {
		h.res.Logger.Fields("err", err).Error("serverless: failed to create rest request")
		http.Error(w, "Request Initialization Failed", http.StatusInternalServerError)
		return
	}

	h.prepareHeaders(proxyReq.Header)
	h.doProxyWithCache(w, r, proxyReq, false, time.Now())
}

func (h *Replay) serveReplay(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	rawURL := r.Header.Get(def.HeaderXAgberoReplayURL)
	if rawURL == "" {
		rawURL = r.URL.Query().Get("url")
	}
	if rawURL == "" {
		h.res.Logger.Fields("replay", h.cfg.Name, "remote", r.RemoteAddr).Warn("serverless: replay missing target url")
		http.Error(w, "replay: missing target url — set X-Agbero-Replay-Url header or ?url= param", http.StatusBadRequest)
		return
	}

	h.res.Logger.Fields("replay", h.cfg.Name, "method", r.Method, "target", rawURL, "remote", r.RemoteAddr).Info("serverless: replay request")

	targetURL, err := url.Parse(rawURL)
	if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		http.Error(w, "replay: invalid target url", http.StatusBadRequest)
		return
	}

	if err := h.validateTargetHost(targetURL.Hostname()); err != nil {
		h.res.Logger.Fields("host", targetURL.Hostname(), "err", err).Warn("serverless: target host validation failed")
		http.Error(w, "replay: target host validation failed", http.StatusForbidden)
		return
	}

	h.prepareURL(targetURL, r.URL.Query())

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		h.res.Logger.Fields("err", err).Error("serverless: failed to create replay request")
		http.Error(w, "Request Initialization Failed", http.StatusInternalServerError)
		return
	}

	forwardSafeHeaders(proxyReq.Header, r.Header)
	h.prepareHeaders(proxyReq.Header)

	h.setReferer(proxyReq, targetURL, r.Header.Get("Referer"))

	strip := h.cfg.StripHeaders.Active()
	h.doProxyWithCache(w, r, proxyReq, strip, start)
}

func (h *Replay) setReferer(proxyReq *http.Request, targetURL *url.URL, incomingReferer string) {
	mode := strings.ToLower(strings.TrimSpace(h.cfg.RefererMode))
	if mode == "" {
		mode = "auto"
	}

	switch mode {
	case "auto":
		proxyReq.Header.Set("Referer", targetURL.Scheme+"://"+targetURL.Host+"/")
	case "fixed":
		if h.cfg.RefererValue != "" {
			proxyReq.Header.Set("Referer", h.cfg.RefererValue)
		}
	case "forward":
		if incomingReferer != "" {
			proxyReq.Header.Set("Referer", incomingReferer)
		}
	case "none":
		proxyReq.Header.Del("Referer")
	}
}

func (h *Replay) doProxyWithCache(w http.ResponseWriter, r *http.Request, proxyReq *http.Request, strip bool, start time.Time) {
	activity := h.res.Metrics.GetOrRegister(h.statsKey).Activity
	activity.StartRequest()
	failed := false
	defer func() {
		activity.EndRequest(time.Since(start).Microseconds(), failed)
	}()

	shouldCache := h.shouldCacheRequest(r)
	var cacheKey string

	if shouldCache && h.cacheStore != nil {
		cacheKey = stash.Key(r, h.cfg.Cache.TTLPolicy.KeyScope)

		if entry, ok := h.cacheStore.Get(cacheKey); ok {
			h.res.Logger.Fields("cache_key", cacheKey[:min(20, len(cacheKey))]).Debug("serverless: cache hit")

			for k, vv := range entry.Headers {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-Cache-Status", "HIT")
			w.WriteHeader(entry.Status)
			w.Write(entry.Body)
			return
		}
		h.res.Logger.Fields("cache_key", cacheKey[:min(20, len(cacheKey))]).Debug("serverless: cache miss")
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		failed = true
		h.res.Logger.Fields("url", proxyReq.URL.String(), "err", err).Error("serverless: upstream call failed")
		http.Error(w, "Upstream Service Unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var body []byte
	if shouldCache && resp.StatusCode == http.StatusOK {

		cc := resp.Header.Get("Cache-Control")
		if strings.Contains(cc, "no-store") {

			shouldCache = false
		} else {
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				h.res.Logger.Fields("err", err).Error("serverless: failed to read response body")
				http.Error(w, "Upstream Error", http.StatusBadGateway)
				return
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	if body == nil {
		defer func() {
			io.Copy(io.Discard, resp.Body)
		}()
	}

	for k, vv := range resp.Header {
		lower := strings.ToLower(k)
		if strip {
			if _, blocked := upstreamHeadersToStrip[lower]; blocked {
				continue
			}
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	if strip {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if shouldCache {
		w.Header().Set("X-Cache-Status", "MISS")
	}

	if resp.StatusCode >= 500 {
		failed = true
	}
	h.res.Logger.Fields("replay", h.cfg.Name, "target", proxyReq.URL.Host, "status", resp.StatusCode, "duration", time.Since(start)).Info("serverless: replay done")

	w.WriteHeader(resp.StatusCode)
	if body != nil {
		w.Write(body)
	} else {
		io.Copy(w, resp.Body)
	}

	if shouldCache && resp.StatusCode == http.StatusOK && body != nil && h.cacheStore != nil {
		entry := &stash.Entry{
			Body:        body,
			Headers:     resp.Header.Clone(),
			Status:      resp.StatusCode,
			CreatedAt:   time.Now(),
			StoredAt:    time.Now(),
			ContentType: resp.Header.Get("Content-Type"),
		}
		ttl := h.getTTLForResponse(entry.ContentType)
		if ttl > 0 {
			h.cacheStore.Set(cacheKey, entry, ttl)
			w.Header().Set("X-Cache-Status", "MISS,STORED")
		}
	}
}

func (h *Replay) shouldCacheRequest(r *http.Request) bool {
	if h.cacheStore == nil || !h.cfg.Cache.Enabled.Active() {
		return false
	}

	if r.Method != http.MethodGet {
		return false
	}

	if len(h.cfg.Cache.Methods) > 0 {
		methodAllowed := false
		for _, m := range h.cfg.Cache.Methods {
			if strings.EqualFold(r.Method, m) {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			return false
		}
	}

	cc := r.Header.Get("Cache-Control")
	if strings.Contains(cc, "no-cache") || strings.Contains(cc, "no-store") {
		return false
	}

	return true
}

func (h *Replay) getTTLForResponse(contentType string) time.Duration {
	policy := h.cfg.Cache.TTLPolicy
	defaultTTL := h.cfg.Cache.TTL.StdDuration()

	if policy.Enabled.Active() {
		return policy.GetTTL(defaultTTL, contentType)
	}
	return defaultTTL
}

func (h *Replay) methodAllowed(method string) bool {
	if len(h.methods) == 0 {
		return true
	}
	upper := strings.ToUpper(method)
	for _, m := range h.methods {
		if m == upper {
			return true
		}
	}
	return false
}

func (h *Replay) domainAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pattern := range h.cfg.AllowedDomains {
		pattern = strings.ToLower(strings.TrimSpace(pattern))

		if pattern == "*" {
			return true
		}

		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			base := pattern[2:]
			if host != base && strings.HasSuffix(host, "."+base) {
				return true
			}
		}
	}
	return false
}

func (h *Replay) prepareURL(u *url.URL, incoming url.Values) {
	query := u.Query()

	if h.cfg.ForwardQuery.Active() {
		for k, vv := range incoming {
			for _, v := range vv {
				query.Add(k, v)
			}
		}
	}

	resolver := h.getResolver()
	for k, v := range h.cfg.Query {
		query.Set(k, v.Resolve(resolver))
	}

	u.RawQuery = query.Encode()
}

func (h *Replay) prepareHeaders(hdt http.Header) {
	for k, v := range h.cfg.Headers {
		hdt.Set(k, v)
	}
}

func (h *Replay) getResolver() func(string) string {
	merged := make(map[string]string)

	for k, v := range h.globalEnv {
		merged[k] = v.String()
	}
	for k, v := range h.routeEnv {
		merged[k] = v.String()
	}
	for k, v := range h.cfg.Env {
		merged[k] = v.String()
	}

	return func(key string) string {
		return merged[key]
	}
}

func (h *Replay) validateTargetHost(host string) error {
	// AllowedDomains doubles as a trust list: explicitly listed domains
	// (exact or wildcard) bypass DNS/IP checks so internal endpoints on
	// RFC-1918 addresses or without public DNS records can be reached.
	// All other hosts must resolve to a public IP — private, loopback,
	// link-local, multicast, and unspecified ranges are blocked.
	//
	// This is the single access gate. The caller must NOT pre-filter with
	// domainAllowed — doing so would make the SSRF check unreachable for
	// any host that passes the allowlist.
	if h.domainAllowed(host) {
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("DNS resolution returned no addresses for %s", host)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("target host %s resolves to blocked IP %s", host, ip)
		}
	}
	return nil
}

func forwardSafeHeaders(dst, src http.Header) {
	safe := []string{
		"Accept", "Accept-Encoding", "Accept-Language",
		"Cache-Control", "Content-Type", "Content-Length",
		"If-Modified-Since", "If-None-Match",
		"Referer",
	}
	for _, hdr := range safe {
		if v := src.Get(hdr); v != "" {
			dst.Set(hdr, v)
		}
	}
}
