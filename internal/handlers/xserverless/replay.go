package xserverless

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/middleware/nonce"
)

const (
	defaultRESTTimeout = 30 * time.Second
)

// upstreamHeadersToStrip are headers sent by the upstream that must not be
// forwarded to the browser when StripUpstreamHeaders is active.  These are
// headers that apply to the upstream's own origin and would confuse or block
// the browser when the response is re-served from agbero's origin.
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
	REST       alaye.Replay
	GlobalEnv  map[string]expect.Value
	RouteEnv   map[string]expect.Value
	NonceStore *nonce.Store
}

type Replay struct {
	res        *resource.Resource
	cfg        alaye.Replay
	globalEnv  map[string]expect.Value
	routeEnv   map[string]expect.Value
	client     *http.Client
	methods    []string
	nonceStore *nonce.Store
}

func NewReplay(cfg ReplayConfig) *Replay {
	timeout := cfg.REST.Timeout.StdDuration()
	if timeout <= 0 {
		timeout = defaultRESTTimeout
	}

	return &Replay{
		res:        cfg.Resource,
		cfg:        cfg.REST,
		globalEnv:  cfg.GlobalEnv,
		routeEnv:   cfg.RouteEnv,
		methods:    cfg.REST.NormalisedMethods(),
		nonceStore: cfg.NonceStore,
		client: &http.Client{
			Timeout: timeout,
		},
	}
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
			if h.cfg.Auth.Secret.Empty() { // or inject via config
				http.Error(w, "replay: token verifier not configured", http.StatusInternalServerError)
				return
			}
			// guard = nonce.NewTokenGuard(h.cfg.Auth.Secret)
			// todo this will work with agbero secre
			// thi swill use in internal to generate auth token i think
			/// we need to make this work
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
	// Method guard — applied in both fixed and replay modes.
	if !h.methodAllowed(r.Method) {
		allowed := strings.Join(h.methods, ", ")
		w.Header().Set("Allow", allowed)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.cfg.IsReplayMode() {
		h.serveReplay(w, r)
	} else {
		h.serveFixed(w, r)
	}
}

// serveFixed handles requests where a static upstream URL is configured.
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
	h.doProxy(w, r, proxyReq, false)
}

// serveReplay handles requests where the upstream URL is provided at runtime
// via the X-Agbero-Replay-Url header or ?url= query parameter.
func (h *Replay) serveReplay(w http.ResponseWriter, r *http.Request) {
	rawURL := r.Header.Get(woos.HeaderXAgberoReplayURL)
	if rawURL == "" {
		rawURL = r.URL.Query().Get("url")
	}
	if rawURL == "" {
		http.Error(w, "replay: missing target url — set X-Agbero-Replay-Url header or ?url= param", http.StatusBadRequest)
		return
	}

	targetURL, err := url.Parse(rawURL)
	if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		http.Error(w, "replay: invalid target url", http.StatusBadRequest)
		return
	}

	if !h.domainAllowed(targetURL.Hostname()) {
		h.res.Logger.Fields("host", targetURL.Hostname()).Warn("serverless: replay domain blocked")
		http.Error(w, "replay: target domain not allowed", http.StatusForbidden)
		return
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		h.res.Logger.Fields("err", err).Error("serverless: failed to create replay request")
		http.Error(w, "Request Initialization Failed", http.StatusInternalServerError)
		return
	}

	// Forward safe headers from the incoming request to the upstream.
	forwardSafeHeaders(proxyReq.Header, r.Header)
	h.prepareHeaders(proxyReq.Header) // config-level header overrides

	strip := h.cfg.StripHeaders.Active()
	h.doProxy(w, r, proxyReq, strip)
}

// doProxy executes the upstream request and writes the response.
// When strip is true, upstream CORS and security headers are removed and
// Access-Control-Allow-Origin is set to the incoming request's origin so the
// browser treats the response as same-origin.
func (h *Replay) doProxy(w http.ResponseWriter, r *http.Request, proxyReq *http.Request, strip bool) {
	resp, err := h.client.Do(proxyReq)
	if err != nil {
		h.res.Logger.Fields("url", proxyReq.URL.String(), "err", err).Error("serverless: upstream call failed")
		http.Error(w, "Upstream Service Unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.res.Logger.Fields("err", err).Debug("serverless: rest stream interrupted")
	}
}

// methodAllowed reports whether the given HTTP method is permitted by the
// handler's method list.  An empty list means all methods are allowed.
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

// domainAllowed checks the upstream hostname against AllowedDomains.
// Patterns support a leading wildcard: *.bbc.co.uk matches any subdomain.
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
			suffix := pattern[1:] // ".bbc.co.uk"
			if strings.HasSuffix(host, suffix) {
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

// forwardSafeHeaders copies a curated subset of incoming request headers to
// the upstream request.  Host, cookies, and auth headers are intentionally
// excluded — they belong to the browser↔agbero leg, not the agbero↔upstream leg.
func forwardSafeHeaders(dst, src http.Header) {
	safe := []string{
		"Accept", "Accept-Encoding", "Accept-Language",
		"Cache-Control", "Content-Type", "Content-Length",
		"If-Modified-Since", "If-None-Match",
	}
	for _, h := range safe {
		if v := src.Get(h); v != "" {
			dst.Set(h, v)
		}
	}
}
