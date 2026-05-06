package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/mappo"
)

var forwardAuthAllowedDenyHeaders = map[string]bool{
	"Content-Type":     true,
	"Content-Length":   true,
	"Www-Authenticate": true,
	"Retry-After":      true,
	"Cache-Control":    true,
	"X-Auth-Error":     true,
	"X-Auth-Message":   true,
}

// dialContextFunc is the signature of net.Dialer.DialContext, factored out so
// forwardAuth can accept an injected dialer (e.g. in tests).
type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// forwardAuth holds all wired-up state for a single forward_auth middleware
// instance. Keeping state in a struct rather than bare closed-over variables
// makes dependencies explicit, methods individually testable, and future
// additions (metrics, tracing) easy to attach in one place.
type forwardAuth struct {
	res         *resource.Resource
	cfg         *alaye.ForwardAuth
	client      *http.Client
	onFailure   string
	cachePrefix string
	timeout     time.Duration
	cacheTTL    time.Duration

	// dialContext is injected by tests to allow connections to httptest servers
	// (127.0.0.1) without setting AllowPrivate = true in every test config.
	// In production this field is nil, and buildClient installs ssrfSafeDialContext
	// when AllowPrivate is false.
	dialContext dialContextFunc
}

// Forward is the public constructor. It returns an http.Handler middleware
// that authenticates each request by forwarding it to an external auth service.
// The upstream request proceeds only when the auth service responds 2xx.
func Forward(res *resource.Resource, cfg *alaye.ForwardAuth) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() || cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	fa := &forwardAuth{res: res, cfg: cfg}
	fa.init()
	return fa.middleware
}

// newForwardAuthWithDialer is used by tests to inject a custom DialContext so
// httptest servers (127.0.0.1) are reachable without AllowPrivate = true.
func newForwardAuthWithDialer(res *resource.Resource, cfg *alaye.ForwardAuth, dial dialContextFunc) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() || cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	fa := &forwardAuth{res: res, cfg: cfg, dialContext: dial}
	fa.init()
	return fa.middleware
}

// init resolves all derived values and builds the HTTP client.
func (fa *forwardAuth) init() {
	fa.onFailure = strings.ToLower(fa.cfg.OnFailure)
	if fa.onFailure != def.Allow {
		fa.onFailure = def.Deny
	}

	fa.cachePrefix = fa.cfg.Name
	if fa.cachePrefix == "" {
		fa.cachePrefix = "default_" + fa.cfg.URL
	}

	fa.timeout = fa.cfg.Timeout.StdDuration()
	if fa.timeout <= 0 {
		fa.timeout = def.DefaultForwardAuthTimeout
	}

	fa.cacheTTL = fa.cfg.Response.CacheTTL.StdDuration()
	fa.client = fa.buildClient()
}

// buildClient constructs the HTTP client for this instance.
//
// SSRF protection:
//   - When allow_private = false (the default), ssrfSafeDialContext is installed.
//     It intercepts each connection after DNS resolution but before the TCP socket
//     opens, blocking private/loopback IPs — the only atomic way to prevent
//     DNS-rebinding. This is the runtime complement to the config-time check in
//     rejectPrivateURL (alaye/fn.go).
//   - When allow_private = true the operator explicitly acknowledges that their
//     auth server is on a private network; the safe dialer is not installed.
//   - When dialContext is set (tests only) that function is used instead.
func (fa *forwardAuth) buildClient() *http.Client {
	var dial dialContextFunc
	switch {
	case fa.dialContext != nil:
		dial = fa.dialContext
	case !fa.cfg.AllowPrivate:
		dial = ssrfSafeDialContext(&net.Dialer{
			Timeout:   def.DefaultTransportDialTimeout,
			KeepAlive: def.DefaultTransportKeepAlive,
		})
	}

	if fa.cfg.TLS.Enabled.Active() {
		return fa.buildTLSClient(dial)
	}
	return fa.buildPlainClient(dial)
}

// buildTLSClient constructs a client with a custom TLS configuration.
func (fa *forwardAuth) buildTLSClient(dial dialContextFunc) *http.Client {
	tlsConfig, err := buildTLSConfig(fa.cfg.TLS)
	if err != nil {
		// Surface the error at request time via errorTransport rather than
		// silently swallowing it at construction time.
		return &http.Client{Transport: &errorTransport{err: err}}
	}
	transport := &http.Transport{
		MaxIdleConns:        def.CacheClientMaxIdleCons,
		MaxIdleConnsPerHost: def.CacheClientMaxIdleCons,
		IdleConnTimeout:     def.CacheClientMaxIdleTimeOuts,
		DisableCompression:  true,
		TLSClientConfig:     tlsConfig,
	}
	if dial != nil {
		transport.DialContext = dial
	}
	return &http.Client{Timeout: fa.timeout, Transport: transport}
}

// buildPlainClient clones the resource's shared transport (inheriting all
// tuning) without mutating the global client, then optionally installs the
// safe dialer.
func (fa *forwardAuth) buildPlainClient(dial dialContextFunc) *http.Client {
	base, _ := fa.res.HTTPClient.Transport.(*http.Transport)
	var transport *http.Transport
	if base != nil {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	if dial != nil {
		transport.DialContext = dial
	}
	return &http.Client{
		Timeout:   fa.timeout,
		Transport: transport,
	}
}

// middleware is the http.Handler returned to callers.
func (fa *forwardAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheKey := fa.buildCacheKey(r)

		// Strip any incoming headers that the backend expects to be set
		// exclusively by the auth service — prevents privilege escalation via
		// header injection (e.g. attacker sending X-User-Role: admin).
		if fa.cfg.Response.Enabled.Active() {
			for _, h := range fa.cfg.Response.CopyHeaders {
				r.Header.Del(h)
			}
		}

		if fa.serveCached(w, r, next, cacheKey) {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), fa.timeout)
		defer cancel()

		authReq, err := fa.buildAuthRequest(ctx, r)
		if err != nil {
			fa.fail(w, r, next, "failed to create auth request")
			return
		}

		resp, err := fa.client.Do(authReq)
		if err != nil {
			fa.fail(w, r, next, "auth service unavailable")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			fa.handleAllow(w, r, next, resp, cacheKey)
			return
		}

		fa.handleDeny(w, resp)
	})
}

// serveCached checks the auth cache and serves from it when a valid entry exists.
func (fa *forwardAuth) serveCached(w http.ResponseWriter, r *http.Request, next http.Handler, cacheKey string) bool {
	cached, ok := fa.res.AuthCache.Load(cacheKey)
	if !ok {
		return false
	}
	allowed, ok := mappo.GetTyped[bool](cached)
	if !ok || !allowed {
		return false
	}
	if fa.cfg.Response.Enabled.Active() {
		if item, ok := fa.res.AuthCache.Load(cacheKey + "_headers"); ok {
			if headers, ok := mappo.GetTyped[http.Header](item); ok {
				copyHeadersToRequest(headers, r, fa.cfg.Response.CopyHeaders)
			}
		}
	}
	next.ServeHTTP(w, r)
	return true
}

// buildAuthRequest constructs the outbound request to the auth service.
func (fa *forwardAuth) buildAuthRequest(ctx context.Context, r *http.Request) (*http.Request, error) {
	method := http.MethodGet
	if fa.cfg.Request.Method != "" {
		method = strings.ToUpper(fa.cfg.Request.Method)
	}

	authReq, err := http.NewRequestWithContext(ctx, method, fa.cfg.URL, nil)
	if err != nil {
		return nil, err
	}

	if fa.cfg.Request.Enabled.Active() {
		copyHeaders(r.Header, authReq.Header, fa.cfg.Request.Headers)
	} else {
		copyHeaders(r.Header, authReq.Header, nil)
	}

	if fa.cfg.Request.Enabled.Active() {
		fa.applyRequestExtras(r, authReq)
	}

	return authReq, nil
}

// applyRequestExtras forwards method, URI, IP, and body as configured.
func (fa *forwardAuth) applyRequestExtras(r *http.Request, authReq *http.Request) {
	ipMgr := zulu.NewIP()
	if fa.cfg.Request.ForwardMethod {
		authReq.Header.Set(def.HeaderXOriginalMethod, r.Method)
	}
	if fa.cfg.Request.ForwardURI {
		authReq.Header.Set(def.HeaderXOriginalURI, r.URL.RequestURI())
	}
	if fa.cfg.Request.ForwardIP {
		authReq.Header.Set(def.HeaderXForwardedFor, ipMgr.ClientIP(r))
	}

	switch fa.cfg.Request.BodyMode {
	case "metadata":
		authReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		cl := r.Header.Get("Content-Length")
		if cl == "" && r.ContentLength > 0 {
			cl = strconv.FormatInt(r.ContentLength, 10)
		}
		if cl != "" {
			authReq.Header.Set("Content-Length", cl)
		}
	case "limited":
		maxBody := fa.cfg.Request.MaxBody
		if maxBody <= 0 {
			maxBody = def.ForwardAuthMaxBodyDefault
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			return
		}
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		authReq.Body = io.NopCloser(bytes.NewReader(body))
		authReq.ContentLength = int64(len(body))
	}
}

// handleAllow processes a 2xx response: copies auth headers to the upstream
// request, optionally caches the result, then calls next.
func (fa *forwardAuth) handleAllow(w http.ResponseWriter, r *http.Request, next http.Handler, resp *http.Response, cacheKey string) {
	if fa.cfg.Response.Enabled.Active() {
		headersToCopy := make(http.Header)
		for _, h := range fa.cfg.Response.CopyHeaders {
			for _, v := range resp.Header.Values(h) {
				headersToCopy.Add(h, v)
				r.Header.Add(h, v)
			}
		}
		if fa.cacheTTL > 0 {
			fa.res.AuthCache.StoreTTL(cacheKey, &mappo.Item{Value: true}, fa.cacheTTL)
			fa.res.AuthCache.StoreTTL(cacheKey+"_headers", &mappo.Item{Value: headersToCopy}, fa.cacheTTL)
		}
	} else if fa.cacheTTL > 0 {
		fa.res.AuthCache.StoreTTL(cacheKey, &mappo.Item{Value: true}, fa.cacheTTL)
	}
	next.ServeHTTP(w, r)
}

// handleDeny writes a non-2xx auth response back to the client, forwarding
// only the safe subset of headers defined in forwardAuthAllowedDenyHeaders.
func (fa *forwardAuth) handleDeny(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		if !forwardAuthAllowedDenyHeaders[k] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// fail handles auth service errors according to the on_failure policy.
func (fa *forwardAuth) fail(w http.ResponseWriter, r *http.Request, next http.Handler, msg string) {
	if fa.onFailure == def.Allow {
		next.ServeHTTP(w, r)
		return
	}
	http.Error(w, msg, http.StatusForbidden)
}

// buildCacheKey produces a collision-resistant cache key for the forward-auth
// result. It uses SHA-256 (truncated to 32 hex chars / 128 bits) rather than
// a non-cryptographic hash. xxhash has a 64-bit output space — acceptable for
// general-purpose hashing but not for an authentication boundary where a
// collision grants an attacker access with another user's cached credentials.
// SHA-256 provides a 2^128 collision space even after truncation, making
// intentional collisions computationally infeasible.
func (fa *forwardAuth) buildCacheKey(r *http.Request) string {
	h := sha256.New()
	if fa.cachePrefix != "" {
		io.WriteString(h, fa.cachePrefix)
		io.WriteString(h, "|")
	}
	keys := fa.cfg.Request.CacheKey
	if len(keys) == 0 {
		keys = []string{"Authorization"}
	}
	for _, k := range keys {
		io.WriteString(h, r.Header.Get(k))
		io.WriteString(h, "|")
	}
	io.WriteString(h, r.Method)
	io.WriteString(h, "|")
	io.WriteString(h, r.URL.Path)
	io.WriteString(h, "|")
	io.WriteString(h, r.URL.RawQuery)
	// Truncate to 32 hex characters (128 bits). Full SHA-256 is 64 chars —
	// 128 bits is sufficient for collision resistance while keeping cache keys compact.
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Package-level helpers (shared across auth middleware files in this package)

// copyHeaders copies specified headers from src to dst.
// Defaults to Authorization and Cookie when keys is empty.
func copyHeaders(src, dst http.Header, keys []string) {
	if len(keys) == 0 {
		keys = []string{"Authorization", "Cookie"}
	}
	for _, k := range keys {
		for _, v := range src.Values(k) {
			dst.Add(k, v)
		}
	}
}

// copyHeadersToRequest copies auth-service response headers into the upstream
// request so backends can read identity claims (e.g. X-User-ID).
func copyHeadersToRequest(src http.Header, r *http.Request, keys []string) {
	for _, k := range keys {
		for _, v := range src.Values(k) {
			r.Header.Add(k, v)
		}
	}
}

// buildTLSConfig builds a tls.Config from the ForwardTLS block.
func buildTLSConfig(cfg alaye.ForwardTLS) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.ClientCert.String()), []byte(cfg.ClientKey.String()))
		if err != nil {
			return nil, errors.Newf("failed to parse client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CA.String())) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// ssrfSafeDialContext returns a DialContext that rejects connections to
// private, loopback, and link-local IPs after DNS resolution but before the
// TCP socket opens — the only atomic way to prevent DNS-rebinding SSRF.
func ssrfSafeDialContext(d *net.Dialer) dialContextFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("forward_auth: invalid address %q: %w", addr, err)
		}

		// Go's http.Transport passes the original hostname here — it does NOT
		// pre-resolve DNS before calling DialContext. net.ParseIP on a hostname
		// always returns nil, which broke every non-IP forward_auth URL.
		// Resolve the hostname explicitly so the SSRF check operates on the
		// actual IP address(es) that the connection will use.
		ip := net.ParseIP(host)
		if ip == nil {
			// hostname — resolve and check every returned address
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("forward_auth: DNS resolution failed for %q: %w", host, err)
			}
			for _, a := range addrs {
				resolved := net.ParseIP(a)
				if resolved == nil {
					continue
				}
				if alaye.IsPrivateIP(resolved) {
					return nil, fmt.Errorf("forward_auth: SSRF protection blocked connection to private/internal address %s (resolved from %s)", a, host)
				}
			}
			// All resolved IPs are public — dial using the original hostname
			// so TLS SNI is preserved correctly.
			return d.DialContext(ctx, network, addr)
		}

		// Raw IP address supplied directly — check it without resolution.
		if alaye.IsPrivateIP(ip) {
			return nil, fmt.Errorf("forward_auth: SSRF protection blocked connection to private/internal address %s:%s", host, port)
		}
		return d.DialContext(ctx, network, addr)
	}
}

// errorTransport is an http.RoundTripper that always returns a fixed error.
// Used when TLS config construction fails so the error surfaces at request
// time with a clear message rather than panicking at construction time.
type errorTransport struct{ err error }

func (e *errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}
