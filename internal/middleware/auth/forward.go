package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/cespare/xxhash/v2"
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

// Forward returns middleware that authenticates each request by forwarding it
// to an external auth service. The upstream request proceeds only when the
// auth service responds with a 2xx status.
func Forward(res *resource.Resource, cfg *alaye.ForwardAuth) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}
	if cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	onFailure := strings.ToLower(cfg.OnFailure)
	if onFailure != woos.Allow {
		onFailure = woos.Deny
	}

	cachePrefix := cfg.Name
	if cachePrefix == "" {
		cachePrefix = "default_" + cfg.URL
	}

	timeout := cfg.Timeout.StdDuration()
	if timeout <= 0 {
		timeout = woos.DefaultForwardAuthTimeout
	}

	var client *http.Client
	if cfg.TLS.Enabled.Active() {
		tlsConfig, err := createTLSConfig(cfg.TLS)
		if err != nil {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Forward Internal TLS Error: "+err.Error(), http.StatusInternalServerError)
				})
			}
		}
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        woos.CacheClientMaxIdleCons,
				MaxIdleConnsPerHost: woos.CacheClientMaxIdleCons,
				IdleConnTimeout:     woos.CacheClientMaxIdleTimeOuts,
				DisableCompression:  true,
				TLSClientConfig:     tlsConfig,
			},
		}
	} else {
		client = res.HTTPClient
	}

	cacheTTL := cfg.Response.CacheTTL.StdDuration()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cacheKey := buildCacheKey(r, cfg.Request.CacheKey, cachePrefix)

			if cached, ok := res.AuthCache.Load(cacheKey); ok {
				if allowed, ok := mappo.GetTyped[bool](cached); ok && allowed {
					if cfg.Response.Enabled.Active() {
						if headersItem, ok := res.AuthCache.Load(cacheKey + "_headers"); ok {
							if headers, ok := mappo.GetTyped[http.Header](headersItem); ok {
								copyHeadersToRequest(headers, r, cfg.Response.CopyHeaders)
							}
						}
					}
					next.ServeHTTP(w, r)
					return
				}
			}

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			method := http.MethodGet
			if cfg.Request.Method != "" {
				method = strings.ToUpper(cfg.Request.Method)
			}

			authReq, err := http.NewRequestWithContext(ctx, method, cfg.URL, nil)
			if err != nil {
				handleFailure(w, r, onFailure, next, "failed to create auth request")
				return
			}

			if cfg.Request.Enabled.Active() {
				copyHeaders(r.Header, authReq.Header, cfg.Request.Headers)
			} else {
				copyHeaders(r.Header, authReq.Header, nil)
			}

			if cfg.Request.Enabled.Active() {
				ipMgr := zulu.NewIP()
				if cfg.Request.ForwardMethod {
					authReq.Header.Set(woos.HeaderXOriginalMethod, r.Method)
				}
				if cfg.Request.ForwardURI {
					authReq.Header.Set(woos.HeaderXOriginalURI, r.URL.RequestURI())
				}
				if cfg.Request.ForwardIP {
					authReq.Header.Set(woos.HeaderXForwardedFor, ipMgr.ClientIP(r))
				}
			}

			if cfg.Request.Enabled.Active() {
				switch cfg.Request.BodyMode {
				case "metadata":
					authReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
					contentLength := r.Header.Get("Content-Length")
					if contentLength == "" && r.ContentLength > 0 {
						contentLength = strconv.FormatInt(r.ContentLength, 10)
					}
					if contentLength != "" {
						authReq.Header.Set("Content-Length", contentLength)
					}
				case "limited":
					maxBody := cfg.Request.MaxBody
					if maxBody <= 0 {
						maxBody = woos.ForwardAuthMaxBodyDefault
					}
					body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
					if err != nil {
						handleFailure(w, r, onFailure, next, "failed to read body")
						return
					}
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
					authReq.Body = io.NopCloser(bytes.NewReader(body))
					authReq.ContentLength = int64(len(body))
				}
			}

			resp, err := client.Do(authReq)
			if err != nil {
				handleFailure(w, r, onFailure, next, "auth service unavailable")
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
				if cfg.Response.Enabled.Active() {
					headersToCopy := make(http.Header)
					for _, h := range cfg.Response.CopyHeaders {
						if v := resp.Header.Get(h); v != "" {
							headersToCopy.Set(h, v)
							r.Header.Set(h, v)
						}
					}
					if cacheTTL > 0 {
						allowItem := &mappo.Item{Value: true}
						headersItem := &mappo.Item{Value: headersToCopy}
						res.AuthCache.StoreTTL(cacheKey, allowItem, cacheTTL)
						res.AuthCache.StoreTTL(cacheKey+"_headers", headersItem, cacheTTL)
					}
				} else if cacheTTL > 0 {
					allowItem := &mappo.Item{Value: true}
					res.AuthCache.StoreTTL(cacheKey, allowItem, cacheTTL)
				}
				next.ServeHTTP(w, r)
				return
			}

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
		})
	}
}

// createTLSConfig builds a tls.Config from the ForwardTLS block, loading
// optional client certificates and a custom CA pool.
func createTLSConfig(cfg alaye.ForwardTLS) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.ClientCert.String()), []byte(cfg.ClientKey.String()))
		if err != nil {
			return nil, errors.Newf("failed to parse client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if cfg.CA != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(cfg.CA.String())) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}

// buildCacheKey hashes the configured cache key headers together with the
// request method, path, and query to produce a stable auth cache key.
func buildCacheKey(r *http.Request, cacheKeyHeaders []string, prefix string) string {
	h := xxhash.New()
	if prefix != "" {
		h.WriteString(prefix)
		h.WriteString("|")
	}
	if len(cacheKeyHeaders) == 0 {
		cacheKeyHeaders = []string{"Authorization"}
	}
	for _, header := range cacheKeyHeaders {
		h.WriteString(r.Header.Get(header))
		h.WriteString("|")
	}
	h.WriteString(r.Method)
	h.WriteString("|")
	h.WriteString(r.URL.Path)
	h.WriteString("|")
	h.WriteString(r.URL.RawQuery)
	return strconv.FormatUint(h.Sum64(), 16)
}

// copyHeaders copies the specified headers from src to dst. When keys is
// empty, Authorization and Cookie are forwarded by default.
func copyHeaders(src http.Header, dst http.Header, keys []string) {
	if len(keys) == 0 {
		for _, key := range []string{"Authorization", "Cookie"} {
			if v := src.Get(key); v != "" {
				dst.Set(key, v)
			}
		}
		return
	}
	for _, k := range keys {
		if v := src.Get(k); v != "" {
			dst.Set(k, v)
		}
	}
}

// copyHeadersToRequest copies the specified headers from the auth service
// response into the upstream request so backends can read identity claims.
func copyHeadersToRequest(src http.Header, r *http.Request, keys []string) {
	for _, k := range keys {
		if v := src.Get(k); v != "" {
			r.Header.Set(k, v)
		}
	}
}

// handleFailure either calls next (on_failure = allow) or returns 403
// with msg as the body (on_failure = deny).
func handleFailure(w http.ResponseWriter, r *http.Request, onFailure string, next http.Handler, msg string) {
	if onFailure == woos.Allow {
		next.ServeHTTP(w, r)
		return
	}
	http.Error(w, msg, http.StatusForbidden)
}
