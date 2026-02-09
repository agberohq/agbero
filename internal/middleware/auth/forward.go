package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/maypok86/otter/v2"
	"github.com/maypok86/otter/v2/stats"
)

// Global Auth Cache (10k items, with stats enabled)
var counter = stats.NewCounter()
var authCache = otter.Must(&otter.Options[string, bool]{
	MaximumSize:   woos.MaxSizeCache,
	StatsRecorder: counter,
})

func Forward(cfg *alaye.ForwardAuth) func(http.Handler) http.Handler {
	if cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	onFailure := strings.ToLower(cfg.OnFailure)
	if onFailure != woos.Allow {
		onFailure = woos.Deny // Default
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       woos.CacheClientMaxIdleCons,
			IdleConnTimeout:    woos.CacheClientMaxIdleTimeOuts,
			DisableCompression: true,
		},
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Construct raw key
			rawKey := cfg.URL + "|" + r.Header.Get("Authorization") + "|" + r.Header.Get("Cookie") + "|" + r.Method + "|" + r.URL.Path

			// Hash key to ensure fixed size (Fix for large JWT/Cookie DOS)
			hasher := sha256.New()
			hasher.Write([]byte(rawKey))
			cacheKey := hex.EncodeToString(hasher.Sum(nil))

			if allowed, ok := authCache.GetIfPresent(cacheKey); ok {
				if allowed {
					next.ServeHTTP(w, r)
					return
				}
				// Cached Deny (generic forbidden)
				http.Error(w, "Forbidden (Cached)", http.StatusForbidden)
				return
			}

			authReq, err := http.NewRequest(r.Method, cfg.URL, nil)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			copyHeaders(r.Header, authReq.Header, cfg.RequestHeaders)

			authReq.Header.Set(woos.HeaderXOriginalURI, r.URL.RequestURI())
			authReq.Header.Set(woos.HeaderXOriginalMethod, r.Method)
			authReq.Header.Set(woos.HeaderXForwardedFor, r.Header.Get(woos.HeaderXForwardedFor))

			resp, err := client.Do(authReq)
			if err != nil {
				// Network Failure case
				if onFailure == woos.Allow {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Auth Service Unavailable", http.StatusForbidden)
				return
			}
			defer resp.Body.Close()

			// SUCCESS: 2xx means authorized
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
				ttl := time.Minute // Default TTL
				cc := resp.Header.Get(woos.HeaderCacheControl)
				if cc != "" && strings.Contains(cc, "max-age=") {
					parts := strings.SplitAfter(cc, "max-age=")
					if len(parts) > 1 {
						maStr := strings.Split(parts[1], ",")[0]
						maStr = strings.TrimSpace(maStr)
						if sec, err := strconv.Atoi(maStr); err == nil && sec > 0 {
							ttl = time.Duration(sec) * time.Second
						}
					}
				}

				authCache.Set(cacheKey, true)
				authCache.SetExpiresAfter(cacheKey, ttl)

				copyHeaders(resp.Header, r.Header, cfg.AuthResponseHeaders)
				next.ServeHTTP(w, r)
				return
			}

			// FAILURE: 4xx/5xx means unauthorized (or error)
			// Cache the failure briefly (10s) to prevent hammering auth service on denial
			authCache.Set(cacheKey, false)
			authCache.SetExpiresAfter(cacheKey, woos.CacheSetTTL)

			// Pass through the Auth Service's response headers (e.g. WWW-Authenticate, Content-Type)
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}

			// Pass through status code
			w.WriteHeader(resp.StatusCode)

			// Pass through the response body (JSON error, HTML, etc)
			io.Copy(w, resp.Body)
		})
	}
}

func copyHeaders(src http.Header, dst http.Header, keys []string) {
	if len(keys) == 0 {
		val := src.Get(woos.AuthorizationHeaderKey)
		if val != "" {
			dst.Set(woos.AuthorizationHeaderKey, val)
		}
		val = src.Get(woos.CookieHeaderKey)
		if val != "" {
			dst.Set(woos.CookieHeaderKey, val)
		}
		return
	}

	for _, k := range keys {
		if val := src.Get(k); val != "" {
			dst.Set(k, val)
		}
	}
}
