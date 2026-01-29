package auth

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/maypok86/otter/v2"
	"github.com/maypok86/otter/v2/stats"
)

// Global Auth Cache (10k items, with stats enabled)
var counter = stats.NewCounter()
var authCache = otter.Must(&otter.Options[string, bool]{
	MaximumSize:   10_000,
	StatsRecorder: counter,
})

func Forward(cfg *alaye.ForwardAuth) func(http.Handler) http.Handler {
	if cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	onFailure := strings.ToLower(cfg.OnFailure)
	if onFailure != "allow" {
		onFailure = "deny" // Default
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true,
		},
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Include config URL in cache key to avoid collisions between different routes using different auth services
			cacheKey := cfg.URL + "|" + r.Header.Get("Authorization") + "|" + r.Header.Get("Cookie") + "|" + r.Method + "|" + r.URL.Path

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

			authReq.Header.Set("X-Original-URI", r.URL.RequestURI())
			authReq.Header.Set("X-Original-Method", r.Method)
			authReq.Header.Set("X-Forwarded-For", r.Header.Get("X-Forwarded-For"))

			resp, err := client.Do(authReq)
			if err != nil {
				// Network Failure case
				if onFailure == "allow" {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Auth Service Unavailable", http.StatusForbidden)
				return
			}
			defer resp.Body.Close()

			// SUCCESS: 2xx means authorized
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				ttl := time.Minute // Default TTL
				cc := resp.Header.Get("Cache-Control")
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
			authCache.SetExpiresAfter(cacheKey, 10*time.Second)

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
		val := src.Get("Authorization")
		if val != "" {
			dst.Set("Authorization", val)
		}
		val = src.Get("Cookie")
		if val != "" {
			dst.Set("Cookie", val)
		}
		return
	}

	for _, k := range keys {
		if val := src.Get(k); val != "" {
			dst.Set(k, val)
		}
	}
}
