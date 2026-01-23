// internal/middleware/auth/auth.go
package auth

import (
	"crypto/subtle"
	"io"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/maypok86/otter/v2"
)

func BasicAuth(cfg *woos.BasicAuthConfig) func(http.Handler) http.Handler {
	secrets := make(map[string]string)
	for _, u := range cfg.Users {
		parts := strings.SplitN(u, ":", 2)
		if len(parts) == 2 {
			secrets[parts[0]] = parts[1]
		}
	}

	realm := "Restricted"
	if cfg.Realm != "" {
		realm = cfg.Realm
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()

			if !ok {
				unauthorized(w, realm)
				return
			}

			validPass, exists := secrets[user]
			if !exists {
				unauthorized(w, realm)
				return
			}

			if subtle.ConstantTimeCompare([]byte(pass), []byte(validPass)) != 1 {
				unauthorized(w, realm)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// Global Auth Cache (10k items, with variable TTL support)
var authCache = otter.Must[string, bool](&otter.Options[string, bool]{
	MaximumSize: 10_000,
	Recorder:    stats.NewRecorder(), // <-- turns stats on
})

func ForwardAuth(cfg *woos.ForwardAuthConfig) func(http.Handler) http.Handler {
	if cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
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
			cacheKey := r.Header.Get("Authorization") + "|" + r.Header.Get("Cookie") + "|" + r.Method + "|" + r.URL.Path

			if allowed, ok := authCache.Get[string](cacheKey); ok {
				if allowed {
					next.ServeHTTP(w, r)
					return
				}
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
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				ttl := time.Minute * 1
				cc := resp.Header.Get("Cache-Control")
				if cc != "" {
					if strings.Contains(cc, "max-age=") {
						// Logic to parse max-age could go here
						// defaulting to 5 minutes for now if present
						ttl = time.Minute * 5
					}
				}
				authCache.SetWithTTL(cacheKey, true, ttl)

				copyHeaders(resp.Header, r.Header, cfg.AuthResponseHeaders)
				next.ServeHTTP(w, r)
				return
			}

			authCache.SetWithTTL(cacheKey, false, time.Second*30)

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		})
	}
}

func copyHeaders(src http.Header, dst http.Header, keys []string) {
	if len(keys) == 0 {
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
	}

	for _, k := range keys {
		if val := src.Get(k); val != "" {
			dst.Set(k, val)
		}
	}
}
