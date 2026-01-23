package auth

import (
	"crypto/subtle"
	"io"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// --- BASIC AUTH ---

func BasicAuth(cfg *woos.BasicAuthConfig) func(http.Handler) http.Handler {
	// Parse users into a map for O(1) lookup
	// Format: "username:password"
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

			// Constant time comparison to prevent timing attacks
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

// --- FORWARD AUTH (The "Killer" Feature) ---

func ForwardAuth(cfg *woos.ForwardAuthConfig) func(http.Handler) http.Handler {
	if cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		// We DO NOT use shared transport here to avoid coupling auth failures
		// with backend traffic pool exhaustion.
		Transport: &http.Transport{
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true, // We only care about headers/status
		},
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Prepare Request to Auth Service
			// We use GET usually, checking the same URI
			authReq, err := http.NewRequest(r.Method, cfg.URL, nil)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// 2. Copy Headers (Client -> Auth)
			// e.g. Authorization, Cookie, X-Forwarded-For
			copyHeaders(r.Header, authReq.Header, cfg.RequestHeaders)

			// Always pass original info
			authReq.Header.Set("X-Original-URI", r.URL.RequestURI())
			authReq.Header.Set("X-Original-Method", r.Method)
			authReq.Header.Set("X-Forwarded-For", r.Header.Get("X-Forwarded-For"))

			// 3. Execute Check
			resp, err := client.Do(authReq)
			if err != nil {
				// Auth service down? Fail closed.
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			defer resp.Body.Close()

			// 4. Check Decision
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// ALLOWED

				// 5. Copy Headers (Auth -> Backend)
				// e.g. X-User-ID, X-Role, X-JWT-Payload
				copyHeaders(resp.Header, r.Header, cfg.AuthResponseHeaders)

				// Cleanup auth-specific headers we might not want to pass?
				// Usually fine to leave them.

				next.ServeHTTP(w, r)
				return
			}

			// DENIED
			// Copy headers (Auth -> Client) e.g. WWW-Authenticate, Location (redirect)
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
		// If explicit list is empty, maybe default to "Authorization" and "Cookie"?
		// Or copy all?
		// "Traefik" default is copy all if list is empty, but that's risky.
		// Let's copy common auth headers if empty list provided.
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
