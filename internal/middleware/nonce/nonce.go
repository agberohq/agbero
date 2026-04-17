// Package nonce provides authentication middleware for agbero REST replay
// endpoints.
//
// A replay endpoint is a serverless rest block with no fixed url — the target
// URL is supplied by the client at request time. Because the endpoint
// effectively proxies arbitrary upstream resources on behalf of a browser, it
// must be guarded so that only legitimate clients on the same agbero host can
// use it.
//
// Three guard methods are supported, selected via auth.method in HCL:
//
//	meta   — agbero injects a single-use nonce into HTML responses served from
//	         the same host. Client JS reads it from
//
//	         and sends it back in the X-Agbero-Replay-Nonce header. Nonces are
//	         single-use and expire after a configurable TTL (default 1 h).
//	         Suitable for public pages.
//
//	token  — a short-lived scoped JWT is minted by agbero and fetched by the
//	         client from /.agbero/replay//token. The token is validated on
//	         every request. Suitable for pages behind agbero auth.
//
//	direct — a valid agbero session cookie (agbero_sess) is required on every
//	         request. Suitable when the page is already behind agbero's admin
//	         or OAuth auth.
package nonce

import (
	"net/http"

	"github.com/agberohq/agbero/internal/core/def"
)

// Guard enforces replay authentication using one of three methods.
type Guard struct {
	method string
	store  *Store            // meta only
	verify func(string) bool // token only
}

// NewMetaGuard creates a Guard that validates single-use nonces from store.
func NewMetaGuard(store *Store) *Guard {
	return &Guard{method: "meta", store: store}
}

// NewTokenGuard creates a Guard that validates Bearer JWTs using verify.
// verify must return true iff the token is valid and unexpired.
func NewTokenGuard(verify func(string) bool) *Guard {
	return &Guard{method: "token", verify: verify}
}

// NewDirectGuard creates a Guard that checks for an agbero session cookie.
func NewDirectGuard() *Guard {
	return &Guard{method: "direct"}
}

// Middleware wraps next and enforces the guard.
// Unauthenticated requests receive 401; misconfigured guards receive 500.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch g.method {
		case "meta":
			nonce := r.Header.Get(def.HeaderXAgberoReplayNonce)
			if !g.store.Consume(nonce) {
				http.Error(w, "replay: invalid or expired nonce", http.StatusUnauthorized)
				return
			}
		case "token":
			if g.verify == nil {
				http.Error(w, "replay: token verifier not configured", http.StatusInternalServerError)
				return
			}
			auth := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if len(auth) <= len(prefix) {
				http.Error(w, "replay: bearer token required", http.StatusUnauthorized)
				return
			}
			if !g.verify(auth[len(prefix):]) {
				http.Error(w, "replay: invalid or expired token", http.StatusUnauthorized)
				return
			}
		case "direct":
			cookie, err := r.Cookie(def.SessionCookieName)
			if err != nil || cookie.Value == "" {
				http.Error(w, "replay: session cookie required", http.StatusUnauthorized)
				return
			}
		default:
			http.Error(w, "replay: unknown auth method", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	})
}
