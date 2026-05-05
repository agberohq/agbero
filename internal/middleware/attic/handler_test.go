package attic

import (
	"net/http"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

// Helpers

// backendWithCookie returns a handler that always responds with a Set-Cookie
// header in addition to the supplied body.
func backendWithCookie(body, cookieVal string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", cookieVal)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
}

// backendChangingCookie returns successive bodies and cookies on each call.
// The first call returns body1/cookie1; every subsequent call returns body2/cookie2.
func backendChangingCookie(body1, cookie1, body2, cookie2 string) http.Handler {
	calls := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/plain")
		if calls == 1 {
			w.Header().Set("Set-Cookie", cookie1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body1))
		} else {
			w.Header().Set("Set-Cookie", cookie2)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body2))
		}
	})
}

// Core CVE tests: Set-Cookie must never be served from cache

// TestSetCookie_ResponseNotCached verifies that a response carrying Set-Cookie
// is never stored in the cache.  Concretely: a second identical request must
// NOT get X-Cache-Status: HIT, and must NOT receive the first visitor's cookie.
func TestSetCookie_ResponseNotCached(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)
	h := mw(backendWithCookie("body", "session_id=VICTIM_SESSION; Path=/; HttpOnly"))

	// First request — populates (or fails to populate) the cache.
	doGET(h, "/login-page")

	// Second request — must NOT serve the first visitor's session cookie.
	w := doGET(h, "/login-page")

	if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
		t.Fatal("SECURITY: response with Set-Cookie was served from cache (HIT); " +
			"this enables cross-user session fixation / account take-over")
	}
	if got := w.Header().Get("Set-Cookie"); got == "session_id=VICTIM_SESSION; Path=/; HttpOnly" {
		// Only fatal if it came from the cache; a fresh upstream response with
		// the same cookie is fine — but combined with a HIT it is fatal.
		// We already checked for HIT above; here we guard a MISS that somehow
		// replayed a stale cookie.
		t.Logf("Set-Cookie present on second request (status=%s) — acceptable only if upstream generated it fresh",
			w.Header().Get("X-Cache-Status"))
	}
}

// TestSetCookie_NeverHit ensures that repeated requests to a Set-Cookie
// endpoint never produce a cache HIT, regardless of how many times it is
// called.
func TestSetCookie_NeverHit(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)
	h := mw(backendWithCookie("body", "session_id=abc; Path=/"))

	for i := 0; i < 5; i++ {
		w := doGET(h, "/session-endpoint")
		if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
			t.Errorf("request %d: got HIT for a Set-Cookie response — must never be cached", i+1)
		}
	}
}

// TestSetCookie_DifferentCookiesPerUser verifies that two users receive their
// own distinct cookies and not each other's.
func TestSetCookie_DifferentCookiesPerUser(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)
	h := mw(backendChangingCookie(
		"user1-body", "session_id=USER1; Path=/",
		"user2-body", "session_id=USER2; Path=/",
	))

	w1 := doGET(h, "/home")
	w2 := doGET(h, "/home")

	cookie1 := w1.Header().Get("Set-Cookie")
	cookie2 := w2.Header().Get("Set-Cookie")

	// User 2 must not receive User 1's session cookie via the cache.
	if w2.Header().Get("X-Cache-Status") == "HIT" && cookie2 == cookie1 {
		t.Errorf("SECURITY: user2 received user1's Set-Cookie via cache HIT: %q", cookie2)
	}
}

// TestSetCookie_StripFromStoredEntry is a belt-and-suspenders test: even if a
// Set-Cookie response somehow slips past isResponseCacheable, the header must
// be stripped from the stored entry before it is replayed.
//
// We verify this indirectly by checking that a HIT response (if it ever
// occurs) does not contain Set-Cookie.
func TestSetCookie_StripFromStoredEntry(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)
	h := mw(backendWithCookie("sensitive-body", "session_id=SECRET; Path=/; Secure"))

	doGET(h, "/strip-test") // prime

	w := doGET(h, "/strip-test")
	if w.Header().Get("X-Cache-Status") == "HIT" {
		// If it somehow got cached (should not), the cookie must at least be stripped.
		if got := w.Header().Get("Set-Cookie"); got != "" {
			t.Errorf("SECURITY: Set-Cookie %q was replayed from cache entry — session hijack vector", got)
		}
	}
}

// Regression: cacheable responses without Set-Cookie still work normally

// TestNoSetCookie_StillCached ensures the fix does not break normal caching
// for responses that carry no Set-Cookie header.
func TestNoSetCookie_StillCached(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)
	h := mw(backendWith(200, "public content", "text/plain"))

	doGET(h, "/public") // prime

	w := doGET(h, "/public")
	if got := w.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("public response without Set-Cookie should be cached: want HIT, got %q", got)
	}
}

// Edge cases

// TestSetCookie_EmptyValue — an explicit but empty Set-Cookie header should
// still prevent caching (belt-and-suspenders; some frameworks emit this).
func TestSetCookie_EmptyValue_DoesNotBypassCheck(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)

	// Backend emits Set-Cookie with an empty string value.
	emptySetCookieBackend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Set-Cookie"] = []string{""} // explicitly set empty
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	})

	h := mw(emptySetCookieBackend)
	doGET(h, "/empty-cookie")

	w := doGET(h, "/empty-cookie")
	// An empty Set-Cookie is still a Set-Cookie — the response must not be a HIT.
	if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
		t.Error("response with empty Set-Cookie header should not be cached")
	}
}

// TestSetCookie_CacheControlPublicWithCookie — Cache-Control: public does NOT
// override the Set-Cookie prohibition (RFC 7234 §3).
func TestSetCookie_CacheControlPublicWithCookie(t *testing.T) {
	cfg := &alaye.Cache{
		Enabled: expect.Active,
		Driver:  "memory",
		Methods: []string{"GET"},
		TTL:     expect.Duration(time.Minute),
	}
	mw := New(cfg, nil)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Set-Cookie", "session_id=TRAP; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	})

	h := mw(backend)
	doGET(h, "/public-with-cookie")

	w := doGET(h, "/public-with-cookie")
	if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
		t.Error("Cache-Control: public must not override the Set-Cookie no-cache rule")
	}
}
