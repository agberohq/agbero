package bugs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

// Finding: cache ordered outside auth — internal/handlers/routes.go:118.
//
// wrapHandler() applies auth.JWT/Basic/Forward/OAuth first and then wraps the
// result with attic.New(...), which makes the cache the OUTERMOST middleware.
// Execution order is therefore cache -> auth, so a cache hit is served without
// any authentication taking place. The cache key (internal/pkg/stash/memory.go:131)
// contains no identity material, so the entry stored for one authenticated user
// is reused for anonymous requests.
func TestBUG_CacheServesAuthenticatedResponseToAnonymousClient(t *testing.T) {
	const secretBody = "PRIVATE-ALICE-DATA"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(secretBody))
	}))
	defer backend.Close()

	var authHits atomic.Int32
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHits.Add(1)
		if r.Header.Get("Cookie") == "session=alice" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer authSrv.Close()

	ts := startTestServer(t, serverOpts{
		hosts: func(t *testing.T, hm *discovery.Host) {
			hm.Set("cache.example", &alaye.Host{
				Domains: []string{"cache.example"},
				Routes: []alaye.Route{{
					Enabled: expect.Active,
					Path:    "/",
					Backends: alaye.Backend{
						Enabled: expect.Active,
						Servers: []alaye.Server{alaye.NewServer(backend.URL)},
					},
					// Cookie based auth: this is the case the cache key does not cover.
					ForwardAuth: alaye.ForwardAuth{
						Enabled:      expect.Active,
						URL:          authSrv.URL,
						AllowPrivate: true,
						OnFailure:    "deny",
					},
					Cache: alaye.Cache{
						Enabled: expect.Active,
						TTL:     expect.Duration(time.Minute),
					},
					Compression: alaye.Compression{Enabled: expect.Inactive},
				}},
			})
		},
	})

	// 1) Authenticated request: populates the cache with Alice's private payload.
	resp, body := doRequest(t, http.MethodGet, ts.httpURL(""), "cache.example", "/",
		map[string]string{"Cookie": "session=alice"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, secretBody) {
		t.Fatalf("setup: authenticated request expected 200 + payload, got %d / %q", resp.StatusCode, body)
	}

	// 2) Anonymous request: forward_auth must reject it (403).
	resp2, body2 := doRequest(t, http.MethodGet, ts.httpURL(""), "cache.example", "/", nil)

	if resp2.StatusCode == http.StatusOK && strings.Contains(body2, secretBody) {
		t.Fatalf("BUG CONFIRMED: cache is evaluated before authentication — the anonymous "+
			"request received Alice's cached private body (status=%d, X-Cache=%q, body=%q). "+
			"Forward-auth was called %d time(s), so it never saw this request. "+
			"Fix: apply attic.New() BEFORE the auth middleware in handlers.wrapHandler, "+
			"or refuse cache when an auth block is active.",
			resp2.StatusCode, resp2.Header.Get("X-Cache"), strings.TrimSpace(body2), authHits.Load()-1)
	}
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected anonymous request to be rejected with 403, got %d (body=%q)",
			resp2.StatusCode, body2)
	}

	// 3) The cache must still work for authenticated callers (the fix must move
	// the cache, not disable it).
	resp3, body3 := doRequest(t, http.MethodGet, ts.httpURL(""), "cache.example", "/",
		map[string]string{"Cookie": "session=alice"})
	if resp3.StatusCode != http.StatusOK || !strings.Contains(body3, secretBody) {
		t.Fatalf("cache regression: authenticated request expected 200 + payload, got %d / %q",
			resp3.StatusCode, body3)
	}
	if got := resp3.Header.Get("X-Cache"); got != "HIT" {
		t.Fatalf("cache regression: expected X-Cache: HIT on the repeat authenticated request, got %q", got)
	}
}
