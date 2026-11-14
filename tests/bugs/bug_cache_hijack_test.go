package bugs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/middleware/attic"
)

// Finding: the cache response recorder cannot be unwrapped/hijacked —
// internal/middleware/attic/recorder.go implements Flush() but neither
// Unwrap() nor Hijack(), and attic is the outermost wrapper
// (handlers/routes.go:118). httputil.ReverseProxy upgrades use
// http.NewResponseController(...).Hijack(), which fails with ErrNotSupported, so
// enabling `cache` on a route silently breaks every WebSocket/upgrade route.
func TestBUG_CacheMiddlewareBreaksConnectionHijack(t *testing.T) {
	// Handler that needs the raw connection (WebSocket / CONNECT / HTTP upgrade).
	hijackAttempt := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, err.Error())
			return
		}
		_ = conn.Close()
	})

	// Control: without the cache middleware the hijack succeeds (the client sees
	// a closed connection instead of an HTTP response).
	control := httptest.NewServer(hijackAttempt)
	defer control.Close()
	if resp, err := http.Get(control.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("setup problem: hijack unexpectedly failed without any middleware (status %d)", resp.StatusCode)
	}

	// With the cache middleware installed exactly as routes.go does it.
	cfg := &alaye.Cache{
		Enabled:          expect.Active,
		Driver:           "memory",
		TTL:              expect.Duration(time.Minute),
		Methods:          []string{http.MethodGet},
		MaxCacheableSize: 1 << 20,
	}
	guarded := httptest.NewServer(attic.New(cfg, testLogger)(hijackAttempt))
	defer guarded.Close()

	resp, err := http.Get(guarded.URL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusInternalServerError {
			t.Fatalf("BUG CONFIRMED: the cache middleware prevents connection hijacking "+
				"(status %d, body=%q). attic's recorder lacks Unwrap()/Hijack(), so "+
				"httputil.ReverseProxy cannot tunnel WebSocket/upgrade requests on any "+
				"route with `cache { enabled = true }`.",
				resp.StatusCode, string(body))
		}
		t.Fatalf("unexpected response through cache middleware (status %d)", resp.StatusCode)
	}
}
