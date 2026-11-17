package bugs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/middleware/ratelimit"
	"github.com/golang-jwt/jwt/v5"
)

// Finding: jwt_auth.audience is parsed but never enforced —
// alaye.JWTAuth declares Audience but only uses it for IsZero(), and the JWT
// middleware checks Issuer but never aud. A token minted for a different
// audience with the same shared secret is therefore accepted (classic
// confused-deputy).
func TestBUG_JWTAudienceNotEnforced(t *testing.T) {
	const secret = "shared-hmac-secret"

	sign := func(aud string) string {
		claims := jwt.MapClaims{
			"sub": "user-1",
			"aud": aud,
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return tok
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := auth.JWT(&alaye.JWTAuth{
		Enabled:  expect.Active,
		Secret:   expect.Value(secret),
		Audience: "api-1",
	})(next)

	// Control: a token for the configured audience must pass.
	called = false
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sign("api-1"))
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Fatalf("control failed: token with the configured audience was rejected (%d) — test setup problem", rr.Code)
	}

	// Token minted for a DIFFERENT audience must be rejected.
	called = false
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sign("some-other-service"))
	rr = httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("BUG CONFIRMED: jwt_auth.audience=%q is not enforced — a token with "+
			"aud=%q signed by the same secret was accepted (middleware/auth/jwt.go).",
			"api-1", "some-other-service")
	}
}

// Finding: cluster gossip runs unencrypted and unauthenticated when
// gossip.secret_key is empty — internal/core/alaye/gossip.go:44 treats the key as
// optional, and internal/hub/cluster/manager.go:79-91 then runs memberlist with no
// SecretKey and a nil payload cipher. Any host that can reach the gossip port can
// join and push OpConfig/OpCert/OpSecret payloads.
func TestBUG_GossipAcceptsEmptySecret(t *testing.T) {
	g := alaye.Gossip{
		Enabled:   expect.Active,
		Port:      7946,
		SecretKey: "",
	}
	if err := g.Validate(); err == nil {
		t.Fatalf("BUG CONFIRMED: gossip.secret_key is optional — an enabled cluster starts " +
			"with memberlist running unencrypted and with no membership authentication, so " +
			"any network peer can join and inject configs, certificates and keeper secrets " +
			"(alaye/gossip.go:44, hub/cluster/manager.go:79-91).")
	}
}

// failingSharedState simulates a Redis/cluster backend that is unreachable.
type failingSharedState struct{}

func (failingSharedState) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("shared state unavailable")
}

func (failingSharedState) AllowRateLimit(context.Context, string, int, time.Duration, int) (bool, error) {
	return false, errors.New("shared state unavailable")
}

func (failingSharedState) Close() error { return nil }

// Finding: distributed rate limiting fails open —
// the limiter returns true (allow) on any shared-state error, so a Redis outage
// silently disables rate limiting cluster-wide.
func TestBUG_RateLimitFailsOpenOnSharedStateError(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{
		TTL:        time.Minute,
		MaxEntries: 128,
		IPManager:  zulu.NewIPManager(nil),
		Policy: func(*http.Request) (string, ratelimit.RatePolicy, bool) {
			return "bug-bucket", ratelimit.RatePolicy{
				Requests: 1,
				Window:   time.Minute,
				Burst:    1,
			}, true
		},
		SharedState: failingSharedState{},
	})
	t.Cleanup(rl.Close)

	handler := rl.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := 0
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "198.51.100.7:1234"
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			allowed++
		}
	}

	if allowed == 5 {
		t.Fatalf("BUG CONFIRMED: 5/5 requests exceeded a 1-per-minute limit because the " +
			"shared-state error path returns `true` (allow). A Redis outage therefore " +
			"disables rate limiting for every node instead of failing closed/degrading " +
			"to the local bucket (ratelimit.go:115).")
	}
}
