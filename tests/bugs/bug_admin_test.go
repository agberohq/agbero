package bugs

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

// Finding: admin auth endpoints have no brute-force throttling —
// internal/admin.go:814 buildAdminRateLimiter returns nil unless rate_limits is
// explicitly enabled with rules, so /login and /login/challenge are unthrottled
// (bcrypt is the only cost). handleLoginChallenge also consumes the challenge JTI
// with a non-atomic Get()+SetTTL() pair (admin.go:451-459) instead of the atomic
// Compute() already used by middleware/nonce/store.go:72.
func TestBUG_AdminTOTPHasNoThrottle(t *testing.T) {
	ts := startTestServer(t, serverOpts{admin: true, totp: true})

	const maxAttempts = 12
	for i := 0; i < maxAttempts; i++ {
		token, loginStatus, loginBody := adminChallengeToken(t, ts)
		if loginStatus == http.StatusTooManyRequests {
			return // throttled at /login: correct behaviour
		}
		if loginStatus != http.StatusAccepted {
			t.Fatalf("unexpected status %d from /login (body=%q)", loginStatus, loginBody)
		}

		status, body := postJSON(t, ts.adminURL("/login/challenge"),
			map[string]string{"totp": "000000"}, token)

		lower := strings.ToLower(body)
		if status == http.StatusTooManyRequests ||
			strings.Contains(lower, "too many") ||
			strings.Contains(lower, "locked") ||
			strings.Contains(lower, "throttl") {
			return // throttled: correct behaviour
		}
		if status != http.StatusUnauthorized {
			t.Fatalf("unexpected status %d on wrong TOTP (body=%q)", status, body)
		}
	}

	t.Fatalf("BUG CONFIRMED: %d consecutive wrong TOTP codes were processed with no "+
		"throttling, lockout or attempt counter (each guess only costs one "+
		"re-authentication). TOTP is 6 digits = 10^6 space; without a limiter this is "+
		"online-bruteforceable. Same for the keeper passphrase accepted by "+
		"/login/challenge.", maxAttempts)
}

// Finding: /status disclosed keeper state, telemetry state and cluster
// membership to unauthenticated callers (admin.go registered it outside the auth
// group). It is still public — the admin UI login screen probes it for `locked` —
// but the sensitive fields must only be present for an authenticated caller.
func TestBUG_AdminStatusLeaksClusterState(t *testing.T) {
	ts := startTestServer(t, serverOpts{admin: true})

	// Unauthenticated: minimal payload only.
	status, body := getBearer(t, ts.adminURL("/status"), "")
	if status != http.StatusOK {
		t.Fatalf("expected 200 for the public probe, got %d: %s", status, body)
	}
	if !strings.Contains(body, "locked") {
		t.Fatalf("the UI login probe needs the `locked` field, got %q", strings.TrimSpace(body))
	}
	for _, leaked := range []string{"cluster_members", "telemetry"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("BUG CONFIRMED: unauthenticated GET /status returned %q (body=%q) — "+
				"only {status, locked} may be public.", leaked, strings.TrimSpace(body))
		}
	}

	// Authenticated: full payload.
	loginStatus, loginBody := postJSON(t, ts.adminURL("/login"), map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	}, "")
	if loginStatus != http.StatusOK {
		t.Fatalf("setup: login failed (%d): %s", loginStatus, loginBody)
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(loginBody), &login); err != nil || login.Token == "" {
		t.Fatalf("setup: decode login token: %v (%s)", err, loginBody)
	}

	status, body = getBearer(t, ts.adminURL("/status"), login.Token)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for an authenticated caller, got %d: %s", status, body)
	}
	if !strings.Contains(body, "cluster_members") {
		t.Fatalf("authenticated GET /status should include cluster_members, got %q",
			strings.TrimSpace(body))
	}
}

// TestRace_AdminChallengeTokenConsumption guards the single-use property of the
// challenge JTI. It failed to reproduce before the fix (the Get()->SetTTL()
// window at admin.go:492 was sub-microsecond) and now asserts the invariant that
// matters: of all concurrent requests presenting the same token, at most one
// reaches TOTP / keeper-passphrase verification. The admin login limiter caps how
// many requests reach the handler at all, which is why the assertion is "at most
// one", not "exactly one".
func TestRace_AdminChallengeTokenConsumption(t *testing.T) {
	ts := startTestServer(t, serverOpts{admin: true, totp: true})

	token, loginStatus, loginBody := adminChallengeToken(t, ts)
	if loginStatus != http.StatusAccepted {
		t.Skipf("login throttled before the race could be exercised (status %d, body=%q)", loginStatus, loginBody)
	}

	const goroutines = 48
	var (
		start     = make(chan struct{})
		wg        sync.WaitGroup
		passed    atomic.Int32
		blocked   atomic.Int32
		throttled atomic.Int32
	)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status, body := postJSON(t, ts.adminURL("/login/challenge"),
				map[string]string{"totp": "000000"}, token)
			switch {
			case status == http.StatusTooManyRequests:
				throttled.Add(1)
			case status == http.StatusUnauthorized && strings.Contains(body, "already used"):
				blocked.Add(1)
			case status == http.StatusUnauthorized:
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if passed.Load() > 1 {
		t.Fatalf("BUG CONFIRMED: one challenge token was accepted by %d concurrent "+
			"requests (only 1 may reach TOTP verification, %d were rejected as already "+
			"used). The single-use check is a TOCTOU race — use an atomic "+
			"LoadOrStore/Compute on TimeStore instead of Get()+SetTTL().",
			passed.Load(), blocked.Load())
	}
	t.Logf("%d concurrent replays: %d reached verification, %d already-used, %d rate-limited",
		goroutines, passed.Load(), blocked.Load(), throttled.Load())
}

// Finding: /config/global leaks non-expect.Value secrets —
// helpers.go:13 sanitizeGlobalConfig() blanks gossip.secret_key, oauth secrets and
// storage paths but not gossip.shared_state.redis.password (a plain string in
// alaye/gossip.go:30) nor tunnels[].username, so an admin token (or anyone
// reading the response) obtains backend infrastructure credentials.
func TestBUG_GlobalConfigDumpLeaksRedisPassword(t *testing.T) {
	const redisPassword = "redis-super-secret"

	ts := startTestServer(t, serverOpts{
		admin: true,
		global: func(t *testing.T, g *alaye.Global) {
			g.Gossip.SharedState = alaye.SharedState{
				Enabled: expect.Inactive, // stored & serialised regardless
				Driver:  "redis",
				Redis: &alaye.RedisState{
					Host:     "127.0.0.1",
					Port:     6379,
					Password: redisPassword,
				},
			}
		},
	})

	// Full password login (TOTP disabled) to obtain a usable admin token.
	status, body := postJSON(t, ts.adminURL("/login"), map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("setup: /login expected 200, got %d: %s", status, body)
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &login); err != nil || login.Token == "" {
		t.Fatalf("setup: decode login token: %v (%s)", err, body)
	}

	status, dump := getBearer(t, ts.adminURL("/config/global"), login.Token)
	if status != http.StatusOK {
		t.Fatalf("setup: /config/global expected 200, got %d: %s", status, dump)
	}

	if strings.Contains(dump, redisPassword) {
		t.Fatalf("BUG CONFIRMED: GET /config/global returned the Redis password %q in "+
			"cleartext. sanitizeGlobalConfig (helpers.go:13) redacts gossip.secret_key "+
			"but not gossip.shared_state.redis.password (plain string), so infrastructure "+
			"credentials leak through the config dump.", redisPassword)
	}
}
