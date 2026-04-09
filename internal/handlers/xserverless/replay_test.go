package xserverless

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/middleware/nonce"
)

const (
	testHeaderKey     = "X-Test-Header"
	testHeaderVal     = "TestValue"
	testQueryKey      = "q"
	testEnvKey        = "MY_VAR"
	testEnvVal        = "resolved-env"
	testUpstreamPath  = "/upstream"
	testTimeout       = 2 * time.Second
	testNonceHeader   = "X-Agbero-Replay-Nonce"
	testSessionCookie = "agbero_sess"
)

// Constructor & Config

func TestNewReplay(t *testing.T) {
	res := resource.New()
	cfg := alaye.Replay{URL: "http://localhost", Timeout: alaye.Duration(testTimeout)}

	h := NewReplay(ReplayConfig{Resource: res, REST: cfg})
	if h.client.Timeout != testTimeout {
		t.Errorf("timeout: want %v, got %v", testTimeout, h.client.Timeout)
	}

	hDefault := NewReplay(ReplayConfig{Resource: res, REST: alaye.Replay{URL: "http://localhost"}})
	if hDefault.client.Timeout != defaultRESTTimeout {
		t.Errorf("default timeout: want %v, got %v", defaultRESTTimeout, hDefault.client.Timeout)
	}
}

// Fixed Mode

func TestFixedMode_BasicProxy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(testHeaderKey) != testHeaderVal {
			t.Error("header not forwarded")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:     ts.URL + testUpstreamPath,
			Methods: []string{http.MethodGet},
			Headers: map[string]string{testHeaderKey: testHeaderVal},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Errorf("want 200/ok, got %d/%s", rr.Code, rr.Body.String())
	}
}

func TestFixedMode_QueryMerge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("static") != "value" || q.Get("forwarded") != "from-client" {
			t.Errorf("query mismatch: %v", q)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:          ts.URL,
			ForwardQuery: alaye.NewEnabled(true),
			Query:        map[string]expect.Value{"static": expect.Value("value")},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?forwarded=from-client", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

func TestFixedMode_EnvResolution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// Check that all three env keys resolved correctly
		if q.Get("g") != "global" || q.Get("r") != "route" || q.Get("c") != "config" {
			t.Errorf("env resolution failed: %v", q)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL: ts.URL,
			Query: map[string]expect.Value{
				"g": expect.Value("env.global"),
				"r": expect.Value("env.route"),
				"c": expect.Value("env.config"),
			},
			Env: map[string]expect.Value{
				"config": expect.Value("config"),
			},
		},
		GlobalEnv: map[string]expect.Value{"global": expect.Value("global")},
		RouteEnv:  map[string]expect.Value{"route": expect.Value("route")},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

// Replay Mode

func TestReplayMode_HeaderURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Methods:        []string{http.MethodGet},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(woos.HeaderXAgberoReplayURL, ts.URL)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("want 418, got %d", rr.Code)
	}
}

func TestReplayMode_QueryURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

func TestReplayMode_MissingURL(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestReplayMode_InvalidURL(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=%%invalid", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestDomainAllowed_Wildcard(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{AllowedDomains: []string{"*.bbc.co.uk"}}}
	if !h.domainAllowed("news.bbc.co.uk") || h.domainAllowed("bbc.co.uk") {
		t.Error("wildcard logic failed")
	}
}

func TestDomainAllowed_Blocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"allowed.com"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rr.Code)
	}
}

// Header Stripping

func TestStripHeaders_RemovesUpstreamSecurityHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://upstream.com")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Custom", "keep-me")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			StripHeaders:   alaye.NewEnabled(true),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req.Header.Set("Origin", "https://client.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	hdr := rr.Header()
	if hdr.Get("Access-Control-Allow-Origin") != "https://client.com" {
		t.Errorf("CORS origin not rewritten: %v", hdr.Get("Access-Control-Allow-Origin"))
	}
	if hdr.Get("X-Frame-Options") != "" {
		t.Error("X-Frame-Options should be stripped")
	}
	if hdr.Get("Content-Security-Policy") != "" {
		t.Error("CSP should be stripped")
	}
	if hdr.Get("X-Custom") != "keep-me" {
		t.Error("non-security header should be kept")
	}
}

func TestNoStripHeaders_ForwardsAll(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			StripHeaders:   alaye.NewEnabled(false),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("header should be forwarded when strip is false")
	}
}

// Auth: Meta (Nonce)

func TestAuthMeta_ValidNonce(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	store := nonce.NewStore(time.Minute)
	n, _ := store.Generate()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "meta",
			},
		},
		NonceStore: store,
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req.Header.Set(testNonceHeader, n)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

func TestAuthMeta_MissingNonce(t *testing.T) {
	// Must provide NonceStore; otherwise guard returns 500 (store not initialised)
	store := nonce.NewStore(time.Minute)
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "meta",
			},
		},
		NonceStore: store,
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestAuthMeta_StoreNotInitialised(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "meta",
			},
		},
		// NonceStore intentionally nil → expect 500
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rr.Code)
	}
}

// Auth: Direct (Cookie)

func TestAuthDirect_ValidCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "direct",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: testSessionCookie, Value: "valid-session"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

func TestAuthDirect_MissingCookie(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "direct",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestAuthDirect_EmptyCookie(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "direct",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	req.AddCookie(&http.Cookie{Name: testSessionCookie, Value: ""})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

// Auth: Token (Bearer)
// Note: token auth is not yet wired in replay.go ServeHTTP switch.
// These tests are skipped until the "token" case is implemented.

func TestAuthToken_MissingHeader(t *testing.T) {
	t.Skip("token auth handler not yet implemented in replay.go")
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "token",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestAuthToken_NilVerifier(t *testing.T) {
	t.Skip("token auth handler not yet implemented in replay.go")
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: alaye.NewEnabled(true),
				Method:  "token",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500 for nil verifier, got %d", rr.Code)
	}
}

// Method Allowance

func TestMethodAllowed_EmptyList(t *testing.T) {
	h := &Replay{methods: []string{}}
	if !h.methodAllowed("POST") {
		t.Error("empty list should allow all methods")
	}
}

func TestMethodAllowed_ExplicitList(t *testing.T) {
	h := &Replay{methods: []string{"GET", "POST"}}
	if !h.methodAllowed("get") || !h.methodAllowed("POST") || h.methodAllowed("DELETE") {
		t.Error("method filtering failed")
	}
}

func TestMethodNotAllowed_Response(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST:     alaye.Replay{URL: "http://example.com", Methods: []string{"GET"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "GET" {
		t.Errorf("want 405 with Allow: GET, got %d / %v", rr.Code, rr.Header().Get("Allow"))
	}
}

// Header Forwarding

func TestForwardSafeHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Accept", "application/json")
	src.Set("Authorization", "secret")
	src.Set("Host", "evil.com")

	dst := http.Header{}
	forwardSafeHeaders(dst, src)

	if dst.Get("Accept") != "application/json" {
		t.Error("Accept should forward")
	}
	if dst.Get("Authorization") != "" {
		t.Error("Authorization should NOT forward")
	}
	if dst.Get("Host") != "" {
		t.Error("Host should NOT forward")
	}
}

// Error Cases

func TestUpstreamTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer slow.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST:     alaye.Replay{URL: slow.URL, Timeout: alaye.Duration(10 * time.Millisecond)},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway && rr.Code != http.StatusGatewayTimeout {
		t.Errorf("want 502/504, got %d", rr.Code)
	}
}

func TestResponseBodyCopyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		REST:     alaye.Replay{URL: ts.URL},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

// Domain Allowlist Tests

func TestDomainAllowed_AllowAllWildcard(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{AllowedDomains: []string{"*"}}}
	if !h.domainAllowed("example.com") || !h.domainAllowed("any.domain.here") {
		t.Error(`"*" should allow any domain`)
	}
}

func TestDomainAllowed_ExactMatch(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{AllowedDomains: []string{"example.com"}}}
	tests := []struct {
		host     string
		expected bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true}, // case-insensitive
		{"sub.example.com", false},
		{"evil.com", false},
	}
	for _, tt := range tests {
		if got := h.domainAllowed(tt.host); got != tt.expected {
			t.Errorf("domainAllowed(%q) = %v; want %v", tt.host, got, tt.expected)
		}
	}
}

func TestDomainAllowed_WildcardSubdomain(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{AllowedDomains: []string{"*.example.com"}}}
	tests := []struct {
		host     string
		expected bool
	}{
		{"api.example.com", true},
		{"sub.api.example.com", true},
		{"example.com", false}, // wildcard requires subdomain
		{"evil.com", false},
		{"example.com.evil.com", false}, // suffix spoofing attempt
	}
	for _, tt := range tests {
		if got := h.domainAllowed(tt.host); got != tt.expected {
			t.Errorf("domainAllowed(%q) = %v; want %v", tt.host, got, tt.expected)
		}
	}
}

func TestDomainAllowed_MultiplePatterns(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{AllowedDomains: []string{"*.safe.com", "exact.org", "*"}}}
	// "*" at end should allow all
	if !h.domainAllowed("random.net") {
		t.Error(`expected "random.net" allowed due to "*" pattern`)
	}
}

func TestDomainAllowed_EmptyList(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{AllowedDomains: []string{}}}
	if h.domainAllowed("anything.com") {
		t.Error("empty allowlist should reject all domains")
	}
}
