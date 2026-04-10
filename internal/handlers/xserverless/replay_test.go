package xserverless

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

	h := NewReplay(ReplayConfig{Resource: res, Replay: cfg})
	if h.client.Timeout != testTimeout {
		t.Errorf("timeout: want %v, got %v", testTimeout, h.client.Timeout)
	}

	hDefault := NewReplay(ReplayConfig{Resource: res, Replay: alaye.Replay{URL: "http://localhost"}})
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
		Replay: alaye.Replay{
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
		Replay: alaye.Replay{
			URL:          ts.URL,
			ForwardQuery: expect.NewEnabled(true),
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
		if q.Get("g") != "global" || q.Get("r") != "route" || q.Get("c") != "config" {
			t.Errorf("env resolution failed: %v", q)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL: ts.URL,
			Query: map[string]expect.Value{
				"g": "env.global",
				"r": "env.route",
				"c": "env.config",
			},
			Env: map[string]expect.Value{
				"config": "config",
			},
		},
		GlobalEnv: map[string]expect.Value{"global": "global"},
		RouteEnv:  map[string]expect.Value{"route": "route"},
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
		Replay: alaye.Replay{
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
		Replay: alaye.Replay{
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
		Replay: alaye.Replay{
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
		Replay: alaye.Replay{
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

// Domain Allowlist

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
		{"EXAMPLE.COM", true},
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
		{"example.com", false},
		{"evil.com", false},
		{"example.com.evil.com", false},
	}
	for _, tt := range tests {
		if got := h.domainAllowed(tt.host); got != tt.expected {
			t.Errorf("domainAllowed(%q) = %v; want %v", tt.host, got, tt.expected)
		}
	}
}

func TestDomainAllowed_Blocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
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

// Referer Handling

func TestSetReferer_Auto(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{RefererMode: "auto"}}
	target, _ := url.Parse("https://api.example.com/feed")
	proxyReq, _ := http.NewRequest("GET", target.String(), nil)
	h.setReferer(proxyReq, target, "https://evil.com/page")

	if got := proxyReq.Header.Get("Referer"); got != "https://api.example.com/" {
		t.Errorf("auto mode: want 'https://api.example.com/', got %q", got)
	}
}

func TestSetReferer_Fixed(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{RefererMode: "fixed", RefererValue: "https://agbero.local/"}}
	target, _ := url.Parse("https://upstream.com/data")
	proxyReq, _ := http.NewRequest("GET", target.String(), nil)
	h.setReferer(proxyReq, target, "https://browser.com/page")

	if got := proxyReq.Header.Get("Referer"); got != "https://agbero.local/" {
		t.Errorf("fixed mode: want 'https://agbero.local/', got %q", got)
	}
}

func TestSetReferer_Forward(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{RefererMode: "forward"}}
	target, _ := url.Parse("https://upstream.com/data")
	proxyReq, _ := http.NewRequest("GET", target.String(), nil)
	h.setReferer(proxyReq, target, "https://browser.com/page")

	if got := proxyReq.Header.Get("Referer"); got != "https://browser.com/page" {
		t.Errorf("forward mode: want browser referer, got %q", got)
	}
}

func TestSetReferer_None(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{RefererMode: "none"}}
	target, _ := url.Parse("https://upstream.com/data")
	proxyReq, _ := http.NewRequest("GET", target.String(), nil)
	proxyReq.Header.Set("Referer", "https://should-be-removed.com")
	h.setReferer(proxyReq, target, "https://browser.com/page")

	if proxyReq.Header.Get("Referer") != "" {
		t.Errorf("none mode: want empty Referer, got %q", proxyReq.Header.Get("Referer"))
	}
}

func TestSetReferer_DefaultIsAuto(t *testing.T) {
	h := &Replay{cfg: alaye.Replay{RefererMode: ""}}
	target, _ := url.Parse("https://api.example.com/feed")
	proxyReq, _ := http.NewRequest("GET", target.String(), nil)
	h.setReferer(proxyReq, target, "")

	if got := proxyReq.Header.Get("Referer"); got != "https://api.example.com/" {
		t.Errorf("default mode: want auto-derived referer, got %q", got)
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			StripHeaders:   expect.NewEnabled(true),
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			StripHeaders:   expect.NewEnabled(false),
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
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
	store := nonce.NewStore(time.Minute)
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
				Method:  "meta",
			},
		},
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
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
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
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

func TestAuthToken_ValidWithSecret(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
				Method:  "token",
				Secret:  expect.Value("my-secret-token"),
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

func TestAuthToken_InvalidWithSecret(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
				Method:  "token",
				Secret:  expect.Value("my-secret-token"),
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestAuthToken_MissingHeader(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
				Method:  "token",
				Secret:  expect.Value("secret"),
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

func TestAuthToken_NoSecretConfigured(t *testing.T) {
	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"example.com"},
			Auth: alaye.RestAuth{
				Enabled: expect.NewEnabled(true),
				Method:  "token",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/?url=http://example.com", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 when no secret configured, got %d", rr.Code)
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
		Replay:   alaye.Replay{URL: "http://example.com", Methods: []string{"GET"}},
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
	src.Set("Referer", "https://browser.com/page")

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
	if dst.Get("Referer") != "https://browser.com/page" {
		t.Error("Referer should forward when in safe list")
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
		Replay:   alaye.Replay{URL: slow.URL, Timeout: alaye.Duration(10 * time.Millisecond)},
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
		Replay:   alaye.Replay{URL: ts.URL},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
}

// TTL Policy Tests

func TestTTLPolicy_CachingWithContentType(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"test"}`))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				TTLPolicy: alaye.TTLPolicy{
					Enabled: expect.Active,
					Default: alaye.Duration(30 * time.Second),
					ContentType: map[string]alaye.Duration{
						"application/json": alaye.Duration(5 * time.Minute),
					},
				},
				Methods: []string{"GET"},
			},
		},
	})

	// First request - cache miss
	req1 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)

	// Second request - should be cache hit
	req2 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)

	if cacheHits != 1 {
		t.Errorf("expected 1 upstream call (cache hit), got %d", cacheHits)
	}

	if rr2.Header().Get("X-Cache-Status") != "HIT" {
		t.Errorf("expected cache HIT, got %s", rr2.Header().Get("X-Cache-Status"))
	}
}

func TestTTLPolicy_DisabledCache(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Inactive,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				Methods: []string{"GET"},
			},
		},
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	if cacheHits != 3 {
		t.Errorf("expected 3 upstream calls (cache disabled), got %d", cacheHits)
	}
}

func TestTTLPolicy_ZeroTTLNoCaching(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(0), // Zero TTL
				TTLPolicy: alaye.TTLPolicy{
					Enabled: expect.Active,
					Default: alaye.Duration(0), // Zero default
				},
				Methods: []string{"GET"},
			},
		},
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	if cacheHits != 3 {
		t.Errorf("expected 3 upstream calls (zero TTL), got %d", cacheHits)
	}
}

func TestTTLPolicy_CacheKeyWithScope(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response for " + r.Header.Get("Accept-Language")))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				TTLPolicy: alaye.TTLPolicy{
					Enabled:  expect.Active,
					Default:  alaye.Duration(1 * time.Minute),
					KeyScope: []string{"header:Accept-Language"},
				},
				Methods: []string{"GET"},
			},
		},
	})

	// Request with Accept-Language: en
	req1 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req1.Header.Set("Accept-Language", "en")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)

	// Request with Accept-Language: fr (different cache key)
	req2 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req2.Header.Set("Accept-Language", "fr")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)

	// Request with Accept-Language: en again (should be cache hit)
	req3 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	req3.Header.Set("Accept-Language", "en")
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)

	if cacheHits != 2 {
		t.Errorf("expected 2 upstream calls (different cache keys), got %d", cacheHits)
	}

	if rr3.Header().Get("X-Cache-Status") != "HIT" {
		t.Errorf("expected cache HIT for same Accept-Language, got %s", rr3.Header().Get("X-Cache-Status"))
	}
}

func TestTTLPolicy_CacheControlNoStore(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secret response"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				Methods: []string{"GET"},
			},
		},
	})

	// First request - no-store response should NOT be cached
	req1 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)

	// Second request - should hit upstream again because first wasn't cached
	req2 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)

	// HTTP spec: no-store responses MUST NOT be cached
	if cacheHits != 2 {
		t.Errorf("HTTP spec violation: expected 2 upstream calls (no-store not cached), got %d", cacheHits)
	}

	// X-Cache-Status should be MISS for both (no caching)
	if rr1.Header().Get("X-Cache-Status") == "HIT" {
		t.Error("first request should not be HIT")
	}
	if rr2.Header().Get("X-Cache-Status") == "HIT" {
		t.Error("second request should not be HIT (no-store prevented caching)")
	}
}

func TestTTLPolicy_CacheControlMaxAge(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("cachable response"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				Methods: []string{"GET"},
			},
		},
	})

	req1 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)

	if cacheHits != 1 {
		t.Errorf("expected 1 upstream call (cache hit), got %d", cacheHits)
	}

	if rr2.Header().Get("X-Cache-Status") != "HIT" {
		t.Errorf("expected cache HIT, got %s", rr2.Header().Get("X-Cache-Status"))
	}
}

func TestTTLPolicy_PostMethodNotCached(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("post response"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				Methods: []string{"GET"}, // Only GET is cached
			},
		},
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/?url="+ts.URL, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	if cacheHits != 2 {
		t.Errorf("expected 2 upstream calls (POST not cached), got %d", cacheHits)
	}
}

func TestTTLPolicy_Non200StatusNotCached(t *testing.T) {
	cacheHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheHits++
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	h := NewReplay(ReplayConfig{
		Resource: resource.New(),
		Replay: alaye.Replay{
			URL:            "",
			AllowedDomains: []string{"127.0.0.1", "localhost"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     alaye.Duration(1 * time.Minute),
				Methods: []string{"GET"},
			},
		},
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/?url="+ts.URL, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	if cacheHits != 2 {
		t.Errorf("expected 2 upstream calls (404 not cached), got %d", cacheHits)
	}
}
