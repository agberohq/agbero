package attic

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

type testRequest struct {
	method       string
	path         string
	body         string
	reqHeaders   map[string]string
	respHeaders  map[string]string
	respStatus   int
	expectStatus int
}

func TestCacheMiddleware(t *testing.T) {
	logger := ll.New(" ").Disable()
	tests := []struct {
		name           string
		config         *alaye.Cache
		requests       []testRequest
		expectedHits   []bool
		expectedBodies []string
	}{
		{
			name: "Cache Hit After Miss",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{method: "GET", path: "/test", body: "response1"},
				{method: "GET", path: "/test", body: "response2"},
			},
			expectedHits:   []bool{false, true},
			expectedBodies: []string{"response1", "response1"},
		},
		{
			name: "Different Paths Different Cache",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{method: "GET", path: "/a", body: "a-response"},
				{method: "GET", path: "/b", body: "b-response"},
			},
			expectedHits:   []bool{false, false},
			expectedBodies: []string{"a-response", "b-response"},
		},
		{
			name: "Query String Differentiation",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{method: "GET", path: "/search?q=foo", body: "foo results"},
				{method: "GET", path: "/search?q=bar", body: "bar results"},
			},
			expectedHits:   []bool{false, false},
			expectedBodies: []string{"foo results", "bar results"},
		},
		{
			name: "POST Not Cached",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{method: "POST", path: "/test", body: "post1"},
				{method: "POST", path: "/test", body: "post2"},
			},
			expectedHits:   []bool{false, false},
			expectedBodies: []string{"post1", "post2"},
		},
		{
			name: "Cache Control No-Store",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{
					method:      "GET",
					path:        "/no-store",
					body:        "secret",
					respHeaders: map[string]string{"Cache-Control": "no-store"},
				},
				{
					method: "GET",
					path:   "/no-store",
					body:   "secret2",
				},
			},
			expectedHits:   []bool{false, false},
			expectedBodies: []string{"secret", "secret2"},
		},
		{
			name: "Vary Header Respect",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{
					method:      "GET",
					path:        "/vary",
					body:        "english",
					reqHeaders:  map[string]string{"Accept-Language": "en"},
					respHeaders: map[string]string{"Vary": "Accept-Language"},
				},
				{
					method:      "GET",
					path:        "/vary",
					body:        "french",
					reqHeaders:  map[string]string{"Accept-Language": "fr"},
					respHeaders: map[string]string{"Vary": "Accept-Language"},
				},
				{
					method:      "GET",
					path:        "/vary",
					body:        "english",
					reqHeaders:  map[string]string{"Accept-Language": "en"},
					respHeaders: map[string]string{"Vary": "Accept-Language"},
				},
			},
			expectedHits:   []bool{false, false, true},
			expectedBodies: []string{"english", "french", "english"},
		},
		{
			name: "Conditional Request ETag",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{
					method:      "GET",
					path:        "/etag",
					body:        "content",
					respHeaders: map[string]string{"ETag": `"abc123"`},
				},
				{
					method:       "GET",
					path:         "/etag",
					reqHeaders:   map[string]string{"If-None-Match": `"abc123"`},
					expectStatus: http.StatusNotModified,
				},
			},
			expectedHits:   []bool{false, true},
			expectedBodies: []string{"content", ""},
		},
		{
			name: "Large Response Not Cached",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     expect.Duration(time.Minute),
			},
			requests: []testRequest{
				{method: "GET", path: "/large", body: strings.Repeat("x", 6*1024*1024)},
				{method: "GET", path: "/large", body: strings.Repeat("x", 6*1024*1024)},
			},
			expectedHits:   []bool{false, false},
			expectedBodies: []string{strings.Repeat("x", 6*1024*1024), strings.Repeat("x", 6*1024*1024)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := New(tt.config, logger)
			if handler == nil {
				t.Fatal("handler is nil")
			}

			for i, req := range tt.requests {
				r := httptest.NewRequest(req.method, req.path, nil)
				for k, v := range req.reqHeaders {
					r.Header.Set(k, v)
				}
				w := httptest.NewRecorder()

				reqCopy := req
				handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for k, v := range reqCopy.respHeaders {
						w.Header().Set(k, v)
					}
					if reqCopy.respStatus != 0 {
						w.WriteHeader(reqCopy.respStatus)
					}
					w.Write([]byte(reqCopy.body))
				})

				wrapped := handler(handlerFunc)
				wrapped.ServeHTTP(w, r)

				resp := w.Result()
				wantStatus := req.expectStatus
				if wantStatus == 0 {
					wantStatus = http.StatusOK
				}
				if resp.StatusCode != wantStatus {
					t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, wantStatus)
				}

				cacheStatus := resp.Header.Get("X-Cache")
				if tt.expectedHits[i] && cacheStatus != "HIT" {
					t.Errorf("request %d: expected HIT, got %s", i, cacheStatus)
				}
				if !tt.expectedHits[i] && cacheStatus == "HIT" {
					t.Errorf("request %d: expected MISS, got HIT", i)
				}

				body := new(bytes.Buffer)
				body.ReadFrom(resp.Body)
				resp.Body.Close()

				if body.String() != tt.expectedBodies[i] {
					t.Errorf("request %d: body = %q, want %q", i, body.String(), tt.expectedBodies[i])
				}
			}
		})
	}
}

func TestCacheDisabled(t *testing.T) {
	logger := ll.New(" ").Disable()
	cfg := &alaye.Cache{
		Enabled: expect.Inactive,
	}
	handler := New(cfg, logger)
	if handler == nil {
		t.Fatal("handler is nil")
	}

	called := false
	wrapped := handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte("ok"))
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)

	if !called {
		t.Error("handler not called when cache disabled")
	}
	if w.Header().Get("X-Cache") != "" {
		t.Error("X-Cache header set when cache disabled")
	}
}

// Helpers

func enabledCache(driver string) *alaye.Cache {
	return &alaye.Cache{
		Enabled: expect.Active,
		Driver:  driver,
		TTL:     expect.Duration(5 * time.Minute),
		Methods: []string{"GET"},
	}
}

func backendWith(status int, body, ct string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func doGET(handler http.Handler, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// X-Cache-Status header (CDN: HIT / MISS / BYPASS / STALE)

func TestHandler_XCacheStatus_Miss(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWith(200, "hello", "text/plain"))

	w := doGET(h, "/test")
	if got := w.Header().Get("X-Cache-Status"); got != "MISS" {
		t.Errorf("first request: want X-Cache-Status=MISS, got %q", got)
	}
}

func TestHandler_XCacheStatus_Hit(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWith(200, "hello", "text/plain"))

	doGET(h, "/hit-test") // prime
	w := doGET(h, "/hit-test")
	if got := w.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("second request: want X-Cache-Status=HIT, got %q", got)
	}
}

func TestHandler_XCacheStatus_Bypass_LargeBody(t *testing.T) {
	cfg := enabledCache("memory")
	cfg.MaxCacheableSize = 10 // 10 bytes — tiny limit to force bypass

	mw := New(cfg, nil)
	h := mw(backendWith(200, strings.Repeat("X", 100), "text/plain"))

	w := doGET(h, "/large")
	if got := w.Header().Get("X-Cache-Status"); got != "BYPASS" {
		t.Errorf("oversized response: want X-Cache-Status=BYPASS, got %q", got)
	}

	// Second request should also be BYPASS (not cached)
	w2 := doGET(h, "/large")
	if got := w2.Header().Get("X-Cache-Status"); got != "BYPASS" {
		t.Errorf("second oversized request: want X-Cache-Status=BYPASS, got %q", got)
	}
}

func TestHandler_XCacheStatus_NotSetWhenCacheDisabled(t *testing.T) {
	cfg := &alaye.Cache{Enabled: expect.Inactive}
	mw := New(cfg, nil)
	h := mw(backendWith(200, "ok", "text/plain"))

	w := doGET(h, "/disabled")
	// When cache is off the middleware is a passthrough — no X-Cache-Status
	if got := w.Header().Get("X-Cache-Status"); got != "" {
		t.Errorf("disabled cache should not set X-Cache-Status, got %q", got)
	}
}

// MaxCacheableSize — bypass logic

func TestHandler_MaxCacheableSize_BelowLimit_IsCached(t *testing.T) {
	cfg := enabledCache("memory")
	cfg.MaxCacheableSize = 1024 // 1KB

	mw := New(cfg, nil)
	h := mw(backendWith(200, "small", "text/plain"))

	doGET(h, "/small") // prime
	w := doGET(h, "/small")
	if got := w.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("small response should be cached: want HIT, got %q", got)
	}
}

func TestHandler_MaxCacheableSize_ZeroMeansDefaultLimit(t *testing.T) {
	cfg := enabledCache("memory")
	cfg.MaxCacheableSize = 0 // 0 = use built-in default

	mw := New(cfg, nil)
	h := mw(backendWith(200, "body", "text/plain"))

	doGET(h, "/default-limit") // prime
	w := doGET(h, "/default-limit")
	if got := w.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("zero MaxCacheableSize should fall back to default: want HIT, got %q", got)
	}
}

// Surrogate tag extraction from Surrogate-Key / Cache-Tag headers

func backendWithTags(tags string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Surrogate-Key", tags)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "tagged content")
	})
}

func TestHandler_SurrogateTags_ParsedOnStore(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWithTags("product:1 category:books"))

	doGET(h, "/tagged") // caches entry with tags
	w := doGET(h, "/tagged")
	if got := w.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("tagged entry should be cached: want HIT, got %q", got)
	}
	// Surrogate-Key header should be forwarded to the client
	if got := w.Header().Get("Surrogate-Key"); got == "" {
		t.Error("Surrogate-Key header should be forwarded on HIT")
	}
}

// Age header on HIT

func TestHandler_AgeHeader_OnHit(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWith(200, "body", "text/plain"))

	doGET(h, "/age-test") // prime
	w := doGET(h, "/age-test")

	// Age must be a non-negative integer string
	age := w.Header().Get("Age")
	if age == "" {
		t.Error("HIT response should include Age header")
	}
}

// Stale-while-revalidate — serve stale immediately, refresh in background

func TestHandler_StaleWhileRevalidate_ServesStaleImmediately(t *testing.T) {
	cfg := enabledCache("memory")
	cfg.TTLPolicy = alaye.TTLPolicy{
		Enabled:              expect.Active,
		Default:              expect.Duration(10 * time.Millisecond), // tiny TTL
		StaleWhileRevalidate: expect.Duration(5 * time.Second),
	}

	calls := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "v1")
	})

	mw := New(cfg, nil)
	h := mw(backend)

	doGET(h, "/swr") // prime (call 1)

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	w := doGET(h, "/swr") // should serve stale while revalidating in bg
	if got := w.Header().Get("X-Cache-Status"); got != "STALE" {
		t.Errorf("expired entry within swr window: want STALE, got %q", got)
	}
	if body := w.Body.String(); body != "v1" {
		t.Errorf("stale body: want v1, got %q", body)
	}
}

// Conditional requests — If-None-Match on cached entry

func TestHandler_ConditionalRequest_IfNoneMatch_Returns304(t *testing.T) {
	mw := New(enabledCache("memory"), nil)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "body")
	})

	h := mw(backend)
	doGET(h, "/etag") // prime

	r := httptest.NewRequest(http.MethodGet, "/etag", nil)
	r.Header.Set("If-None-Match", `"abc123"`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotModified {
		t.Errorf("matching ETag: want 304, got %d", w.Code)
	}
}

// Cache-Control: no-store on request bypasses cache read

func TestHandler_RequestNoStore_BypassesCache(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWith(200, "fresh", "text/plain"))

	doGET(h, "/nocache") // prime cache

	r := httptest.NewRequest(http.MethodGet, "/nocache", nil)
	r.Header.Set("Cache-Control", "no-store")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
		t.Error("no-store request should not serve from cache")
	}
}

// Non-GET method — not cached

func TestHandler_PostNotCached(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWith(200, "ok", "text/plain"))

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "/post", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
			t.Errorf("POST request %d should not be served from cache", i+1)
		}
	}
}

// 5xx response — not cached

func TestHandler_5xxNotCached(t *testing.T) {
	mw := New(enabledCache("memory"), nil)
	h := mw(backendWith(500, "error", "text/plain"))

	doGET(h, "/err") // attempt to cache 500
	w := doGET(h, "/err")
	if got := w.Header().Get("X-Cache-Status"); got == "HIT" {
		t.Error("500 response should not be cached")
	}
}
