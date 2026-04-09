package attic

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

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
				TTL:     alaye.Duration(time.Minute),
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
				TTL:     alaye.Duration(time.Minute),
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
				TTL:     alaye.Duration(time.Minute),
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
				TTL:     alaye.Duration(time.Minute),
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
				TTL:     alaye.Duration(time.Minute),
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
				TTL:     alaye.Duration(time.Minute),
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
				TTL:     alaye.Duration(time.Minute),
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
			name: "Max-Age Respect",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     alaye.Duration(time.Hour),
			},
			requests: []testRequest{
				{
					method:      "GET",
					path:        "/max-age",
					body:        "short-lived",
					respHeaders: map[string]string{"Cache-Control": "max-age=1"},
				},
			},
			expectedHits:   []bool{false},
			expectedBodies: []string{"short-lived"},
		},
		{
			name: "Large Response Not Cached",
			config: &alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				Methods: []string{"GET"},
				TTL:     alaye.Duration(time.Minute),
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

func TestCacheKeyGeneration(t *testing.T) {
	baseReq := httptest.NewRequest("GET", "/test", nil)
	baseKey := generateKey(baseReq)
	req1 := httptest.NewRequest("GET", "/test", nil)
	if generateKey(req1) != baseKey {
		t.Error("same path should have same key")
	}
	req2 := httptest.NewRequest("POST", "/test", nil)
	if generateKey(req2) == baseKey {
		t.Error("different method should have different key")
	}
	req3 := httptest.NewRequest("GET", "/other", nil)
	if generateKey(req3) == baseKey {
		t.Error("different path should have different key")
	}
	req4 := httptest.NewRequest("GET", "/test?q=foo", nil)
	if generateKey(req4) == baseKey {
		t.Error("query string should change key")
	}
	req5 := httptest.NewRequest("GET", "/test", nil)
	req5.Header.Set("Accept", "application/json")
	if generateKey(req5) == baseKey {
		t.Error("Accept header should affect cache key")
	}
	req6 := httptest.NewRequest("GET", "/test", nil)
	req6.Header.Set("Accept-Language", "en")
	if generateKey(req6) == baseKey {
		t.Error("Accept-Language header should affect cache key")
	}
}

func TestIsResponseCacheable(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		headers  http.Header
		expected bool
	}{
		{
			name:     "200 OK is cacheable",
			status:   http.StatusOK,
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "201 Created is cacheable",
			status:   http.StatusCreated,
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "404 Not Found not cacheable",
			status:   http.StatusNotFound,
			headers:  http.Header{},
			expected: false,
		},
		{
			name:   "no-store prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "no-store")
				return h
			}(),
			expected: false,
		},
		{
			name:   "private prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "private")
				return h
			}(),
			expected: false,
		},
		{
			name:   "no-cache prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "no-cache")
				return h
			}(),
			expected: false,
		},
		{
			name:   "WWW-Authenticate prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("WWW-Authenticate", "Basic")
				return h
			}(),
			expected: false,
		},
		{
			name:   "max-age allows caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "max-age=3600")
				return h
			}(),
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isResponseCacheable(tt.status, tt.headers)
			if result != tt.expected {
				t.Errorf("isResponseCacheable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	req := httptest.NewRequest("GET", "/api/v1/users/12345?expand=profile&fields=name,email", nil)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = generateKey(req)
	}
}

type testRequest struct {
	method       string
	path         string
	body         string
	reqHeaders   map[string]string
	respHeaders  map[string]string
	respStatus   int
	expectStatus int
}
