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

type testRequest struct {
	method       string
	path         string
	body         string
	reqHeaders   map[string]string
	respHeaders  map[string]string
	respStatus   int
	expectStatus int
}
