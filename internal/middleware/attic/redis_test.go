package attic

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

func TestRedisCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis tests in short mode")
	}
	logger := ll.New("").Disable()
	cfg := &alaye.Cache{
		Enabled: alaye.Active,
		Driver:  "redis",
		Methods: []string{"GET"},
		TTL:     time.Minute,
		Options: map[string]string{
			"host": "localhost",
			"port": "6379",
			"db":   "1",
		},
	}
	handler := New(cfg, logger)
	if handler == nil {
		t.Skip("redis not available")
	}
	t.Run("Basic Cache Hit After Miss", func(t *testing.T) {
		requests := []testRequest{
			{method: "GET", path: "/test", body: "response1"},
			{method: "GET", path: "/test", body: "response2"},
		}
		for i, req := range requests {
			r := httptest.NewRequest(req.method, req.path, nil)
			w := httptest.NewRecorder()
			reqCopy := req
			handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(reqCopy.body))
			})
			wrapped := handler(handlerFunc)
			wrapped.ServeHTTP(w, r)
			if i == 0 && w.Header().Get("X-Cache") != "MISS" {
				t.Errorf("expected MISS on first request, got %s", w.Header().Get("X-Cache"))
			}
			if i == 1 && w.Header().Get("X-Cache") != "HIT" {
				t.Errorf("expected HIT on second request, got %s", w.Header().Get("X-Cache"))
			}
		}
	})
	t.Run("Different Paths Different Cache", func(t *testing.T) {
		requests := []testRequest{
			{method: "GET", path: "/a", body: "a-response"},
			{method: "GET", path: "/b", body: "b-response"},
		}
		for _, req := range requests {
			r := httptest.NewRequest(req.method, req.path, nil)
			w := httptest.NewRecorder()
			reqCopy := req
			handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(reqCopy.body))
			})
			wrapped := handler(handlerFunc)
			wrapped.ServeHTTP(w, r)
			if w.Header().Get("X-Cache") != "MISS" {
				t.Errorf("expected MISS on %s, got %s", req.path, w.Header().Get("X-Cache"))
			}
		}
	})
	t.Run("Query String Differentiation", func(t *testing.T) {
		requests := []testRequest{
			{method: "GET", path: "/search?q=foo", body: "foo results"},
			{method: "GET", path: "/search?q=bar", body: "bar results"},
		}
		for i, req := range requests {
			r := httptest.NewRequest(req.method, req.path, nil)
			w := httptest.NewRecorder()
			reqCopy := req
			handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(reqCopy.body))
			})
			wrapped := handler(handlerFunc)
			wrapped.ServeHTTP(w, r)
			if i == 2 && w.Header().Get("X-Cache") != "HIT" {
				t.Errorf("expected HIT on second ?q=foo request, got %s", w.Header().Get("X-Cache"))
			}
		}
		r3 := httptest.NewRequest("GET", "/search?q=foo", nil)
		w3 := httptest.NewRecorder()
		handlerFunc3 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("foo results"))
		})
		wrapped3 := handler(handlerFunc3)
		wrapped3.ServeHTTP(w3, r3)
		if w3.Header().Get("X-Cache") != "HIT" {
			t.Errorf("expected HIT on second ?q=foo request, got %s", w3.Header().Get("X-Cache"))
		}
	})
	t.Run("Vary Header Respect", func(t *testing.T) {
		requests := []testRequest{
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
		}
		for i, req := range requests {
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
				w.Write([]byte(reqCopy.body))
			})
			wrapped := handler(handlerFunc)
			wrapped.ServeHTTP(w, r)
			if i == 2 && w.Header().Get("X-Cache") != "HIT" {
				t.Errorf("expected HIT on second en request, got %s", w.Header().Get("X-Cache"))
			}
		}
	})
	t.Run("TTL Expiration", func(t *testing.T) {
		shortTTL := 1 * time.Second
		cfg := &alaye.Cache{
			Enabled: alaye.Active,
			Driver:  "redis",
			Methods: []string{"GET"},
			TTL:     shortTTL,
			Options: map[string]string{
				"host": "localhost",
				"port": "6379",
				"db":   "1",
			},
		}
		handler := New(cfg, logger)
		if handler == nil {
			t.Skip("redis not available")
		}
		called := 0
		wrapped := handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			w.Write([]byte("response"))
		}))
		r1 := httptest.NewRequest("GET", "/ttl", nil)
		w1 := httptest.NewRecorder()
		wrapped.ServeHTTP(w1, r1)
		if called != 1 {
			t.Errorf("expected handler called once, got %d", called)
		}
		r2 := httptest.NewRequest("GET", "/ttl", nil)
		w2 := httptest.NewRecorder()
		wrapped.ServeHTTP(w2, r2)
		if called != 1 {
			t.Errorf("expected handler still called once, got %d", called)
		}
		time.Sleep(shortTTL + 100*time.Millisecond)
		r3 := httptest.NewRequest("GET", "/ttl", nil)
		w3 := httptest.NewRecorder()
		wrapped.ServeHTTP(w3, r3)
		if called != 2 {
			t.Errorf("expected handler called twice after expiration, got %d", called)
		}
	})
}

func TestRedisStoreOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis tests in short mode")
	}
	logger := ll.New("").Disable()
	tests := []struct {
		name    string
		options map[string]string
	}{
		{
			name:    "Default options",
			options: map[string]string{},
		},
		{
			name: "Custom host and port",
			options: map[string]string{
				"host": "localhost",
				"port": "6379",
			},
		},
		{
			name: "Custom DB",
			options: map[string]string{
				"db": "2",
			},
		},
		{
			name: "Custom key prefix",
			options: map[string]string{
				"key_prefix": "test:cache:",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &alaye.Cache{
				Enabled: alaye.Active,
				Driver:  "redis",
				Methods: []string{"GET"},
				TTL:     time.Minute,
				Options: tt.options,
			}
			store, err := NewRedis(cfg, logger)
			if err != nil {
				t.Skipf("redis not available: %v", err)
			}
			defer store.Close()
			key := "test-key"
			entry := &Entry{
				Body:      []byte("test"),
				Headers:   make(http.Header),
				Status:    http.StatusOK,
				CreatedAt: time.Now(),
				StoredAt:  time.Now(),
			}
			store.Set(key, entry, time.Second)
			time.Sleep(10 * time.Millisecond)
			retrieved, ok := store.Get(key)
			if !ok {
				t.Error("failed to retrieve stored entry")
			}
			if string(retrieved.Body) != "test" {
				t.Errorf("expected body 'test', got '%s'", string(retrieved.Body))
			}
			store.Delete(key)
			time.Sleep(10 * time.Millisecond)
			_, ok = store.Get(key)
			if ok {
				t.Error("entry still exists after delete")
			}
		})
	}
}
