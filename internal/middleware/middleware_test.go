package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func contextWithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, ip)
}

func TestIPMiddleware_ClientIP_FromTrustedXFFChain(t *testing.T) {
	m := NewIPMiddleware([]string{"127.0.0.1/32", "10.0.0.0/8"})

	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.2, 127.0.0.1")

	rr := httptest.NewRecorder()

	var got string
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
		w.WriteHeader(200)
	}))

	h.ServeHTTP(rr, req)

	if got != "1.1.1.1" {
		t.Fatalf("expected client 1.1.1.1, got %q", got)
	}
}

func TestIPMiddleware_UntrustedPeer_IgnoresXFF(t *testing.T) {
	m := NewIPMiddleware([]string{"127.0.0.1/32"})

	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	rr := httptest.NewRecorder()

	var got string
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
		w.WriteHeader(200)
	}))

	h.ServeHTTP(rr, req)

	if got != "203.0.113.9" {
		t.Fatalf("expected 203.0.113.9, got %q", got)
	}
}

func TestRateLimiter_BlocksAfterLimit(t *testing.T) {
	rl := NewRateLimiter(30*time.Minute, 1000, func(r *http.Request) (string, RatePolicy, bool) {
		return "global", RatePolicy{Requests: 2, Window: time.Second, Burst: 2}, true
	})
	defer rl.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := rl.Handler(next)

	req := httptest.NewRequest("GET", "http://x/", nil)
	req = req.WithContext(contextWithClientIP(req.Context(), "9.9.9.9"))

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("expected 200 at i=%d got %d", i, rr.Code)
		}
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

func TestRateLimiter_TTL_EvictsEventually(t *testing.T) {
	rl := NewRateLimiter(80*time.Millisecond, 1000, func(r *http.Request) (string, RatePolicy, bool) {
		return "global", RatePolicy{Requests: 1, Window: time.Second, Burst: 1}, true
	})
	defer rl.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := rl.Handler(next)

	req := httptest.NewRequest("GET", "http://x/", nil)
	req = req.WithContext(contextWithClientIP(req.Context(), "8.8.8.8"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}

	// Wait and retry until it becomes 200 (evicted + recreated).
	deadline := time.Now().Add(2 * time.Second)
	for {
		time.Sleep(120 * time.Millisecond)
		rr2 := httptest.NewRecorder()
		h.ServeHTTP(rr2, req)
		if rr2.Code == 200 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 200 after TTL eviction, still %d", rr2.Code)
		}
	}
}
