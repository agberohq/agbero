package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type clientIPCtxKey struct{}

func contextWithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, ip)
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

func TestRateLimiter_Blocks(t *testing.T) {
	// 1. Setup Policy: 5 reqs / 1 sec
	policy := func(r *http.Request) (string, RatePolicy, bool) {
		return "test_bucket", RatePolicy{
			Requests: 5,
			Window:   1 * time.Second,
			Burst:    5,
		}, true
	}

	rl := NewRateLimiter(1*time.Minute, 1000, policy)
	defer rl.Close()

	// 2. Create Handler chain
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rl.Handler(nextHandler)

	// 3. Send 5 allowed requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234" // Client IP
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Request %d should be allowed, got %d", i, w.Code)
		}
	}

	// 4. Send 6th request (Should block)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Request 6 should be blocked (429), got %d", w.Code)
	}

	// 5. Different IP should be allowed
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "5.6.7.8:1234"
	w2 := httptest.NewRecorder()

	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("Different IP should be allowed, got %d", w2.Code)
	}
}
