package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_BlocksAfterLimit(t *testing.T) {
	rl := New(Config{
		TTL:        30 * time.Minute,
		MaxEntries: 1000,
		Policy: func(r *http.Request) (string, RatePolicy, bool) {
			return "global", RatePolicy{Requests: 2, Window: time.Second, Burst: 2}, true
		},
	})
	defer rl.Close()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := rl.Handler(next)
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	for i := range 2 {
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
	rl := New(Config{
		TTL:        80 * time.Millisecond,
		MaxEntries: 1000,
		Policy: func(r *http.Request) (string, RatePolicy, bool) {
			return "global", RatePolicy{Requests: 1, Window: time.Second, Burst: 1}, true
		},
	})
	defer rl.Close()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := rl.Handler(next)
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
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

func TestRateLimiter_Identity(t *testing.T) {
	rl := New(Config{
		TTL:        1 * time.Minute,
		MaxEntries: 1000,
		Policy: func(r *http.Request) (string, RatePolicy, bool) {
			return "identity", RatePolicy{
				Requests: 2,
				Window:   time.Second,
				Burst:    2,
				KeySpec:  "header:X-API-Key",
			}, true
		},
	})
	defer rl.Close()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := rl.Handler(next)
	reqA := httptest.NewRequest("GET", "/", nil)
	reqA.RemoteAddr = "10.0.0.1:1234"
	reqA.Header.Set("X-API-Key", "user_A")
	reqB := httptest.NewRequest("GET", "/", nil)
	reqB.RemoteAddr = "10.0.0.1:1234"
	reqB.Header.Set("X-API-Key", "user_B")
	for i := range 2 {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, reqA)
		if rr.Code != 200 {
			t.Fatalf("Key A: expected 200 at i=%d got %d", i, rr.Code)
		}
	}
	rrA := httptest.NewRecorder()
	h.ServeHTTP(rrA, reqA)
	if rrA.Code != 429 {
		t.Fatalf("Key A: expected 429, got %d", rrA.Code)
	}
	rrB := httptest.NewRecorder()
	h.ServeHTTP(rrB, reqB)
	if rrB.Code != 200 {
		t.Fatalf("Key B: expected 200 (separate bucket), got %d", rrB.Code)
	}
	reqNoHeader := httptest.NewRequest("GET", "/", nil)
	reqNoHeader.RemoteAddr = "10.0.0.2:1234"
	for i := range 2 {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, reqNoHeader)
		if rr.Code != 200 {
			t.Fatalf("NoHeader: expected 200 at i=%d got %d", i, rr.Code)
		}
	}
	rrIP := httptest.NewRecorder()
	h.ServeHTTP(rrIP, reqNoHeader)
	if rrIP.Code != 429 {
		t.Fatalf("NoHeader: expected 429, got %d", rrIP.Code)
	}
}

func TestRateLimiter_Blocks(t *testing.T) {
	policy := func(r *http.Request) (string, RatePolicy, bool) {
		return "test_bucket", RatePolicy{
			Requests: 5,
			Window:   1 * time.Second,
			Burst:    5,
		}, true
	}
	rl := New(Config{
		TTL:        1 * time.Minute,
		MaxEntries: 1000,
		Policy:     policy,
	})
	defer rl.Close()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rl.Handler(nextHandler)
	for i := range 5 {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Request %d should be allowed, got %d", i, w.Code)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Request 6 should be blocked (429), got %d", w.Code)
	}
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "5.6.7.8:1234"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("Different IP should be allowed, got %d", w2.Code)
	}
}
