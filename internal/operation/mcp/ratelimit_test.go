package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimit(t *testing.T) {
	h := RateLimit("2/m")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if call() != http.StatusOK || call() != http.StatusOK {
		t.Fatal("first two calls should pass")
	}
	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("third call = %d, want 429", got)
	}
}

func TestParseRateLimit(t *testing.T) {
	for spec, want := range map[string]int{"60/m": 60, "10/s": 10, "100/h": 100} {
		n, _, ok := parseRateLimit(spec)
		if !ok || n != want {
			t.Fatalf("parseRateLimit(%q) = %d,%v", spec, n, ok)
		}
	}
	if _, _, ok := parseRateLimit("60"); ok {
		t.Fatal("accepted a rate limit without a window")
	}
}
