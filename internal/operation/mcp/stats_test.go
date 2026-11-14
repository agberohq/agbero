package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatsMiddleware(t *testing.T) {
	s := NewStats()
	h := s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("payload"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	snap := s.Snapshot()
	if snap.Requests != 1 || snap.Errors != 1 {
		t.Fatalf("stats = %+v", snap)
	}
	if snap.BytesIn != uint64(len("payload")) || snap.BytesOut != uint64(len("hello")) {
		t.Fatalf("bytes = %+v", snap)
	}
}
