package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminBodyLimitRejectsOversizedRequest(t *testing.T) {
	var read int
	h := adminBodyLimit(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		read = int(n)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kv", strings.NewReader(strings.Repeat("x", 2048)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if read != 0 {
		t.Fatalf("handler read %d bytes from an oversized body; want 0", read)
	}
}

func TestAdminBodyLimitAllowsNormalRequest(t *testing.T) {
	h := adminBodyLimit(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if n != 16 {
			t.Fatalf("read %d bytes, want 16", n)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kv", strings.NewReader("0123456789abcdef"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

// MaxBytesReader still covers chunked requests, where ContentLength is -1.
func TestAdminBodyLimitCapsChunkedRequest(t *testing.T) {
	h := adminBodyLimit(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err == nil {
			t.Fatal("expected MaxBytesReader error for chunked oversized body")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kv", strings.NewReader(strings.Repeat("x", 2048)))
	req.ContentLength = -1
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
}
