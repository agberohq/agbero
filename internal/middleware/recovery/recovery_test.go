package recovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/olekukonko/ll"
)

func TestRecoveryRepanicsAbortHandler(t *testing.T) {
	h := New(ll.New("recovery/test").Disable())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler {
			t.Fatalf("recover() = %v, want http.ErrAbortHandler", rec)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Fatal("ErrAbortHandler was swallowed")
}

func TestRecoveryHandlesApplicationPanic(t *testing.T) {
	h := New(ll.New("recovery/test").Disable())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
