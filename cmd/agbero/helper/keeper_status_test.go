package helper

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeeperStatusFromService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","locked":true}`))
	}))
	defer srv.Close()

	locked, ok := keeperStatus(srv.URL)
	if !ok {
		t.Fatal("status endpoint was not recognized")
	}
	if !locked {
		t.Fatal("locked state was not decoded")
	}
}

func TestKeeperStatusUnavailable(t *testing.T) {
	if _, ok := keeperStatus("http://127.0.0.1:1"); ok {
		t.Fatal("unreachable status endpoint was accepted")
	}
}
