package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// TestClientDoesNotPreDialLocalHTTPTarget guards the root cause of the 502: an
// idle session must not hold a local HTTP connection open, because the local
// listener's read-header timeout closes it and the tunnel dies with it.
func TestClientDoesNotPreDialLocalHTTPTarget(t *testing.T) {
	var accepts atomic.Int64
	local := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	local.Config.ReadHeaderTimeout = time.Second
	local.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	local.StartTLS()
	defer local.Close()

	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy:      alaye.RelayPolicy{AllowHTTP: true},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent:         "alice",
		Relay:         "https://" + srv.Addr(),
		Enroll:        "enroll-secret",
		Local:         local.URL,
		LocalInsecure: true,
		Insecure:      true,
		Pool:          2,
		Exposes: []alaye.Expose{{
			ID: "show", Path: true, LocalHost: "show.localhost",
		}},
	})
	go client.Run(ctx)

	get := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/show", nil)
		req.Host = "relay.test"
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code, strings.TrimSpace(rr.Body.String())
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _ := get(); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

	before := accepts.Load()
	time.Sleep(2 * time.Second)
	if after := accepts.Load(); after != before {
		t.Fatalf("agent opened %d local connections while idle; want none", after-before)
	}
}

// TestServerAgentHTTPPathSurvivesIdle is the reported 502 regression: the first
// request worked, then the exposure returned 502 after a short idle period.
func TestServerAgentHTTPPathSurvivesIdle(t *testing.T) {
	local := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "relay body "+r.URL.Path)
	}))
	// Mirror agbero's read_header timeout, which closed the pre-dialed local
	// connections and made the pooled tunnel connections stale.
	local.Config.ReadHeaderTimeout = time.Second
	local.StartTLS()
	defer local.Close()

	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy:      alaye.RelayPolicy{AllowHTTP: true},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent:         "alice",
		Relay:         "https://" + srv.Addr(),
		Enroll:        "enroll-secret",
		Local:         local.URL,
		LocalInsecure: true,
		Insecure:      true,
		Pool:          2,
		Exposes: []alaye.Expose{{
			ID: "show", Path: true, LocalHost: "show.localhost",
		}},
	})
	go client.Run(ctx)

	get := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/show", nil)
		req.Host = "relay.test"
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code, strings.TrimSpace(rr.Body.String())
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _ := get(); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(3 * time.Second)
	code, body := get()
	if code != http.StatusOK {
		t.Fatalf("exposure broke after idle: HTTP %d %q", code, body)
	}
	if body != "relay body /" {
		t.Fatalf("body = %q", body)
	}
}
