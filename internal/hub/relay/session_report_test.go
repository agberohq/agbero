package relay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func startReportRelay(t *testing.T) *Server {
	t.Helper()
	srv := NewServer(ServerConfig{
		Name: "agents", BaseDomain: "relay.test", Listen: "127.0.0.1:0",
		TLSConfig: testTLS(t), EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{AllowHTTP: true},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func reportAgent(t *testing.T, ctx context.Context, srv *Server, local string) {
	t.Helper()
	c := NewClient(ClientConfig{
		Agent: "alice", Relay: "https://" + srv.Addr(), Enroll: "enroll-secret",
		Local: local, Insecure: true,
		Exposes: []alaye.Expose{{ID: "show", Path: true, LocalHost: "show.localhost"}},
	})
	go c.Run(ctx)
}

// TestSessionReportStable: one agent gives a connected session, a live route
// and no replacements.
func TestSessionReportStable(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()
	srv := startReportRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reportAgent(t, ctx, srv, local.URL)

	var report *SessionReport
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := ProbeSession(context.Background(), "https://"+srv.Addr(), "alice", "enroll-secret", "", true)
		if err != nil {
			t.Fatal(err)
		}
		if r != nil && r.Connected && len(r.Routes) > 0 {
			report = r
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connected session reported: %+v", r)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !report.Routes[0].Live || report.Routes[0].Key != "/show" {
		t.Fatalf("route not live: %+v", report.Routes)
	}
	if n := report.Count("replaced", time.Minute); n != 0 {
		t.Fatalf("stable agent reported %d replacements", n)
	}
}

// TestSessionReportDuplicateAgent: two agents with the same name replace each
// other, and the report must show it.
func TestSessionReportDuplicateAgent(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()
	srv := startReportRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reportAgent(t, ctx, srv, local.URL)
	reportAgent(t, ctx, srv, local.URL)

	deadline := time.Now().Add(8 * time.Second)
	for {
		r, err := ProbeSession(context.Background(), "https://"+srv.Addr(), "alice", "enroll-secret", "", true)
		if err != nil {
			t.Fatal(err)
		}
		if r.Count("replaced", time.Minute) >= 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("duplicate agents not visible in report: %+v", r.History)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSessionReportProxyError: a 502 served by the relay is recorded with its
// cause and folded when repeated.
func TestSessionReportProxyError(t *testing.T) {
	srv := startReportRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Local target that refuses connections: the agent closes the stream.
	reportAgent(t, ctx, srv, "http://127.0.0.1:1")

	deadline := time.Now().Add(5 * time.Second)
	for {
		r, _ := ProbeSession(context.Background(), "https://"+srv.Addr(), "alice", "enroll-secret", "", true)
		if r != nil && r.Connected && len(r.Routes) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/show", nil)
		req.Host = "relay.test"
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d", rr.Code)
		}
	}
	r, err := ProbeSession(context.Background(), "https://"+srv.Addr(), "alice", "enroll-secret", "", true)
	if err != nil {
		t.Fatal(err)
	}
	ev := r.LastEvent("proxy_error")
	if ev == nil || ev.Reason == "" {
		t.Fatalf("proxy error not recorded: %+v", r.History)
	}
	if ev.Count != 3 {
		t.Fatalf("expected 3 folded proxy errors, got %d (%+v)", ev.Count, r.History)
	}
}
