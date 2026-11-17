package helper

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/relay"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

func quietFlow() *ui.Flow {
	return ui.NewFlow(ui.WithWriter(&strings.Builder{}), ui.WithIndent(0))
}

func TestProbeWithRetryReportsFlapping(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			http.Error(w, "Relay unavailable", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	probe, history := probeWithRetry(quietFlow(), "public", srv.URL, "", false, ProbeOptions{
		Attempts: 5, Wait: time.Millisecond, Timeout: time.Second,
	})
	if !probe.ok() {
		t.Fatalf("probe status = %d, want 200", probe.Status)
	}
	if len(history) != 3 {
		t.Fatalf("attempts = %d, want 3", len(history))
	}
	if !flapped(history) {
		t.Fatal("502, 502, 200 must be reported as flapping")
	}
}

func TestProbeWithRetryStopsOnPermanentFailure(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "Not found", http.StatusNotFound)
	}))
	defer srv.Close()

	probe, history := probeWithRetry(quietFlow(), "public", srv.URL, "", false, ProbeOptions{
		Attempts: 4, Wait: time.Millisecond, Timeout: time.Second,
	})
	if probe.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", probe.Status)
	}
	if len(history) != 4 {
		t.Fatalf("attempts = %d, want 4 (404 is retried as a possible flap)", len(history))
	}
	if flapped(history) {
		t.Fatal("a stable 404 is not flapping")
	}
}

func TestDiagnoseClientDistinguishesRelayRouteFromLocalRoute(t *testing.T) {
	local := httpProbe{Status: 200, Body: []byte("hello")}
	history := []probeAttempt{{N: 1, Probe: httpProbe{Status: 404, Body: []byte("Not found")}}}

	v := diagnoseClient(local, httpProbe{Status: 404, Body: []byte("Not found")}, history, "show", "https://127.0.0.1:443/")
	if v.OK {
		t.Fatal("404 with a healthy local target must not pass")
	}
	if !strings.Contains(v.Where, "relay route table") {
		t.Fatalf("where = %q, want the relay route table", v.Where)
	}

	// The same public status with a failing local target points at the local
	// route instead, which is a completely different fix.
	v = diagnoseClient(httpProbe{Status: 404, Body: []byte("Not found")}, httpProbe{Status: 404, Body: []byte("Not found")}, history, "show", "https://127.0.0.1:443/")
	if !strings.Contains(v.Where, "local host/route") {
		t.Fatalf("where = %q, want the local route", v.Where)
	}
}

func TestDiagnoseClientTunnelFailure(t *testing.T) {
	local := httpProbe{Status: 200, Body: []byte("hello")}
	public := httpProbe{Status: 502, Body: []byte("Relay unavailable")}
	v := diagnoseClient(local, public, []probeAttempt{{N: 1, Probe: public}}, "show", "https://127.0.0.1:443/")
	if v.OK {
		t.Fatal("502 must not pass")
	}
	if !strings.Contains(v.Where, "tunnel") {
		t.Fatalf("where = %q, want the tunnel", v.Where)
	}
}

func TestDiagnoseClientVerifiesPayloadEndToEnd(t *testing.T) {
	local := httpProbe{Status: 200, Body: []byte("identical payload")}
	public := httpProbe{Status: 200, Body: []byte("identical payload")}
	v := diagnoseClient(local, public, []probeAttempt{{N: 1, Probe: public}}, "show", "https://127.0.0.1:443/")
	if !v.OK || v.Flap {
		t.Fatalf("verdict = %+v, want a clean pass", v)
	}
	joined := strings.Join(v.Detail, "\n")
	if !strings.Contains(joined, "payload verified end to end") {
		t.Fatalf("details = %q, want payload verification", joined)
	}
}

func TestDiagnoseServerReportsDeadRoute(t *testing.T) {
	live := &relay.ServerSnapshot{
		Routes: []relay.RouteSnapshot{{Key: "/show", Agent: "alice", Live: false}},
		Agents: []relay.AgentSnapshot{{ID: "alice", Reconnects: 4}},
	}
	target, _ := url.Parse("https://relay.test/show")
	public := httpProbe{Status: 502, Body: []byte("Relay unavailable")}
	v := diagnoseServer(public, []probeAttempt{{N: 1, Probe: public}}, live, target)
	if v.OK {
		t.Fatal("502 must not pass")
	}
	if !strings.Contains(v.Where, "stale route") {
		t.Fatalf("where = %q, want the stale route diagnosis", v.Where)
	}
}

func TestDiagnoseServerMissingRoute(t *testing.T) {
	live := &relay.ServerSnapshot{Agents: []relay.AgentSnapshot{{ID: "alice"}}}
	target, _ := url.Parse("https://relay.test/show")
	public := httpProbe{Status: 404, Body: []byte("Not found")}
	v := diagnoseServer(public, []probeAttempt{{N: 1, Probe: public}}, live, target)
	if !strings.Contains(v.Where, "exposure registration") {
		t.Fatalf("where = %q, want exposure registration", v.Where)
	}
}

func TestLocalProbeURLMirrorsRelayRewrite(t *testing.T) {
	base, _ := url.Parse("https://127.0.0.1:443")
	ex := alaye.Expose{ID: "show"}
	cases := map[string]string{
		"/show":          "https://127.0.0.1:443/",
		"/show/docs":     "https://127.0.0.1:443/docs",
		"/show/docs/sub": "https://127.0.0.1:443/docs/sub",
	}
	for in, want := range cases {
		if got := localProbeURL(base, ex, in); got != want {
			t.Fatalf("localProbeURL(%q) = %q, want %q", in, got, want)
		}
	}
	ex.LocalPath = "/app"
	if got := localProbeURL(base, ex, "/show/docs"); got != "https://127.0.0.1:443/app/docs" {
		t.Fatalf("local path prefix: got %q", got)
	}
}

func TestRouteForPathPicksLongestPrefix(t *testing.T) {
	live := &relay.ServerSnapshot{Routes: []relay.RouteSnapshot{
		{Key: "/show", Agent: "alice", Live: true},
		{Key: "/show/api", Agent: "alice", Live: true},
		{Key: "sub:show", Agent: "alice", Live: true},
	}}
	if r := routeForPath(live, "/show/api/users"); r == nil || r.Key != "/show/api" {
		t.Fatalf("route = %+v, want /show/api", r)
	}
	if r := routeForPath(live, "/other"); r != nil {
		t.Fatalf("route = %+v, want none", r)
	}
}
