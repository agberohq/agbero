package helper

import (
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/relay"
)

func TestFindAgentSites(t *testing.T) {
	h := &alaye.Host{
		Domains: []string{"show.localhost"},
		Agents:  []alaye.Agent{{Name: "alice", Relay: "https://relay.test:8443", Local: "https://127.0.0.1:443"}},
		Routes: []alaye.Route{{
			Path: "/",
			Exposes: []alaye.Expose{
				{ID: "show", Via: "alice", Path: true},
				{ID: "other", Via: "bob", Path: true},
			},
		}},
	}
	hosts := map[string]*alaye.Host{"show.localhost": h}
	sites := findAgentSites(hosts, "ALICE")
	if len(sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(sites))
	}
	site := sites[0]
	if site.HostName != "show.localhost" {
		t.Fatalf("host = %q", site.HostName)
	}
	if len(site.Exposes) != 1 || site.Exposes[0].ID != "show" {
		t.Fatalf("exposes = %+v, want only alice's", site.Exposes)
	}
	if site.LocalURL != "https://127.0.0.1:443" || !site.LocalInsecure {
		t.Fatalf("local = %q insecure=%v", site.LocalURL, site.LocalInsecure)
	}

	// The same host reachable under two keys must not be checked twice.
	hosts["show.localhost."] = h
	if got := findAgentSites(hosts, "alice"); len(got) != 1 {
		t.Fatalf("sites = %d after duplicate host key, want 1", len(got))
	}
	// Unknown agents are not invented.
	if got := findAgentSites(hosts, "nobody"); len(got) != 0 {
		t.Fatalf("sites = %d for unknown agent, want 0", len(got))
	}
}

func TestDoctorReportCountsAndFailure(t *testing.T) {
	rep := &doctorReport{Agent: "alice", Side: "client"}
	rep.add("configuration", doctorPass, "ok")
	rep.add("dns", doctorPass, "ok")
	rep.add("tls", doctorWarn, "expires soon")
	rep.add("public /show", doctorFail, "502")
	rep.add("udp 53", doctorSkip, "not probed")

	pass, warn, fail, skip := rep.counts()
	if pass != 2 || warn != 1 || fail != 1 || skip != 1 {
		t.Fatalf("counts = %d/%d/%d/%d", pass, warn, fail, skip)
	}
	if !rep.failed() {
		t.Fatal("a FAIL stage must fail the report")
	}
}

func TestDoctorReportWarningsDoNotFail(t *testing.T) {
	rep := &doctorReport{Agent: "alice"}
	rep.add("session", doctorWarn, "reconnects 2")
	if rep.failed() {
		t.Fatal("warnings must not fail the report")
	}
}

func TestSecretValueResolvesLiteralToken(t *testing.T) {
	value, err := secretValue("plain-enroll-token", &alaye.Global{})
	if err != nil {
		t.Fatal(err)
	}
	if value != "plain-enroll-token" {
		t.Fatalf("value = %q", value)
	}
	if _, err := secretValue("", &alaye.Global{}); err == nil {
		t.Fatal("empty secret must be an error")
	}
}

func TestProbeTLSReadsCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "https://")

	info, err := probeTLS(hostport, "127.0.0.1", true, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if info.NotAfter.IsZero() {
		t.Fatal("certificate expiry was not read")
	}
	if info.Version < tls.VersionTLS12 {
		t.Fatalf("tls version = %x, want >= TLS 1.2", info.Version)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Fatalf("test certificate already expired: %s", info.NotAfter)
	}
}

func TestHumanLeft(t *testing.T) {
	cases := map[time.Duration]string{
		-2 * time.Hour:   "expired",
		3 * time.Hour:    "3h",
		72 * time.Hour:   "3d",
		30 * time.Minute: "30m0s",
	}
	for in, want := range cases {
		if got := humanLeft(in); got != want {
			t.Fatalf("humanLeft(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestDoctorServerDetectsMissingRoute(t *testing.T) {
	// AgentSnapshot.Exposures uses the relay's internal exposure type, so the
	// snapshot is built through its JSON form.
	var srv relay.ServerSnapshot
	if err := json.Unmarshal([]byte(`{"domain":"relay.test","agents":[{"id":"alice","exposures":[{"id":"show","path":true}]}]}`), &srv); err != nil {
		t.Fatal(err)
	}
	rep := &doctorReport{Agent: "alice", Side: "server"}
	r := &Relay{}
	r.doctorServer(quietFlow(), rep, &srv, &srv.Agents[0], ProbeOptions{Attempts: 1, Wait: time.Millisecond, Timeout: time.Second})
	if !rep.failed() {
		t.Fatalf("stages = %+v, want a failure for the missing route", rep.Stages)
	}
}

func TestDoctorServerDetectsDeadRoute(t *testing.T) {
	srv := &relay.ServerSnapshot{
		Domain: "relay.test",
		Agents: []relay.AgentSnapshot{{ID: "alice", ConnectedAt: time.Now(), Reconnects: 3}},
		Routes: []relay.RouteSnapshot{{Key: "/show", Agent: "alice", Live: false}},
	}
	rep := &doctorReport{Agent: "alice", Side: "server"}
	r := &Relay{}
	r.doctorServer(quietFlow(), rep, srv, &srv.Agents[0], ProbeOptions{Attempts: 1, Wait: time.Millisecond, Timeout: time.Second})
	if !rep.failed() {
		t.Fatalf("stages = %+v, want a failure for the dead route", rep.Stages)
	}
	joined := ""
	for _, st := range rep.Stages {
		joined += st.Name + " " + st.Detail + "\n"
	}
	if !strings.Contains(joined, "closed session") {
		t.Fatalf("stages = %s, want a closed-session diagnosis", joined)
	}
}
