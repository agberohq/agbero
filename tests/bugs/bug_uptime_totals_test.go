package bugs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	uptime "github.com/agberohq/agbero/internal/handlers/uptime"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
)

// These tests document two related defects in the /uptime admin API that the
// Agbero map, hosts list and route drawers consume:
//
//   BUG A — RouteSnapshot / ProxySnapshot are marshalled WITHOUT request
//           totals. Only BackendSnapshot carries total_reqs, so every route
//           card / host→route edge / route drawer in the admin UI renders
//           "no traffic" even when the route is saturated (uptime.go:70-105;
//           the UI's route node "total" comes from statsOf(hostStats.routes,r)
//           .total_reqs in graph.js processData).
//
//   BUG B — A multi-domain host file is reported about N times. discovery's
//           rebuildLookupLocked (hosts.go:643) maps EVERY domain in a host
//           config to the same *Host, and the uptime handler iterates that
//           lookup map (uptime.go:201 "for domain, hcfg := range hosts"), so a
//           host with 2 domains produces 2 HostSnapshots with identical routes
//           — the admin hosts page and map therefore draw the same routes
//           twice, and per-host request totals double-count.
//
// The tests PASS while the defects are live. They fail with a "BUG FIXED"
// message when the backend changes, at which point they should be flipped to
// assert the new contract.

// fixtureHost builds one host config with two domains and a single HTTP backend
// and registers it in the discovery map.
func uptimeFixture(t *testing.T) (*discovery.Host, *resource.Resource) {
	t.Helper()

	tmp := t.TempDir()
	hostsDir := expect.NewFolder(tmp)
	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	if _, err := hm.LoadAll(); err != nil {
		t.Fatalf("prime host manager: %v", err)
	}

	cfg := &alaye.Host{
		Domains: []string{"dup.a.example", "alias.b.example"},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/api",
			Backends: alaye.Backend{
				Enabled: expect.Active,
				Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:9000")},
			},
		}},
	}
	hm.Set("dup.a.example", cfg)

	live := hm.Get("dup.a.example")
	if live == nil || len(live.Routes) == 0 || len(live.Routes[0].Backends.Servers) == 0 {
		t.Fatalf("fixture: host not registered with a backend")
	}
	addr := live.Routes[0].Backends.Servers[0].Address.String()
	key := live.Routes[0].KeyBackend("dup.a.example", addr)
	res := resource.New(resource.WithLogger(testLogger))
	res.Metrics.GetOrRegister(key).Activity.Requests.Add(5)
	return hm, res
}

func fetchUptimeJSON(t *testing.T, hm *discovery.Host, res *resource.Resource) map[string]map[string]any {
	t.Helper()
	handler := uptime.Uptime(res, hm, nil, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/uptime", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /uptime returned %d: %s", rr.Code, rr.Body.String())
	}
	var snap struct {
		Hosts map[string]map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode uptime JSON: %v", err)
	}
	return snap.Hosts
}

// Route and proxy snapshots must expose per-route request totals so the map,
// hosts list, and route drawer can stop reconstructing them from backends.
func TestUptimeSnapshotsExposeRequestTotals(t *testing.T) {
	checks := []struct {
		name string
		typ  any
	}{
		{"RouteSnapshot", uptime.RouteSnapshot{}},
		{"ProxySnapshot", uptime.ProxySnapshot{}},
	}
	for _, c := range checks {
		if _, ok := reflect.TypeOf(c.typ).FieldByName("TotalReqs"); !ok {
			t.Errorf("%s has no TotalReqs field", c.name)
		}
		if _, ok := reflect.TypeOf(c.typ).FieldByName("Failures"); !ok {
			t.Errorf("%s has no Failures field", c.name)
		}
	}
}

// One host file must produce one canonical host entry, and its route snapshot
// must carry the aggregated backend requests.
func TestUptimeDeduplicatesAliasesAndPopulatesRouteTotals(t *testing.T) {
	hm, res := uptimeFixture(t)
	hosts := fetchUptimeJSON(t, hm, res)

	if len(hosts) != 1 {
		t.Fatalf("one host file produced %d host entries; want 1 (canonical only): %v",
			len(hosts), hostKeys(hosts))
	}
	dup := hosts["dup.a.example"]
	if dup == nil {
		t.Fatalf("canonical host dup.a.example missing; got %v", hostKeys(hosts))
	}
	if _, ok := hosts["alias.b.example"]; ok {
		t.Fatalf("alias.b.example still appears as a separate host entry")
	}

	routes, _ := dup["routes"].([]any)
	if len(routes) == 0 {
		t.Fatalf("fixture: route snapshot missing")
	}
	r0, _ := routes[0].(map[string]any)
	if got, _ := r0["total_reqs"].(float64); got != 5 {
		t.Fatalf("route total_reqs = %v, want 5", r0["total_reqs"])
	}
	if got, _ := r0["failures"].(float64); got != 0 {
		t.Fatalf("route failures = %v, want 0", r0["failures"])
	}
	hostTotal, _ := dup["total_reqs"].(float64)
	if hostTotal != 5 {
		t.Fatalf("host total_reqs = %v, want 5", hostTotal)
	}
}

func hostKeys(hosts map[string]map[string]any) []string {
	keys := make([]string, 0, len(hosts))
	for k := range hosts {
		keys = append(keys, k)
	}
	return keys
}
