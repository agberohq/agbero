package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// MetricsHandler returns a JSON snapshot of the proxy state
func MetricsHandler(hm *discovery.Host) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := collectMetrics(hm)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshot)
	}
}

// --- Data Structures for JSON Output ---

type SystemSnapshot struct {
	Timestamp time.Time                `json:"timestamp"`
	Hosts     map[string]*HostSnapshot `json:"hosts"`
}

type HostSnapshot struct {
	Routes []*RouteSnapshot `json:"routes"`
}

type RouteSnapshot struct {
	Path     string             `json:"path"`
	Strategy string             `json:"strategy"`
	Backends []*BackendSnapshot `json:"backends"`
}

type BackendSnapshot struct {
	URL       string `json:"url"`
	Alive     bool   `json:"alive"`
	InFlight  int64  `json:"in_flight"`
	Failures  int64  `json:"failures"`
	TotalReqs uint64 `json:"total_reqs"`
	// Latency in Microseconds
	Latency metrics.LatencySnapshot `json:"latency_us"`
}

// --- Collection Logic ---

func collectMetrics(hm *discovery.Host) *SystemSnapshot {
	sys := &SystemSnapshot{
		Timestamp: time.Now(),
		Hosts:     make(map[string]*HostSnapshot),
	}

	// 1. Get Configured Hosts from HostManager
	// We need to expose a Snapshot() method on HostManager or just reuse LoadAll() logic
	// safely if possible. Assuming hm.LoadAll() returns a copy safe for reading:
	hosts, _ := hm.LoadAll() // Returns map[string]*HostConfig

	for domain, hcfg := range hosts {
		hSnap := &HostSnapshot{
			Routes: make([]*RouteSnapshot, 0, len(hcfg.Routes)),
		}

		// 2. Iterate Routes in Config
		for _, route := range hcfg.Routes {
			rSnap := &RouteSnapshot{
				Path:     route.Path,
				Strategy: route.LBStrategy,
				Backends: make([]*BackendSnapshot, 0),
			}

			if v, ok := woos.RouteCache.Load(route.Key()); ok {
				// Found active handler
				item := v.(*woos.RouteCacheItem)
				handler := item.Handler.(*RouteHandler)

				// 4. Extract Backend Stats
				for _, b := range handler.Backends {

					// Get P-Values
					lat := metrics.LatencySnapshot{}
					if b.Metrics != nil {
						lat = b.Metrics.Snapshot()
					}

					bSnap := &BackendSnapshot{
						URL:       b.URL.String(),
						Alive:     b.Alive.Load(),
						InFlight:  b.InFlight.Load(),
						Failures:  b.Failures.Load(),
						TotalReqs: b.TotalReqs.Load(),
						Latency:   lat,
					}
					rSnap.Backends = append(rSnap.Backends, bSnap)
				}
			} else {
				// Handler not built yet (no traffic), or reaped.
				// We can list configured backends with zero stats if we want,
				// but skipping keeps the output clean to "what is active".
			}

			hSnap.Routes = append(hSnap.Routes, rSnap)
		}

		sys.Hosts[domain] = hSnap
	}

	return sys
}
