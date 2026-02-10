package uptime

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/cache"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
)

type SystemStats struct {
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
	MemAlloc     uint64 `json:"mem_alloc"` // Bytes allocated and not yet freed
	MemTotal     uint64 `json:"mem_total"` // Total bytes allocated (cumulative)
	MemSys       uint64 `json:"mem_sys"`   // Bytes obtained from OS
	MemRSS       uint64 `json:"mem_rss"`   // Approximate RSS
}

// Uptime returns a JSON snapshot of the proxy state
func Uptime(hm *discovery.Host) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := collectMetrics(hm)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshot)
	}
}

type SystemSnapshot struct {
	Timestamp time.Time                `json:"timestamp"`
	System    SystemStats              `json:"system"`
	Hosts     map[string]*HostSnapshot `json:"hosts"`
}

type HostSnapshot struct {
	Routes        []*RouteSnapshot `json:"routes"`
	TotalReqs     uint64           `json:"total_reqs"`     // Sum across routes
	TotalBackends int              `json:"total_backends"` // Count across routes
	AvgP99        int64            `json:"avg_p99_us"`     // Avg P99 (non-zero samples only)
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

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	sysStats := SystemStats{
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemAlloc:     m.Alloc,
		MemTotal:     m.TotalAlloc,
		MemSys:       m.Sys,
		MemRSS:       m.HeapSys, // Approximation of RSS for Go
	}

	sys := &SystemSnapshot{
		Timestamp: time.Now(),
		System:    sysStats,
		Hosts:     make(map[string]*HostSnapshot),
	}

	// Get all configured hosts (active + inactive)
	hosts, _ := hm.LoadAll() // Returns map[string]*Host

	for domain, hcfg := range hosts {
		hSnap := &HostSnapshot{
			Routes: make([]*RouteSnapshot, 0, len(hcfg.Routes)),
		}

		var totalReqs uint64
		var totalBackends int
		var sumP99 int64
		var p99Count int

		// Add all configured routes (even inactive)
		for _, route := range hcfg.Routes {
			rSnap := &RouteSnapshot{
				Path:     route.Path,
				Strategy: route.Backends.LBStrategy,
				Backends: make([]*BackendSnapshot, 0),
			}

			// Check cache for active stats
			if v, ok := cache.Route.Load(route.Key()); ok {
				handler := v.Value.(*handlers.Route)

				for _, b := range handler.Backends {
					lat := b.Metrics.Snapshot()
					bSnap := &BackendSnapshot{
						URL:       b.URL.String(),
						Alive:     b.Alive.Load(),
						InFlight:  b.InFlight.Load(),
						Failures:  b.Failures.Load(),
						TotalReqs: b.TotalReqs.Load(),
						Latency:   lat,
					}
					rSnap.Backends = append(rSnap.Backends, bSnap)

					totalReqs += b.TotalReqs.Load()
					if lat.Count > 0 && lat.P99 > 0 {
						sumP99 += lat.P99
						p99Count++
					}
				}
			} else {
				// Inactive: Zero stats, list configured backends
				for _, url := range route.Backends.Servers {
					bSnap := &BackendSnapshot{
						URL:       url.Address,
						Alive:     false, // Inactive
						InFlight:  0,
						Failures:  0,
						TotalReqs: 0,
						Latency:   metrics.LatencySnapshot{},
					}
					rSnap.Backends = append(rSnap.Backends, bSnap)
				}
			}

			totalBackends += len(rSnap.Backends)
			hSnap.Routes = append(hSnap.Routes, rSnap)
		}

		hSnap.TotalReqs = totalReqs
		hSnap.TotalBackends = totalBackends
		if p99Count > 0 {
			hSnap.AvgP99 = sumP99 / int64(p99Count)
		}

		sys.Hosts[domain] = hSnap
	}

	return sys
}
