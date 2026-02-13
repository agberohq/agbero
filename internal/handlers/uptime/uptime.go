package uptime

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"

	"git.imaxinacion.net/aibox/agbero/internal/core/cache"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/tcp"
)

type SystemStats struct {
	NumCPU       int     `json:"num_cpu"`
	NumGoroutine int     `json:"num_goroutine"`
	MemAlloc     uint64  `json:"mem_alloc"`
	MemTotal     uint64  `json:"mem_total"`
	MemSys       uint64  `json:"mem_sys"`
	MemRSS       uint64  `json:"mem_rss"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemUsed      uint64  `json:"mem_used"`
	MemTotalOS   uint64  `json:"mem_total_os"`
}

type SystemSnapshot struct {
	Timestamp time.Time                `json:"timestamp"`
	System    SystemStats              `json:"system"`
	Hosts     map[string]*HostSnapshot `json:"hosts"`
}

type HostSnapshot struct {
	Routes        []*RouteSnapshot `json:"routes"`
	TotalReqs     uint64           `json:"total_reqs"`
	TotalBackends int              `json:"total_backends"`
	AvgP99        int64            `json:"avg_p99_us"`
}

type RouteSnapshot struct {
	Protocol string             `json:"protocol"` // "http" or "tcp"
	Path     string             `json:"path"`
	Strategy string             `json:"strategy"`
	Backends []*BackendSnapshot `json:"backends"`
}

type BackendSnapshot struct {
	URL       string                  `json:"url"`
	Alive     bool                    `json:"alive"`
	InFlight  int64                   `json:"in_flight"`
	Failures  int64                   `json:"failures"`
	TotalReqs uint64                  `json:"total_reqs"`
	Latency   metrics.LatencySnapshot `json:"latency_us"`
	Healthy   bool                    `json:"healthy"`
}

var (
	lastCPUCheck     time.Time
	lastCPUPercent   float64
	cpuMutex         sync.Mutex
	cpuCacheDuration = time.Second
)

func getCPUPercent() float64 {
	cpuMutex.Lock()
	defer cpuMutex.Unlock()

	if time.Since(lastCPUCheck) < cpuCacheDuration {
		return lastCPUPercent
	}

	percent, err := cpu.Percent(0, false)
	if err != nil || len(percent) == 0 {
		lastCPUPercent = 0
	} else {
		lastCPUPercent = percent[0]
	}

	lastCPUCheck = time.Now()
	return lastCPUPercent
}

func Uptime(hm *discovery.Host) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := collectMetrics(hm)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshot)
	}
}

func collectMetrics(hm *discovery.Host) *SystemSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	vmStat, _ := mem.VirtualMemory()

	sysStats := SystemStats{
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemAlloc:     m.Alloc,
		MemTotal:     m.TotalAlloc,
		MemSys:       m.Sys,
		MemRSS:       m.HeapSys,
		CPUPercent:   getCPUPercent(),
		MemUsed:      vmStat.Used,
		MemTotalOS:   vmStat.Total,
	}

	sysSnap := &SystemSnapshot{
		Timestamp: time.Now(),
		System:    sysStats,
		Hosts:     make(map[string]*HostSnapshot),
	}

	hosts, _ := hm.LoadAll()
	for domain, hcfg := range hosts {
		hSnap := &HostSnapshot{
			Routes: make([]*RouteSnapshot, 0, len(hcfg.Routes)),
		}

		var totalReqs uint64
		var totalBackends int
		var sumP99 int64
		var p99Count int

		// --- HTTP Routes ---
		for _, route := range hcfg.Routes {
			rSnap := &RouteSnapshot{
				Protocol: "http",
				Path:     route.Path,
				Strategy: route.Backends.LBStrategy,
				Backends: make([]*BackendSnapshot, 0),
			}

			// Load returns *cache.Item, not interface{}
			if item, ok := cache.Route.Load(route.Key()); ok {
				if handler, ok := item.Value.(*handlers.Route); ok {
					for _, b := range handler.Backends {
						bSnap := &BackendSnapshot{
							URL:       b.URL.String(),
							Alive:     b.Alive.Load(),
							InFlight:  b.Activity.InFlight.Load(),
							Failures:  int64(b.Activity.Failures.Load()),
							TotalReqs: b.Activity.Requests.Load(),
							Latency:   b.Activity.Latency.Snapshot(),
							Healthy:   b.Health.IsHealthy(),
						}
						rSnap.Backends = append(rSnap.Backends, bSnap)

						totalReqs += b.Activity.Requests.Load()
						if bSnap.Latency.Count > 0 && bSnap.Latency.P99 > 0 {
							sumP99 += bSnap.Latency.P99
							p99Count++
						}
					}
				}
			} else {
				// Fallback for inactive routes
				for _, url := range route.Backends.Servers {
					rSnap.Backends = append(rSnap.Backends, &BackendSnapshot{
						URL:     url.Address,
						Alive:   false,
						Healthy: false,
						Latency: metrics.LatencySnapshot{},
					})
				}
			}

			totalBackends += len(rSnap.Backends)
			hSnap.Routes = append(hSnap.Routes, rSnap)
		}

		// --- TCP Routes ---
		if len(hcfg.TCPProxy) > 0 {
			for _, tcpCfg := range hcfg.TCPProxy {
				// Load returns *cache.Item directly
				item, ok := cache.TCP.Load(tcpCfg.Listen)
				if !ok {
					continue
				}

				// Assert Value field directly
				rtProxy, ok := item.Value.(*tcp.Proxy)
				if !ok {
					continue
				}

				// Lock Proxy to safely read Balancers
				rtProxy.Mu.RLock()

				// 1. SNI Routes
				for sni, bal := range rtProxy.Routes {
					rSnap := &RouteSnapshot{
						Protocol: "tcp",
						Path:     sni,
						Strategy: bal.GetStrategyName(),
						Backends: make([]*BackendSnapshot, 0),
					}

					for _, b := range bal.Backends() {
						snapLat := b.Activity.Latency.Snapshot()

						bSnap := &BackendSnapshot{
							URL:       b.Address,
							Alive:     b.Alive.Load(),
							InFlight:  b.Activity.InFlight.Load(),
							Failures:  int64(b.Activity.Failures.Load()),
							TotalReqs: b.Activity.Requests.Load(),
							Latency:   snapLat,
							Healthy:   b.Health.IsHealthy(),
						}
						rSnap.Backends = append(rSnap.Backends, bSnap)

						totalReqs += b.Activity.Requests.Load()
						if snapLat.Count > 0 && snapLat.P99 > 0 {
							sumP99 += snapLat.P99
							p99Count++
						}
					}
					totalBackends += len(rSnap.Backends)
					hSnap.Routes = append(hSnap.Routes, rSnap)
				}

				// 2. Default Route
				if rtProxy.Default != nil {
					rSnap := &RouteSnapshot{
						Protocol: "tcp",
						Path:     "*default*",
						Strategy: rtProxy.Default.GetStrategyName(),
						Backends: make([]*BackendSnapshot, 0),
					}
					for _, b := range rtProxy.Default.Backends() {
						snapLat := b.Activity.Latency.Snapshot()

						bSnap := &BackendSnapshot{
							URL:       b.Address,
							Alive:     b.Alive.Load(),
							InFlight:  b.Activity.InFlight.Load(),
							Failures:  int64(b.Activity.Failures.Load()),
							TotalReqs: b.Activity.Requests.Load(),
							Latency:   snapLat,
							Healthy:   b.Health.IsHealthy(),
						}
						rSnap.Backends = append(rSnap.Backends, bSnap)

						totalReqs += b.Activity.Requests.Load()
						if snapLat.Count > 0 && snapLat.P99 > 0 {
							sumP99 += snapLat.P99
							p99Count++
						}
					}
					totalBackends += len(rSnap.Backends)
					hSnap.Routes = append(hSnap.Routes, rSnap)
				}

				rtProxy.Mu.RUnlock()
			}
		}

		hSnap.TotalReqs = totalReqs
		hSnap.TotalBackends = totalBackends
		if p99Count > 0 {
			hSnap.AvgP99 = sumP99 / int64(p99Count)
		}

		sysSnap.Hosts[domain] = hSnap
	}

	return sysSnap
}
