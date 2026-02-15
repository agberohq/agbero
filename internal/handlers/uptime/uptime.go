package uptime

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"

	"git.imaxinacion.net/aibox/agbero/internal/core/cache"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/xtcp"
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
	Routes    []*RouteSnapshot `json:"routes"`
	Proxies   []*ProxySnapshot `json:"proxies"`
	TotalReqs uint64           `json:"total_reqs"`
}

type RouteSnapshot struct {
	Protocol string             `json:"protocol"` // "http"
	Path     string             `json:"path"`
	Strategy string             `json:"strategy"`
	Backends []*BackendSnapshot `json:"backends"`
}

type ProxySnapshot struct {
	Protocol string             `json:"protocol"` // "tcp"
	Name     string             `json:"name"`     // SNI name or "*default*"
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
			Routes:  make([]*RouteSnapshot, 0),
			Proxies: make([]*ProxySnapshot, 0),
		}

		var totalReqs uint64

		// --- HTTP Routes ---
		for _, route := range hcfg.Routes {
			rSnap := &RouteSnapshot{
				Protocol: "http",
				Path:     route.Path,
				Strategy: route.Backends.Strategy,
				Backends: make([]*BackendSnapshot, 0),
			}

			rKey := route.Key()

			for _, srv := range route.Backends.Servers {
				statsKey := fmt.Sprintf("%s|%s", rKey, srv.Address)

				var latSnap metrics.LatencySnapshot
				var failures, reqs, inFlight int64
				healthy := false
				alive := true // Default until found

				if stats := metrics.DefaultRegistry.Get(statsKey); stats != nil {
					snap := stats.Activity.Snapshot()
					latSnap = snap["latency"].(metrics.LatencySnapshot)
					failures = int64(snap["failures"].(uint64))
					reqs = int64(snap["requests"].(uint64))
					inFlight = snap["in_flight"].(int64)
					healthy = stats.Health.IsHealthy()
					alive = stats.Alive.Load() // Read actual state
				}

				bSnap := &BackendSnapshot{
					URL:       srv.Address,
					Alive:     alive,
					InFlight:  inFlight,
					Failures:  failures,
					TotalReqs: uint64(reqs),
					Latency:   latSnap,
					Healthy:   healthy,
				}

				rSnap.Backends = append(rSnap.Backends, bSnap)
				totalReqs += uint64(reqs)
			}
			hSnap.Routes = append(hSnap.Routes, rSnap)
		}

		// --- TCP Proxies ---
		if len(hcfg.Proxies) > 0 {
			for _, tcpCfg := range hcfg.Proxies {
				item, ok := cache.TCP.Load(tcpCfg.Listen)
				if !ok {
					continue
				}

				rtProxy, ok := item.Value.(*xtcp.Proxy)
				if !ok {
					continue
				}

				rtProxy.Mu.RLock()

				// 1. SNI Routes
				for sni, bal := range rtProxy.Routes {
					pSnap := &ProxySnapshot{
						Protocol: "tcp",
						Name:     sni,
						Strategy: bal.GetStrategyName(),
						Backends: make([]*BackendSnapshot, 0),
					}

					for _, b := range bal.Backends() {
						bSnap := &BackendSnapshot{
							URL:       b.Address,
							Alive:     b.Alive.Load(),
							InFlight:  b.Activity.InFlight.Load(),
							Failures:  int64(b.Activity.Failures.Load()),
							TotalReqs: b.Activity.Requests.Load(),
							Latency:   b.Activity.Latency.Snapshot(),
							Healthy:   b.Health.IsHealthy(),
						}
						pSnap.Backends = append(pSnap.Backends, bSnap)
						totalReqs += b.Activity.Requests.Load()
					}
					hSnap.Proxies = append(hSnap.Proxies, pSnap)
				}

				// 2. Default Route
				if rtProxy.Default != nil {
					pSnap := &ProxySnapshot{
						Protocol: "tcp",
						Name:     "*default*",
						Strategy: rtProxy.Default.GetStrategyName(),
						Backends: make([]*BackendSnapshot, 0),
					}
					for _, b := range rtProxy.Default.Backends() {
						bSnap := &BackendSnapshot{
							URL:       b.Address,
							Alive:     b.Alive.Load(),
							InFlight:  b.Activity.InFlight.Load(),
							Failures:  int64(b.Activity.Failures.Load()),
							TotalReqs: b.Activity.Requests.Load(),
							Latency:   b.Activity.Latency.Snapshot(),
							Healthy:   b.Health.IsHealthy(),
						}
						pSnap.Backends = append(pSnap.Backends, bSnap)
						totalReqs += b.Activity.Requests.Load()
					}
					hSnap.Proxies = append(hSnap.Proxies, pSnap)
				}

				rtProxy.Mu.RUnlock()
			}
		}

		hSnap.TotalReqs = totalReqs
		sysSnap.Hosts[domain] = hSnap
	}

	return sysSnap
}
