package uptime

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/cluster"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/xtcp"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/health"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
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

type GlobalStats struct {
	AvgP99  float64 `json:"avg_p99_ms"`
	HttpP99 float64 `json:"http_p99_ms"`
	TcpP99  float64 `json:"tcp_p99_ms"`
}

type ClusterStats struct {
	Enabled bool              `json:"enabled"`
	Members []string          `json:"members,omitempty"`
	Metrics map[string]uint64 `json:"metrics,omitempty"`
}

type SystemSnapshot struct {
	Timestamp time.Time                `json:"timestamp"`
	System    SystemStats              `json:"system"`
	Global    GlobalStats              `json:"global"`
	Cluster   ClusterStats             `json:"cluster"`
	Hosts     map[string]*HostSnapshot `json:"hosts"`
}

type HostSnapshot struct {
	Routes    []*RouteSnapshot `json:"routes"`
	Proxies   []*ProxySnapshot `json:"proxies"`
	TotalReqs uint64           `json:"total_reqs"`
}

type RouteSnapshot struct {
	Protocol string             `json:"protocol"`
	Path     string             `json:"path"`
	Strategy string             `json:"strategy"`
	Backends []*BackendSnapshot `json:"backends"`
}

type ProxySnapshot struct {
	Protocol string             `json:"protocol"`
	Name     string             `json:"name"`
	Strategy string             `json:"strategy"`
	Backends []*BackendSnapshot `json:"backends"`
}

type HealthSnapshot struct {
	Status              string     `json:"status"`
	Score               int        `json:"score"`
	Trend               int        `json:"trend"`
	LastCheck           *time.Time `json:"last_check,omitempty"`
	LastSuccess         *time.Time `json:"last_success,omitempty"`
	LastFailure         *time.Time `json:"last_failure,omitempty"`
	ConsecutiveFailures int64      `json:"consecutive_failures"`
	Downtime            string     `json:"downtime,omitempty"`
}

type BackendSnapshot struct {
	URL       string                  `json:"url"`
	Alive     bool                    `json:"alive"`
	InFlight  int64                   `json:"in_flight"`
	Failures  int64                   `json:"failures"`
	TotalReqs uint64                  `json:"total_reqs"`
	Latency   metrics.LatencySnapshot `json:"latency_us"`
	Health    HealthSnapshot          `json:"health"`
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

func stateToString(s health.State) string {
	switch s {
	case health.StateHealthy:
		return "Healthy"
	case health.StateDegraded:
		return "Degraded"
	case health.StateUnhealthy:
		return "Unhealthy"
	case health.StateDead:
		return "Dead"
	default:
		return "Unknown"
	}
}

func Uptime(hm *discovery.Host, cm *cluster.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := collectMetrics(hm, cm)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshot)
	}
}

func collectMetrics(hm *discovery.Host, cm *cluster.Manager) *SystemSnapshot {
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

	if cm != nil {
		sysSnap.Cluster = ClusterStats{
			Enabled: true,
			Members: cm.Members(),
			Metrics: cm.Metrics(),
		}
	} else {
		sysSnap.Cluster = ClusterStats{Enabled: false}
	}

	var (
		sumAll, sumHttp, sumTcp       float64
		countAll, countHttp, countTcp int
	)

	hosts, _ := hm.LoadAll()
	for domain, hcfg := range hosts {
		hSnap := &HostSnapshot{
			Routes:  make([]*RouteSnapshot, 0),
			Proxies: make([]*ProxySnapshot, 0),
		}

		var totalReqs uint64

		for _, route := range hcfg.Routes {
			rSnap := &RouteSnapshot{
				Protocol: "http",
				Path:     route.Path,
				Strategy: route.Backends.Strategy,
				Backends: make([]*BackendSnapshot, 0),
			}

			rKey := route.Key()

			var activeRoute *handlers.Route
			if it, ok := zulu.Route.Load(rKey); ok {
				activeRoute, _ = it.Value.(*handlers.Route)
			}

			for i, srv := range route.Backends.Servers {
				statsKey := fmt.Sprintf("%s|%s", rKey, srv.Address)

				var latSnap metrics.LatencySnapshot
				var failures, reqs, inFlight int64
				alive := true

				hSnapStruct := HealthSnapshot{
					Status: stateToString(health.StateUnknown),
					Score:  100,
				}

				if activeRoute != nil && i < len(activeRoute.Backends) {
					b := activeRoute.Backends[i]
					if b != nil && b.HealthScore != nil {
						hSnapStruct.Score = int(b.HealthScore.Value())
						hSnapStruct.Status = stateToString(b.HealthScore.State())
						hSnapStruct.Trend = int(b.HealthScore.Trend())

						if b.Prober != nil {
							lc := b.Prober.LastProbeTime()
							if !lc.IsZero() {
								hSnapStruct.LastCheck = &lc
							}
						}
					}
				}

				if stats := metrics.DefaultRegistry.Get(statsKey); stats != nil {
					snap := stats.Activity.Snapshot()
					latSnap = snap["latency"].(metrics.LatencySnapshot)
					failures = int64(snap["failures"].(uint64))
					reqs = int64(snap["requests"].(uint64))
					inFlight = snap["in_flight"].(int64)

					hSnapStruct.ConsecutiveFailures = stats.Health.ConsecutiveFailures()
					ls := stats.Health.LastSuccess()
					if !ls.IsZero() {
						hSnapStruct.LastSuccess = &ls
					}
					lf := stats.Health.LastFailure()
					if !lf.IsZero() {
						hSnapStruct.LastFailure = &lf
					}

					if activeRoute != nil && i < len(activeRoute.Backends) {
						alive = activeRoute.Backends[i].Alive()
					} else {
						alive = stats.Alive.Load()
					}

					if latSnap.Count > 0 && latSnap.P99 > 0 {
						val := float64(latSnap.P99)
						sumAll += val
						countAll++
						sumHttp += val
						countHttp++
					}
				}

				if hSnapStruct.Status != "Healthy" && hSnapStruct.Status != "Unknown" && hSnapStruct.LastSuccess != nil {
					hSnapStruct.Downtime = time.Since(*hSnapStruct.LastSuccess).Round(time.Second).String()
				}

				bSnap := &BackendSnapshot{
					URL:       srv.Address,
					Alive:     alive,
					InFlight:  inFlight,
					Failures:  failures,
					TotalReqs: uint64(reqs),
					Latency:   latSnap,
					Health:    hSnapStruct,
				}

				rSnap.Backends = append(rSnap.Backends, bSnap)
				totalReqs += uint64(reqs)
			}
			hSnap.Routes = append(hSnap.Routes, rSnap)
		}

		if len(hcfg.Proxies) > 0 {
			for _, tcpCfg := range hcfg.Proxies {
				item, ok := zulu.TCP.Load(tcpCfg.Listen)
				if !ok {
					continue
				}

				rtProxy, ok := item.Value.(*xtcp.Proxy)
				if !ok {
					continue
				}

				rtProxy.Mu.RLock()

				processBackend := func(b *xtcp.Backend) *BackendSnapshot {
					latSnap := b.Activity.Latency.Snapshot()
					if latSnap.Count > 0 && latSnap.P99 > 0 {
						val := float64(latSnap.P99)
						sumAll += val
						countAll++
						sumTcp += val
						countTcp++
					}

					totalReqs += b.Activity.Requests.Load()

					hSnapStruct := HealthSnapshot{
						Status: stateToString(health.StateUnknown),
						Score:  100,
					}

					if b.HealthScore != nil {
						hSnapStruct.Score = int(b.HealthScore.Value())
						hSnapStruct.Status = stateToString(b.HealthScore.State())
						hSnapStruct.Trend = int(b.HealthScore.Trend())

						if b.Prober != nil {
							lc := b.Prober.LastProbeTime()
							if !lc.IsZero() {
								hSnapStruct.LastCheck = &lc
							}
						}
					}

					if b.Health != nil {
						hSnapStruct.ConsecutiveFailures = b.Health.ConsecutiveFailures()
						ls := b.Health.LastSuccess()
						if !ls.IsZero() {
							hSnapStruct.LastSuccess = &ls
						}
						lf := b.Health.LastFailure()
						if !lf.IsZero() {
							hSnapStruct.LastFailure = &lf
						}
					}

					if hSnapStruct.Status != "Healthy" && hSnapStruct.Status != "Unknown" && hSnapStruct.LastSuccess != nil {
						hSnapStruct.Downtime = time.Since(*hSnapStruct.LastSuccess).Round(time.Second).String()
					}

					return &BackendSnapshot{
						URL:       b.Address,
						Alive:     b.Alive(),
						InFlight:  b.Activity.InFlight.Load(),
						Failures:  int64(b.Activity.Failures.Load()),
						TotalReqs: b.Activity.Requests.Load(),
						Latency:   latSnap,
						Health:    hSnapStruct,
					}
				}

				for sni, bal := range rtProxy.Routes {
					pSnap := &ProxySnapshot{
						Protocol: "tcp",
						Name:     sni,
						Strategy: bal.GetStrategyName(),
						Backends: make([]*BackendSnapshot, 0),
					}

					for _, b := range bal.Backends() {
						pSnap.Backends = append(pSnap.Backends, processBackend(b))
					}
					hSnap.Proxies = append(hSnap.Proxies, pSnap)
				}

				if rtProxy.Default != nil {
					pSnap := &ProxySnapshot{
						Protocol: "tcp",
						Name:     "*default*",
						Strategy: rtProxy.Default.GetStrategyName(),
						Backends: make([]*BackendSnapshot, 0),
					}
					for _, b := range rtProxy.Default.Backends() {
						pSnap.Backends = append(pSnap.Backends, processBackend(b))
					}
					hSnap.Proxies = append(hSnap.Proxies, pSnap)
				}

				rtProxy.Mu.RUnlock()
			}
		}

		hSnap.TotalReqs = totalReqs
		sysSnap.Hosts[domain] = hSnap
	}

	sysSnap.Global = GlobalStats{
		AvgP99:  calcAvg(sumAll, countAll),
		HttpP99: calcAvg(sumHttp, countHttp),
		TcpP99:  calcAvg(sumTcp, countTcp),
	}

	return sysSnap
}

func calcAvg(sum float64, count int) float64 {
	if count == 0 {
		return 0
	}
	return (sum / float64(count)) / 1000.0
}
