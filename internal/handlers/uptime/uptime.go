package uptime

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/cook"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

var processStartTime = time.Now()

type SystemStats struct {
	PID          int       `json:"pid"`
	StartTime    time.Time `json:"start_time"`
	Uptime       string    `json:"uptime"`
	NumCPU       int       `json:"num_cpu"`
	NumGoroutine int       `json:"num_goroutine"`
	MemAlloc     uint64    `json:"mem_alloc"`
	MemTotal     uint64    `json:"mem_total"`
	MemSys       uint64    `json:"mem_sys"`
	MemRSS       uint64    `json:"mem_rss"`
	CPUPercent   float64   `json:"cpu_percent"`
	MemUsed      uint64    `json:"mem_used"`
	MemTotalOS   uint64    `json:"mem_total_os"`
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
	Timestamp time.Time                    `json:"timestamp"`
	System    SystemStats                  `json:"system"`
	Global    GlobalStats                  `json:"global"`
	Cluster   ClusterStats                 `json:"cluster"`
	Hosts     map[string]*HostSnapshot     `json:"hosts"`
	Git       map[string]cook.HealthStatus `json:"git"`
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
	Status              health.Status `json:"status"`
	Score               int           `json:"score"`
	Trend               int           `json:"trend"`
	LastCheck           *time.Time    `json:"last_check,omitempty"`
	LastSuccess         *time.Time    `json:"last_success,omitempty"`
	LastFailure         *time.Time    `json:"last_failure,omitempty"`
	ConsecutiveFailures int64         `json:"consecutive_failures"`
	Downtime            string        `json:"downtime,omitempty"`
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

func Uptime(res *resource.Resource, hm *discovery.Host, cm *cluster.Manager, cookMgr *cook.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := collectMetrics(hm, cm, cookMgr, res)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshot)
	}
}

func collectMetrics(hm *discovery.Host, cm *cluster.Manager, cookMgr *cook.Manager, res *resource.Resource) *SystemSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	vmStat, _ := mem.VirtualMemory()

	sysStats := SystemStats{
		PID:          os.Getpid(),
		StartTime:    processStartTime,
		Uptime:       time.Since(processStartTime).Round(time.Second).String(),
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

	if cookMgr != nil {
		sysSnap.Git = cookMgr.Health()
	} else {
		sysSnap.Git = make(map[string]cook.HealthStatus)
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

			if rSnap.Strategy == "" {
				rSnap.Strategy = alaye.StrategyRoundRobin
			}

			for _, srv := range route.Backends.Servers {
				addressStr := srv.Address.String() // Upgraded to alaye.Address
				statsKey := route.BackendKey(domain, addressStr)

				var latSnap metrics.LatencySnapshot
				var failures, reqs, inFlight int64

				alive := true
				hSnapStruct := HealthSnapshot{
					Status: health.StatusUnknown,
					Score:  100,
				}

				hasProber := route.HealthCheck.Enabled.Active() || (route.HealthCheck.Enabled == alaye.Unknown && route.HealthCheck.Path != "")

				if hScore, hasScore := res.Health.Get(statsKey); hasScore {
					hSnapStruct.Score = int(hScore.Value())
					hSnapStruct.Status = hScore.Status()
					hSnapStruct.Trend = int(hScore.Trend())
					hSnapStruct.ConsecutiveFailures = hScore.ConsecutiveFailures()

					if ls := hScore.LastSuccess(); !ls.IsZero() {
						hSnapStruct.LastSuccess = &ls
					}
					if lf := hScore.LastFailure(); !lf.IsZero() {
						hSnapStruct.LastFailure = &lf
					}
					if lu := hScore.LastUpdate(); !lu.IsZero() {
						hSnapStruct.LastCheck = &lu
					}

					state := hScore.State()
					if state == health.StateDead || state == health.StateUnhealthy {
						alive = false
					}
				}

				if stats := res.Metrics.Get(statsKey); stats != nil {
					snap := stats.Activity.Snapshot()
					latSnap = snap["latency"].(metrics.LatencySnapshot)
					failures = int64(snap["failures"].(uint64))
					reqs = int64(snap["requests"].(uint64))
					inFlight = snap["in_flight"].(int64)

					if latSnap.Count > 0 && latSnap.P99 > 0 {
						val := float64(latSnap.P99)
						sumAll += val
						countAll++
						sumHttp += val
						countHttp++
					}

					if !hasProber && route.CircuitBreaker.Threshold > 0 && uint64(failures) >= uint64(route.CircuitBreaker.Threshold) {
						alive = false
					}
				}

				if hSnapStruct.Status != health.StatusHealthy && hSnapStruct.Status != health.StatusUnknown && hSnapStruct.LastSuccess != nil {
					hSnapStruct.Downtime = time.Since(*hSnapStruct.LastSuccess).Round(time.Second).String()
				}

				bSnap := &BackendSnapshot{
					URL:       addressStr,
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

		for _, proxy := range hcfg.Proxies {
			sni := proxy.SNI
			if sni == "" {
				sni = "*"
			}

			pSnap := &ProxySnapshot{
				Protocol: "tcp",
				Name:     proxy.Listen + " (" + sni + ")",
				Strategy: proxy.Strategy,
				Backends: make([]*BackendSnapshot, 0),
			}

			if pSnap.Strategy == "" {
				pSnap.Strategy = alaye.StrategyRoundRobin
			}

			for _, srv := range proxy.Backends {
				addressStr := srv.Address.String() // Upgraded to alaye.Address
				statsKey := proxy.BackendKey(addressStr)

				var latSnap metrics.LatencySnapshot
				var failures, reqs, inFlight int64

				alive := true
				hSnapStruct := HealthSnapshot{
					Status: health.StatusUnknown,
					Score:  100,
				}

				hasProber := proxy.HealthCheck.Enabled.Active() || (proxy.HealthCheck.Enabled == alaye.Unknown && (proxy.HealthCheck.Send != "" || proxy.HealthCheck.Expect != "")) || strings.HasSuffix(addressStr, ":6379")

				if hScore, hasScore := res.Health.Get(statsKey); hasScore {
					hSnapStruct.Score = int(hScore.Value())
					hSnapStruct.Status = hScore.Status()
					hSnapStruct.Trend = int(hScore.Trend())
					hSnapStruct.ConsecutiveFailures = hScore.ConsecutiveFailures()

					if ls := hScore.LastSuccess(); !ls.IsZero() {
						hSnapStruct.LastSuccess = &ls
					}
					if lf := hScore.LastFailure(); !lf.IsZero() {
						hSnapStruct.LastFailure = &lf
					}
					if lu := hScore.LastUpdate(); !lu.IsZero() {
						hSnapStruct.LastCheck = &lu
					}

					state := hScore.State()
					if state == health.StateDead || state == health.StateUnhealthy {
						alive = false
					}
				}

				if stats := res.Metrics.Get(statsKey); stats != nil {
					snap := stats.Activity.Snapshot()
					latSnap = snap["latency"].(metrics.LatencySnapshot)
					failures = int64(snap["failures"].(uint64))
					reqs = int64(snap["requests"].(uint64))
					inFlight = snap["in_flight"].(int64)

					if latSnap.Count > 0 && latSnap.P99 > 0 {
						val := float64(latSnap.P99)
						sumAll += val
						countAll++
						sumTcp += val
						countTcp++
					}

					if !hasProber && failures >= 2 {
						alive = false
					}
				}

				if hSnapStruct.Status != health.StatusHealthy && hSnapStruct.Status != health.StatusUnknown && hSnapStruct.LastSuccess != nil {
					hSnapStruct.Downtime = time.Since(*hSnapStruct.LastSuccess).Round(time.Second).String()
				}

				bSnap := &BackendSnapshot{
					URL:       addressStr,
					Alive:     alive,
					InFlight:  inFlight,
					Failures:  failures,
					TotalReqs: uint64(reqs),
					Latency:   latSnap,
					Health:    hSnapStruct,
				}

				pSnap.Backends = append(pSnap.Backends, bSnap)
				totalReqs += uint64(reqs)
			}
			hSnap.Proxies = append(hSnap.Proxies, pSnap)
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
