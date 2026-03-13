package agbero

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// setupBackends creates N fast, dummy HTTP servers to act as our upstreams.
func setupBackends(count int) ([]*httptest.Server, []alaye.Server) {
	var tsList []*httptest.Server
	var srvList []alaye.Server

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	for i := 0; i < count; i++ {
		ts := httptest.NewServer(handler)
		tsList = append(tsList, ts)
		srvList = append(srvList, alaye.NewServer(ts.URL))
	}
	return tsList, srvList
}

// setupProxy configures and starts an in-memory Agbero proxy using isolated resources.
func setupProxy(b *testing.B, strategy string, backends []alaye.Server) (*Server, *jack.Shutdown, *resource.Manager, string) {
	port := zulu.PortFree()
	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// 1. Setup Global Config (Disable heavy features like logging/WAF for pure proxy bench)
	global := &alaye.Global{
		Bind: alaye.Bind{
			HTTP: []string{bindAddr},
		},
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       30 * time.Second,
			Write:      30 * time.Second,
			Idle:       120 * time.Second,
			ReadHeader: 5 * time.Second,
		},
		General: alaye.General{
			MaxHeaderBytes: 1 << 20,
		},
		Storage: alaye.Storage{
			HostsDir: b.TempDir(),
			DataDir:  b.TempDir(),
			CertsDir: b.TempDir(),
		},
	}

	// 2. Setup Host Config
	hostCfg := &alaye.Host{
		Domains: []string{"bench.localhost"},
		Bind:    []string{fmt.Sprintf("%d", port)},
		TLS: alaye.TLS{
			Mode: alaye.ModeLocalNone,
		},
		Routes: []alaye.Route{
			{
				Enabled: alaye.Active,
				Path:    "/",
				Backends: alaye.Backend{
					Enabled:  alaye.Active,
					Strategy: strategy,
					Servers:  backends,
				},
				HealthCheck: alaye.HealthCheck{
					Enabled: alaye.Inactive, // Disable health checks to isolate LB logic
				},
			},
		},
	}
	woos.DefaultHost(hostCfg)

	// 3. Setup Dependencies
	logger := ll.New("bench").Disable() // Disable logs
	shutdown := jack.NewShutdown()
	hm := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(logger))
	hm.LoadStatic(map[string]*alaye.Host{"bench.localhost": hostCfg})

	// Create isolated resource manager to avoid global singletons
	res := resource.New()

	// 4. Start Server
	srv := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(logger),
		WithShutdownManager(shutdown),
		WithResource(res),
	)

	// Run in background
	go func() {
		_ = srv.Start("")
	}()

	proxyURL := fmt.Sprintf("http://%s", bindAddr)
	return srv, shutdown, res, proxyURL
}

func BenchmarkStrategies(b *testing.B) {
	strategies := []string{
		alaye.StrategyRoundRobin,
		alaye.StrategyRandom,
		alaye.StrategyLeastConn,
		alaye.StrategyWeightedLeastConn,
		alaye.StrategyPowerOfTwoChoices,
		alaye.StrategyAdaptive,
	}

	// 1. Spin up dummy upstream backends
	upstreams, backendCfgs := setupBackends(5)
	defer func() {
		for _, u := range upstreams {
			u.Close()
		}
	}()

	// 2. Highly optimized HTTP client to blast the proxy
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10000,
			MaxIdleConnsPerHost: 10000,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true, // Avoid overhead in the bench client itself
		},
		Timeout: 5 * time.Second,
	}

	for _, strategy := range strategies {
		b.Run(strategy, func(b *testing.B) {
			// Start proxy with specific strategy
			_, shutdown, res, proxyURL := setupProxy(b, strategy, backendCfgs)

			// Readiness loop: Ensure proxy is fully bound before starting timer
			for i := 0; i < 50; i++ {
				req, _ := http.NewRequest(http.MethodGet, proxyURL+"/", nil)
				req.Host = "bench.localhost"
				resp, err := client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					break
				}
				time.Sleep(10 * time.Millisecond)
			}

			// Prune metrics to clear any recorded during readiness loop
			if res.Metrics != nil {
				res.Metrics.Prune(map[alaye.BackendKey]bool{})
			}

			var successes atomic.Uint64
			var httpErrs atomic.Uint64
			var netErrs atomic.Uint64

			b.ResetTimer()
			b.ReportAllocs()

			// Run massive concurrency
			b.RunParallel(func(pb *testing.PB) {
				req, _ := http.NewRequest(http.MethodGet, proxyURL+"/", nil)
				req.Host = "bench.localhost" // Ensure routing matches

				for pb.Next() {
					// Clone request to avoid concurrent map read/write panics in net/http
					r := req.Clone(context.Background())

					resp, err := client.Do(r)
					if err != nil {
						netErrs.Add(1)
						continue // Ignore standard benchmark connection reset errors
					}

					// Must read and close body to return conn to pool
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						successes.Add(1)
					} else {
						httpErrs.Add(1)
					}
				}
			})

			b.StopTimer()

			// Clean up to prevent port exhaustion for the next iteration
			client.CloseIdleConnections()
			shutdown.TriggerShutdown()

			// Print the Histogram / Distribution for this strategy
			printMetricsSummary(b, strategy, backendCfgs, successes.Load(), httpErrs.Load(), netErrs.Load(), res)
		})
	}
}

func printMetricsSummary(b *testing.B, strategy string, backends []alaye.Server, success, httpErrs, netErrs uint64, res *resource.Manager) {
	b.Logf("\n--- Latency Summary for [%s] ---", strings.ToUpper(strategy))
	b.Logf("  BENCHMARK : Success: %d | HTTP Errors (e.g. 502): %d | Net Errors (e.g. timeout): %d", success, httpErrs, netErrs)

	var totalReqs uint64
	var totalP99 int64
	var totalP50 int64
	var activeBackends int

	for i, srv := range backends {
		// Use the correct BackendKey format from the refactored code
		key := alaye.BackendKey{
			Protocol: "http",
			Domain:   "bench.localhost",
			Path:     "/",
			Addr:     srv.Address.String(),
		}

		if stats := res.Metrics.Get(key); stats != nil {
			snap := stats.Activity.Snapshot()
			lat, ok := snap["latency"].(metrics.LatencySnapshot)
			if !ok {
				continue
			}

			// We pull directly from the atomic uint64 to ensure absolute accuracy of requests served
			reqs := stats.Activity.Requests.Load()

			totalReqs += reqs
			totalP99 += lat.P99
			totalP50 += lat.P50

			if reqs > 0 {
				activeBackends++
				b.Logf("  Backend %d: Reqs: %-7d | P50: %-5d µs | P99: %-5d µs | Max: %-5d µs",
					i, reqs, lat.P50, lat.P99, lat.Max)
			} else {
				b.Logf("  Backend %d: Reqs: 0       | -- Idle --", i)
			}
		}
	}

	if activeBackends > 0 {
		avgP99 := totalP99 / int64(activeBackends)
		avgP50 := totalP50 / int64(activeBackends)
		b.Logf("  OVERALL   : Total: %-6d | Avg P50: %d µs | Avg P99: %d µs", totalReqs, avgP50, avgP99)
	}
	b.Logf("----------------------------------------\n")
}
