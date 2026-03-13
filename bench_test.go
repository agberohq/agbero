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
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

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
		srvList = append(srvList, alaye.Server{
			Address: ts.URL,
			Weight:  1,
		})
	}
	return tsList, srvList
}

func setupProxy(b *testing.B, strategy string, backends []alaye.Server) (*Server, *jack.Shutdown, string) {
	port := zulu.PortFree()
	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)

	global := alaye.NewEphemeralGlobal(port, false)
	global.Logging.Enabled = alaye.Inactive
	global.Security.Enabled = alaye.Inactive
	global.Bind.HTTP = []string{bindAddr}
	global.Bind.HTTPS = []string{}

	hostCfg := &alaye.Host{
		Domains: []string{"bench.localhost"},
		Bind:    []string{fmt.Sprintf("%d", port)},
		TLS:     alaye.TLS{Mode: alaye.ModeLocalNone},
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
					Enabled: alaye.Inactive,
				},
			},
		},
	}
	woos.DefaultHost(hostCfg)

	logger := ll.New("bench").Disable()
	shutdown := jack.NewShutdown()
	hm := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(logger))
	hm.LoadStatic(map[string]*alaye.Host{"bench.localhost": hostCfg})

	srv := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(logger),
		WithShutdownManager(shutdown),
	)

	go func() {
		_ = srv.Start("")
	}()

	proxyURL := fmt.Sprintf("http://%s", bindAddr)
	return srv, shutdown, proxyURL
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

	upstreams, backendCfgs := setupBackends(5)
	defer func() {
		for _, u := range upstreams {
			u.Close()
		}
	}()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10000,
			MaxIdleConnsPerHost: 10000,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		},
		Timeout: 5 * time.Second,
	}

	for _, strategy := range strategies {
		b.Run(strategy, func(b *testing.B) {
			metrics.DefaultRegistry.Clear()

			_, shutdown, proxyURL := setupProxy(b, strategy, backendCfgs)

			// Readiness loop: Ensure proxy is fully bound before starting timer
			for i := 0; i < 50; i++ {
				req, _ := http.NewRequest(http.MethodGet, proxyURL+"/", nil)
				req.Host = "bench.localhost"
				resp, err := client.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					break
				}
				time.Sleep(10 * time.Millisecond)
			}

			var successes atomic.Uint64
			var httpErrs atomic.Uint64
			var netErrs atomic.Uint64

			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				req, _ := http.NewRequest(http.MethodGet, proxyURL+"/", nil)
				req.Host = "bench.localhost"

				for pb.Next() {
					// Clone request to avoid concurrent map read/write panics in net/http
					r := req.Clone(context.Background())

					resp, err := client.Do(r)
					if err != nil {
						netErrs.Add(1)
						continue
					}

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

			printMetricsSummary(b, strategy, backendCfgs, successes.Load(), httpErrs.Load(), netErrs.Load())
		})
	}
}

func printMetricsSummary(b *testing.B, strategy string, backends []alaye.Server, success, httpErrs, netErrs uint64) {
	b.Logf("\n--- Latency Summary for [%s] ---", strings.ToUpper(strategy))
	b.Logf("  BENCHMARK : Success: %d | HTTP Errors (e.g. 502): %d | Net Errors (e.g. timeout): %d", success, httpErrs, netErrs)

	var totalReqs uint64
	var totalP99 int64
	var totalP50 int64
	var activeBackends int

	for i, srv := range backends {
		key := alaye.BackendKey{Protocol: "http", Domain: "bench.localhost", Path: "/", Addr: srv.Address}

		if stats := metrics.DefaultRegistry.Get(key); stats != nil {
			snap := stats.Activity.Snapshot()
			lat := snap["latency"].(metrics.LatencySnapshot)
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
